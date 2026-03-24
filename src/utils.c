#include "utils.h"

#include <stdio.h>
#include <string.h>

/*
 * Core utility logic:
 * - stream/PID classification
 * - continuity counter validation
 * - validation summary aggregation
 */

#define MAX_PID 8192
#define CC_NEVER_SEEN 16
static uint8_t s_previous_continuity_counter[MAX_PID];

/* ============================================================================
 * Validation summary state
 * ========================================================================== */
typedef enum validation_event_type_e {
    VALIDATION_EVENT_SYNC = 0,
    VALIDATION_EVENT_CC = 1
} validation_event_type_t;

typedef struct validation_sample_s {
    validation_event_type_t type;
    size_t packet_index;
    uint16_t pid;
    uint8_t sync_byte;
    uint8_t expected_cc;
    uint8_t got_cc;
} validation_sample_t;

static size_t s_validation_packets_scanned = 0;
static size_t s_validation_sync_errors = 0;
static size_t s_validation_cc_errors = 0;
static size_t s_validation_cc_error_by_pid[MAX_PID];
static size_t s_validation_cc_first_packet_by_pid[MAX_PID];
static size_t s_validation_cc_last_packet_by_pid[MAX_PID];
static size_t s_validation_sample_count = 0;
static size_t s_validation_sample_omitted = 0;
static validation_sample_t s_validation_samples[VALIDATION_SAMPLE_LIMIT];

/* Record first N validation samples for readable error output. */
static void validation_summary_add_sample(validation_event_type_t type,
                                          size_t packet_index,
                                          uint16_t pid,
                                          uint8_t sync_byte,
                                          uint8_t expected_cc,
                                          uint8_t got_cc) {
    if (s_validation_sample_count < VALIDATION_SAMPLE_LIMIT) {
        validation_sample_t* sample = &s_validation_samples[s_validation_sample_count++];
        sample->type = type;
        sample->packet_index = packet_index;
        sample->pid = pid;
        sample->sync_byte = sync_byte;
        sample->expected_cc = expected_cc;
        sample->got_cc = got_cc;
    } else {
        s_validation_sample_omitted++;
    }
}

/* ============================================================================
 * Validation summary API
 * ========================================================================== */
void validation_summary_init(void) {
    s_validation_packets_scanned = 0;
    s_validation_sync_errors = 0;
    s_validation_cc_errors = 0;
    s_validation_sample_count = 0;
    s_validation_sample_omitted = 0;
    memset(s_validation_cc_error_by_pid, 0, sizeof s_validation_cc_error_by_pid);
    memset(s_validation_cc_first_packet_by_pid, 0, sizeof s_validation_cc_first_packet_by_pid);
    memset(s_validation_cc_last_packet_by_pid, 0, sizeof s_validation_cc_last_packet_by_pid);
    memset(s_validation_samples, 0, sizeof s_validation_samples);
}

size_t validation_summary_total_errors(void) {
    return s_validation_sync_errors + s_validation_cc_errors;
}

size_t validation_summary_sync_errors(void) {
    return s_validation_sync_errors;
}

void validation_summary_print(FILE* out) {
    size_t cc_affected_pid_count = 0;
    for (size_t pid = 0; pid < MAX_PID; pid++) {
        if (s_validation_cc_error_by_pid[pid] > 0u) {
            cc_affected_pid_count++;
        }
    }

    fprintf(out, "│  Packets scanned: %zu\n", s_validation_packets_scanned);
    fprintf(out, "│  Sync losses:     %zu\n", s_validation_sync_errors);
    fprintf(out, "│  CC errors:       %zu (affected PIDs: %zu)\n",
            s_validation_cc_errors, cc_affected_pid_count);

    if (s_validation_cc_errors > 0u) {
        size_t rows_printed = 0;
        const size_t max_rows = 12u;
        fprintf(out, "├────────────────────────────────────────────────── CC errors by PID\n");
        fprintf(out, "│  %-10s %-10s %-10s %s\n", "PID", "Count", "First pkt", "Last pkt");
        for (size_t pid = 0; pid < MAX_PID; pid++) {
            if (s_validation_cc_error_by_pid[pid] == 0u) {
                continue;
            }
            if (rows_printed < max_rows) {
                fprintf(out, "│  0x%04X     %-10zu %-10zu %zu\n",
                        (unsigned)pid,
                        s_validation_cc_error_by_pid[pid],
                        s_validation_cc_first_packet_by_pid[pid],
                        s_validation_cc_last_packet_by_pid[pid]);
            }
            rows_printed++;
        }
        if (rows_printed > max_rows) {
            fprintf(out, "│  ... %zu PID rows omitted ...\n", rows_printed - max_rows);
        }
    }

    if (s_validation_sample_count > 0u || s_validation_sample_omitted > 0u) {
        fprintf(out, "├────────────────────────────────────────────────── Samples (first %u)\n",
                (unsigned)VALIDATION_SAMPLE_LIMIT);
        for (size_t i = 0; i < s_validation_sample_count; i++) {
            const validation_sample_t* sample = &s_validation_samples[i];
            if (sample->type == VALIDATION_EVENT_SYNC) {
                fprintf(out, "│  SYNC pkt=%zu PID=0x%04X SB=0x%02X\n",
                        sample->packet_index, (unsigned)sample->pid, (unsigned)sample->sync_byte);
            } else {
                fprintf(out, "│  CC   pkt=%zu PID=0x%04X expected=%u got=%u\n",
                        sample->packet_index,
                        (unsigned)sample->pid,
                        (unsigned)sample->expected_cc,
                        (unsigned)sample->got_cc);
            }
        }
        if (s_validation_sample_omitted > 0u) {
            fprintf(out, "│  ... %zu samples omitted ...\n", s_validation_sample_omitted);
        }
    }
}

/* ============================================================================
 * PID / stream classification
 * ========================================================================== */
int is_well_known_si_pid(uint16_t pid) {
    switch (pid) {
        case 0x0001u:
        case 0x0002u:
        case 0x0010u:
        case 0x0011u:
        case 0x0012u:
        case 0x0013u:
        case 0x0014u:
            return 1;
        default:
            return 0;
    }
}

static const uint8_t s_stream_category_table[256] = {
    [0x01] = STREAM_VIDEO, [0x02] = STREAM_VIDEO, [0x03] = STREAM_AUDIO, [0x04] = STREAM_AUDIO,
    [0x0F] = STREAM_AUDIO, [0x10] = STREAM_VIDEO, [0x11] = STREAM_AUDIO, [0x1B] = STREAM_VIDEO,
    [0x1C] = STREAM_AUDIO, [0x1E] = STREAM_VIDEO, [0x1F] = STREAM_VIDEO, [0x20] = STREAM_VIDEO,
    [0x21] = STREAM_VIDEO, [0x22] = STREAM_VIDEO, [0x23] = STREAM_VIDEO, [0x24] = STREAM_VIDEO,
    [0x25] = STREAM_VIDEO, [0x26] = STREAM_VIDEO, [0x28] = STREAM_VIDEO, [0x29] = STREAM_VIDEO,
    [0x2A] = STREAM_VIDEO, [0x2B] = STREAM_VIDEO, [0x2D] = STREAM_AUDIO, [0x2E] = STREAM_AUDIO,
    [0x31] = STREAM_VIDEO, [0x32] = STREAM_VIDEO, [0x33] = STREAM_VIDEO, [0x34] = STREAM_VIDEO,
    [0x35] = STREAM_VIDEO, [0x36] = STREAM_VIDEO,
};

stream_category_t stream_category_from_type(uint8_t stream_type) {
    return (stream_category_t)s_stream_category_table[stream_type];
}

const char* stream_type_to_codec_string(uint8_t stream_type) {
    switch (stream_type) {
        case 0x01: return "MPEG-1 Video";
        case 0x02: return "MPEG-2 Video";
        case 0x03: return "MPEG-1 Audio";
        case 0x04: return "MPEG-2 Audio";
        case 0x0F: return "AAC ADTS";
        case 0x10: return "MPEG-4 Part 2 Visual";
        case 0x11: return "AAC LATM";
        case 0x1B: return "AVC/H.264";
        case 0x1C: return "AAC";
        case 0x1E: return "Auxiliary video";
        case 0x1F: return "SVC";
        case 0x20: return "MVC";
        case 0x21: return "JPEG 2000";
        case 0x22: return "H.262 3D";
        case 0x23: return "H.264 3D";
        case 0x24: return "HEVC/H.265";
        case 0x25: return "HEVC temporal subset";
        case 0x26: return "MVCD";
        case 0x28: case 0x29: case 0x2A: case 0x2B: return "HEVC enhancement";
        case 0x2D: return "ISO 23008-3 MHAS main";
        case 0x2E: return "ISO 23008-3 MHAS auxiliary";
        case 0x31: return "H.265 substream";
        case 0x32: return "JPEG XS";
        case 0x33: return "VVC/H.266";
        case 0x34: return "VVC temporal subset";
        case 0x35: return "EVC";
        case 0x36: return "LCEVC";
        default:
            if (stream_type >= 0x80u) return "User private";
            if (stream_type >= 0x37u && stream_type <= 0x7Eu) return "Reserved";
            return "Unknown";
    }
}

/* ============================================================================
 * Continuity counter checking
 * ========================================================================== */
void ts_cc_init(void) {
    for (size_t i = 0; i < MAX_PID; i++) {
        s_previous_continuity_counter[i] = CC_NEVER_SEEN;
    }
}

int ts_cc_check(const ts_packet_t* packet, FILE* out, size_t packet_index, int summarize) {
    int reported = 0;
    if (summarize && packet_index + 1u > s_validation_packets_scanned) {
        s_validation_packets_scanned = packet_index + 1u;
    }
    if (packet->sync_byte != 0x47) {
        if (summarize) {
            s_validation_sync_errors++;
            validation_summary_add_sample(VALIDATION_EVENT_SYNC, packet_index, packet->pid, packet->sync_byte, 0u, 0u);
        }
        if (out != NULL) {
            fprintf(out, "│  Sync byte error: PID 0x%04X, SB 0x%02X\n", packet->pid, packet->sync_byte);
        }
        reported = 1;
    }
    if (packet->pid == TS_PID_NULL || packet->pid >= MAX_PID) {
        return reported;
    }
    if (s_previous_continuity_counter[packet->pid] > 15) {
        return reported;
    }
    if (packet->adaptation_field_control == 0u) {
        return reported;
    }
    if (packet->discontinuity_indicator) {
        return reported;
    }

    uint8_t expected = s_previous_continuity_counter[packet->pid];
    if ((packet->adaptation_field_control & 0x01u) != 0u) {
        expected = (uint8_t)((expected + 1u) & 0x0Fu);
    }

    if (packet->continuity_counter != expected) {
        if (summarize) {
            s_validation_cc_errors++;
            if (s_validation_cc_error_by_pid[packet->pid] == 0u) {
                s_validation_cc_first_packet_by_pid[packet->pid] = packet_index;
            }
            s_validation_cc_error_by_pid[packet->pid]++;
            s_validation_cc_last_packet_by_pid[packet->pid] = packet_index;
            validation_summary_add_sample(VALIDATION_EVENT_CC, packet_index, packet->pid, 0u, expected, packet->continuity_counter);
        }
        if (out != NULL) {
            fprintf(out, "│  Continuity counter error: PID 0x%04X, CC %u -> %u\n",
                    packet->pid, (unsigned)s_previous_continuity_counter[packet->pid], (unsigned)packet->continuity_counter);
        }
        reported = 1;
    }
    return reported;
}

void ts_cc_update(const ts_packet_t* packet) {
    if (packet->pid < MAX_PID && packet->adaptation_field_control != 0u) {
        s_previous_continuity_counter[packet->pid] = packet->continuity_counter;
    }
}

/* ============================================================================
 * Validation report helpers and misc utilities
 * ========================================================================== */
void report_undefined_pids(const pat_table_t* pat, const pmt_t* pmt_table, size_t pmt_capacity,
                           const pid_count_list_t* list, int* errors_found) {
    uint8_t defined[MAX_PID];
    memset(defined, 0, sizeof defined);
    defined[TS_PID_PAT] = 1;
    defined[TS_PID_NULL] = 1;
    for (uint16_t pid = 0; pid < MAX_PID; pid++) {
        if (is_well_known_si_pid(pid)) {
            defined[pid] = 1;
        }
    }
    for (size_t i = 0; i < pat->program_count; i++) {
        if (pat->programs[i].pid < MAX_PID) {
            defined[pat->programs[i].pid] = 1;
        }
    }
    for (size_t i = 0; i < pmt_capacity && pmt_table; i++) {
        if (pmt_table[i].pcr_pid < MAX_PID) {
            defined[pmt_table[i].pcr_pid] = 1;
        }
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            if (pmt_table[i].es_list[j].elementary_pid < MAX_PID) {
                defined[pmt_table[i].es_list[j].elementary_pid] = 1;
            }
        }
    }
    for (size_t i = 0; i < list->count; i++) {
        uint16_t pid = list->pids[i].pid;
        if (pid < MAX_PID && !defined[pid]) {
            printf("│  Undefined PID: 0x%04X (packets: %zu)\n", (unsigned)pid, list->pids[i].count);
            if (errors_found) {
                *errors_found = 1;
            }
        }
    }
}

uint64_t pcr_to_time(uint64_t pcr_base, uint64_t pcr_ext) {
    return pcr_base * 300u + pcr_ext;
}

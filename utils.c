#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PID 8192
#define CC_NEVER_SEEN 16
static uint8_t s_previous_continuity_counter[MAX_PID];

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

int is_well_known_si_pid(uint16_t pid) {
    switch (pid) {
        case 0x0001u: /* CAT */
        case 0x0002u: /* TSDT */
        case 0x0010u: /* NIT / ST */
        case 0x0011u: /* SDT / BAT */
        case 0x0012u: /* EIT / CIT */
        case 0x0013u: /* RST */
        case 0x0014u: /* TDT / TOT */
            return 1;
        default:
            return 0;
    }
}

/* Table 2-34 stream_type -> VIDEO/AUDIO/OTHER. STREAM_OTHER=0, STREAM_VIDEO=1, STREAM_AUDIO=2. */
static const uint8_t s_stream_category_table[256] = {
    [0x01] = STREAM_VIDEO,  /* MPEG-1 Video */
    [0x02] = STREAM_VIDEO,  /* MPEG-2 Video */
    [0x03] = STREAM_AUDIO,  /* MPEG-1 Audio */
    [0x04] = STREAM_AUDIO,  /* MPEG-2 Audio */
    [0x0F] = STREAM_AUDIO,  /* AAC ADTS */
    [0x10] = STREAM_VIDEO,  /* MPEG-4 Part 2 Visual */
    [0x11] = STREAM_AUDIO,  /* AAC LATM */
    [0x1B] = STREAM_VIDEO,  /* AVC/H.264 */
    [0x1C] = STREAM_AUDIO,  /* AAC */
    [0x1E] = STREAM_VIDEO,  /* Auxiliary video */
    [0x1F] = STREAM_VIDEO,  /* SVC */
    [0x20] = STREAM_VIDEO,  /* MVC */
    [0x21] = STREAM_VIDEO,  /* JPEG 2000 */
    [0x22] = STREAM_VIDEO,  /* H.262 additional view 3D */
    [0x23] = STREAM_VIDEO,  /* H.264 additional view 3D */
    [0x24] = STREAM_VIDEO,  /* HEVC/H.265 */
    [0x25] = STREAM_VIDEO,  /* HEVC temporal subset */
    [0x26] = STREAM_VIDEO,  /* MVCD */
    [0x28] = STREAM_VIDEO,  /* HEVC enhancement */
    [0x29] = STREAM_VIDEO,
    [0x2A] = STREAM_VIDEO,
    [0x2B] = STREAM_VIDEO,
    [0x2D] = STREAM_AUDIO,  /* ISO 23008-3 MHAS main */
    [0x2E] = STREAM_AUDIO,  /* ISO 23008-3 MHAS auxiliary */
    [0x31] = STREAM_VIDEO,  /* H.265 substream */
    [0x32] = STREAM_VIDEO,  /* JPEG XS */
    [0x33] = STREAM_VIDEO,  /* VVC/H.266 */
    [0x34] = STREAM_VIDEO,  /* VVC temporal subset */
    [0x35] = STREAM_VIDEO,  /* EVC */
    [0x36] = STREAM_VIDEO,  /* LCEVC */
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

void pat_table_init(pat_table_t* table) {
    table->program_count = 0;
    table->capacity = 2;
    table->programs = (pat_program_t*)malloc(sizeof(pat_program_t) * table->capacity);
}

void pat_table_cleanup(pat_table_t* table) {
    free(table->programs);
}

void pat_table_push(pat_table_t* table, pat_program_t program) {
    if (table->program_count == table->capacity) {
        table->capacity *= 2;
        table->programs = realloc(table->programs, sizeof(pat_program_t) * table->capacity);
    }
    table->programs[table->program_count] = program;
    table->program_count++;
}

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
    if (packet->pid == TS_PID_NULL || packet->pid >= MAX_PID)
        return reported;
    if (s_previous_continuity_counter[packet->pid] > 15)
        return reported;

    /* Ignore packets with adaptation_field_control == 0 (reserved). */
    if (packet->adaptation_field_control == 0u)
        return reported;

    /* Discontinuity indicator authorizes continuity counter discontinuity. */
    if (packet->discontinuity_indicator)
        return reported;

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

void pmt_table_ensure_capacity(const pat_table_t* pat, pmt_t** pmt_table, size_t* capacity) {
    while (*capacity < pat->program_count) {
        size_t new_cap = (*capacity == 0) ? 2 : *capacity * 2;
        if (new_cap < pat->program_count)
            new_cap = pat->program_count;
        *pmt_table = realloc(*pmt_table, new_cap * sizeof(pmt_t));
        for (size_t k = *capacity; k < new_cap; k++) {
            (*pmt_table)[k].pcr_pid = 0;
            (*pmt_table)[k].es_count = 0;
            (*pmt_table)[k].capacity = 2;
            (*pmt_table)[k].es_list = (pmt_es_t*)malloc(sizeof(pmt_es_t) * 2);
        }
        *capacity = new_cap;
    }
}

void print_ts_report(const pat_table_t* pat, const pmt_t* pmt_table, const pid_count_list_t* list) {
    printf("\n");
    printf("┌────────────────────────────────────────────────── PAT\n");
    printf("│  %-22s %s\n", "Program number", "PMT PID");
    printf("├──────────────────────────────────────────────────\n");
    for (size_t i = 0; i < pat->program_count; i++) {
        char a[16], b[16];
        snprintf(a, sizeof a, "0x%04X", (unsigned)pat->programs[i].program_number);
        snprintf(b, sizeof b, "0x%04X", (unsigned)pat->programs[i].pid);
        printf("│  %-22s %s\n", a, b);
    }
    printf("└──────────────────────────────────────────────────\n\n");

    printf("┌────────────────────────────────────────────────── PID list\n");
    printf("│  %-12s %-10s %s\n", "PID", "Type", "Count");
    printf("├──────────────────────────────────────────────────\n");
    for (size_t i = 0; i < list->count; i++) {
        char pid_buf[12];
        snprintf(pid_buf, sizeof pid_buf, "0x%04X", (unsigned)list->pids[i].pid);
        printf("│  %-12s %-10s %zu\n", pid_buf, pid_type_to_string(list->pids[i].type), list->pids[i].count);
    }
    printf("└──────────────────────────────────────────────────\n\n");

    for (size_t i = 0; i < pat->program_count; i++) {
        printf("┌────────────────────────────────────────────────── Program 0x%04X (PMT 0x%04X)\n",
               (unsigned)pat->programs[i].program_number, (unsigned)pat->programs[i].pid);
        printf("│  PCR PID                 0x%04X\n", (unsigned)pmt_table[i].pcr_pid);
        printf("├──────────────────────────────────────────────────\n");
        printf("│  %-10s %-10s %-6s %s\n", "Stream", "Elem PID", "Lang", "Codec");
        printf("├──────────────────────────────────────────────────\n");
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            const char* codec = stream_type_to_codec_string(pmt_table[i].es_list[j].stream_type);
            const char* lang = pmt_table[i].es_list[j].language_code[0] != '\0'
                ? pmt_table[i].es_list[j].language_code : "-";
            char st_buf[12], pid_buf[12];
            snprintf(st_buf, sizeof st_buf, "0x%02X", (unsigned)pmt_table[i].es_list[j].stream_type);
            snprintf(pid_buf, sizeof pid_buf, "0x%04X", (unsigned)pmt_table[i].es_list[j].elementary_pid);
            printf("│  %-10s %-10s %-6s %s\n", st_buf, pid_buf, lang, codec);
        }
        printf("└──────────────────────────────────────────────────\n\n");
    }
}

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
    for (size_t i = 0; i < pat->program_count; i++)
        if (pat->programs[i].pid < MAX_PID)
            defined[pat->programs[i].pid] = 1;
    for (size_t i = 0; i < pmt_capacity && pmt_table; i++) {
        if (pmt_table[i].pcr_pid < MAX_PID)
            defined[pmt_table[i].pcr_pid] = 1;
        for (size_t j = 0; j < pmt_table[i].es_count; j++)
            if (pmt_table[i].es_list[j].elementary_pid < MAX_PID)
                defined[pmt_table[i].es_list[j].elementary_pid] = 1;
    }
    for (size_t i = 0; i < list->count; i++) {
        uint16_t pid = list->pids[i].pid;
        if (pid < MAX_PID && !defined[pid]) {
            printf("│  Undefined PID: 0x%04X (packets: %zu)\n", (unsigned)pid, list->pids[i].count);
            if (errors_found)
                *errors_found = 1;
        }
    }
}

void print_pid_ratio_header(const pid_count_list_t* list, long total_packets) {
    if (total_packets <= 0)
        return;
    printf("\n");
    printf("┌────────────────────────────────────────────────── PID statistics (ratio of total packets)\n");
    printf("│  %-12s %-12s %s\n", "PID", "Count", "Ratio");
    printf("├──────────────────────────────────────────────────\n");
    for (size_t i = 0; i < list->count; i++) {
        double ratio = 100.0 * (double)list->pids[i].count / (double)total_packets;
        printf("│  0x%04X      %-12zu %.2f%%\n",
               (unsigned)list->pids[i].pid, list->pids[i].count, ratio);
    }
    printf("│  %-12s %-12ld %s\n", "(total)", total_packets, "100.00%");
    printf("└──────────────────────────────────────────────────\n\n");
}

void ts_state_cleanup(pat_table_t* pat, pmt_t* pmt_table, size_t pmt_table_capacity, pid_count_list_t* list) {
    if (pmt_table) {
        for (size_t i = 0; i < pmt_table_capacity; i++)
            free(pmt_table[i].es_list);
        free(pmt_table);
    }
    pat_table_cleanup(pat);
    pid_count_list_cleanup(list);
}

/*int pat_contains_pid(pat_table_t* pat, uint16_t pid) {
    int ret = 0;
    for (size_t i = 0; i < pat->program_count; i++) {
        if (pat->programs[i].pid == pid) {
            return 1;
        }
    }
    return ret;
}*/

#define PKT_FMT "│  %-24s %s\n"

static void pkt_line(const char* label, const char* value) {
    printf(PKT_FMT, label, value);
}

#define PES_LINE_FMT "│  %-26s %s\n"

static void pes_line(const char* label, const char* value) {
    printf(PES_LINE_FMT, label, value);
}

void print_pes_header(const pes_packet_t* p) {
    char buf[64];
    printf("\n");
    printf("┌────────────────────────────────────────────────── PES header\n");
    snprintf(buf, sizeof buf, "0x%06X", p->packet_start_code_prefix);
    pes_line("packet_start_code_prefix", buf);
    snprintf(buf, sizeof buf, "0x%02X", (unsigned)p->stream_id);
    pes_line("stream_id", buf);
    snprintf(buf, sizeof buf, "%u", (unsigned)p->packet_length);
    pes_line("packet_length", buf);
    snprintf(buf, sizeof buf, "%u%u", p->scrambling_control / 2, p->scrambling_control % 2);
    pes_line("scrambling_control", buf);
    pes_line("priority_indicator", BOOL_STRING(p->priority_indicator));
    pes_line("data_alignment_indicator", BOOL_STRING(p->data_alignment_indicator));
    pes_line("copyright_flag", BOOL_STRING(p->copyright_flag));
    pes_line("original_or_copy", BOOL_STRING(p->original_or_copy));
    snprintf(buf, sizeof buf, "%u%u", p->PTS_DTS_flags / 2, p->PTS_DTS_flags % 2);
    pes_line("PTS_DTS_flags", buf);
    pes_line("escr_flag", BOOL_STRING(p->escr_flag));
    pes_line("es_rate_flag", BOOL_STRING(p->es_rate_flag));
    pes_line("dsm_trick_mode_flag", BOOL_STRING(p->dsm_trick_mode_flag));
    pes_line("additional_copy_info_flag", BOOL_STRING(p->additional_copy_info_flag));
    pes_line("crc_flag", BOOL_STRING(p->crc_flag));
    pes_line("extension_flag", BOOL_STRING(p->extension_flag));
    snprintf(buf, sizeof buf, "%u", (unsigned)p->header_length);
    pes_line("header_length", buf);
    printf("└──────────────────────────────────────────────────\n");
}

static void format_pts_dts_string(uint64_t ts_90k, char* buf, size_t buf_size) {
    uint64_t total_ms = (ts_90k * 1000u) / 90000u;
    uint64_t hours   = total_ms / 3600000u;
    uint64_t minutes = (total_ms % 3600000u) / 60000u;
    uint64_t seconds = (total_ms % 60000u) / 1000u;
    uint64_t millis  = total_ms % 1000u;
    snprintf(buf, buf_size, "0x%012llX (%02llu:%02llu:%02llu.%03llu)",
        (unsigned long long)ts_90k,
        (unsigned long long)hours,
        (unsigned long long)minutes,
        (unsigned long long)seconds,
        (unsigned long long)millis);
}

void print_pts_dts(const pes_packet_t* p) {
    char buf[64];
    printf("\n");
    printf("┌────────────────────────────────────────────────── PTS/DTS\n");
    if (p->PTS_DTS_flags >= 2u) {
        format_pts_dts_string(p->pts, buf, sizeof buf);
        pes_line("PTS", buf);
        if (p->PTS_DTS_flags == 3u) {
            format_pts_dts_string(p->dts, buf, sizeof buf);
            pes_line("DTS", buf);
        }
    } else {
        pes_line("PTS", "(not present)");
    }
    printf("└──────────────────────────────────────────────────\n");
}

void print_pes_one_line(const pes_packet_t* p, size_t index) {
    char pts_buf[64];
    char dts_buf[64];
    if (p->PTS_DTS_flags >= 2u) {
        format_pts_dts_string(p->pts, pts_buf, sizeof pts_buf);
        if (p->PTS_DTS_flags == 3u) {
            format_pts_dts_string(p->dts, dts_buf, sizeof dts_buf);
            printf("#%-4zu  sid=0x%02X  PTS=%s  DTS=%s\n",
                index, (unsigned)p->stream_id, pts_buf, dts_buf);
        } else {
            printf("#%-4zu  sid=0x%02X  PTS=%s\n", index, (unsigned)p->stream_id, pts_buf);
        }
    } else {
        printf("#%-4zu  sid=0x%02X  (no PTS/DTS)\n", index, (unsigned)p->stream_id);
    }
}

void print_pes_streams_summary(const pmt_t* pmt_table, size_t pmt_table_capacity) {
    size_t n_streams = 0;
    for (size_t i = 0; i < pmt_table_capacity; i++) {
        n_streams += pmt_table[i].es_count;
    }
    printf("\n┌────────────────────────────────────────────────── PES streams (%zu)\n", n_streams);
    for (size_t i = 0; i < pmt_table_capacity; i++) {
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            const pmt_es_t* es = &pmt_table[i].es_list[j];
            const char* codec = stream_type_to_codec_string(es->stream_type);
            stream_category_t cat = stream_category_from_type(es->stream_type);
            const char* cat_str = cat == STREAM_VIDEO ? "Video" : cat == STREAM_AUDIO ? "Audio" : "Other";
            printf("│  0x%04X  %-8s (%s)\n", es->elementary_pid, codec, cat_str);
        }
    }
    printf("└──────────────────────────────────────────────────\n");
}

#define PES_PREVIEW_FIRST 10u
#define PES_PREVIEW_LAST  10u

void print_pes_packet_list_report(const pes_packet_list_table_t* table) {
    for (size_t i = 0; i < table->count; i++) {
        const pes_packet_list_t* plist = &table->lists[i];
        const size_t n = plist->count;
        printf("\n┌────────────────────────────────────────────────── PID 0x%04X (%zu PES)\n",
            plist->pid, n);
        if (n == 0u) {
            printf("└──────────────────────────────────────────────────\n");
            continue;
        }
        const size_t show_first = (n <= PES_PREVIEW_FIRST + PES_PREVIEW_LAST) ? n : PES_PREVIEW_FIRST;
        const size_t show_last  = (n <= PES_PREVIEW_FIRST + PES_PREVIEW_LAST) ? 0u : PES_PREVIEW_LAST;
        for (size_t j = 0; j < show_first; j++) {
            printf("├── PES #%zu of %zu ───────────────────────────────┤\n", j, n);
            print_pes_header(&plist->packets[j]);
            print_pts_dts(&plist->packets[j]);
        }
        if (show_last > 0u) {
            printf("│  ... %zu more ...\n", n - show_first - show_last);
            for (size_t j = n - show_last; j < n; j++) {
                print_pes_one_line(&plist->packets[j], j);
            }
        }
        printf("└──────────────────────────────────────────────────\n");
    }
}

void print_packet_header(ts_packet_t* packet, size_t packet_index) {
    int has_adaptation = (packet->adaptation_field_control & 0x02u) != 0u;
    int has_payload    = (packet->adaptation_field_control & 0x01u) != 0u;
    char buf[64];

    printf("\n");
    printf("┌────────────────────────────────────────────────── TS packet\n");
    snprintf(buf, sizeof buf, "%zu", packet_index);
    pkt_line("packet_index", buf);
    snprintf(buf, sizeof buf, "0x%02X", packet->sync_byte);
    pkt_line("sync_byte", buf);
    snprintf(buf, sizeof buf, "0x%04X", packet->pid);
    pkt_line("PID", buf);
    pkt_line("TEI", BOOL_STRING(packet->tei));
    pkt_line("PUSI", BOOL_STRING(packet->pusi));
    pkt_line("transport_priority", BOOL_STRING(packet->transport_priority));
    snprintf(buf, sizeof buf, "%u", (unsigned)packet->tsc);
    pkt_line("TSC", buf);
    const char* afc_str = packet->adaptation_field_control == 1 ? "1 (payload only)" :
                          packet->adaptation_field_control == 2 ? "2 (adaptation only)" :
                          packet->adaptation_field_control == 3 ? "3 (adaptation+payload)" : "reserved";
    pkt_line("adaptation_field_control", afc_str);
    snprintf(buf, sizeof buf, "%u", (unsigned)packet->continuity_counter);
    pkt_line("continuity_counter", buf);
    printf("├──────────────────────────────────────────────────\n");

    if (has_adaptation) {
        printf("│  Adaptation field\n");
        snprintf(buf, sizeof buf, "%u", (unsigned)packet->adaptation_field_length);
        printf("│    %-22s %s\n", "length", buf);
        printf("│    %-22s %s\n", "discontinuity", BOOL_STRING(packet->discontinuity_indicator));
        printf("│    %-22s %s\n", "random_access", BOOL_STRING(packet->random_access_indicator));
        printf("│    %-22s %s\n", "ES_priority", BOOL_STRING(packet->es_priority_indicator));
        if (packet->pcr_flag) {
            if (packet->pcr_valid) {
                snprintf(buf, sizeof buf, "%llu (27 MHz)", (unsigned long long)(packet->pcr_base * 300u + packet->pcr_ext));
                printf("│    %-22s %s\n", "PCR", buf);
            } else
                printf("│    %-22s %s\n", "PCR", "(flag set, not parsed)");
        }
        if (packet->opcr_flag) {
            if (packet->opcr_valid) {
                snprintf(buf, sizeof buf, "%llu (27 MHz)", (unsigned long long)(packet->opcr_base * 300u + packet->opcr_ext));
                printf("│    %-22s %s\n", "OPCR", buf);
            } else
                printf("│    %-22s %s\n", "OPCR", "(flag set, not parsed)");
        }
        if (packet->splicing_point_flag && packet->splice_countdown_valid) {
            snprintf(buf, sizeof buf, "%d", (int)packet->splice_countdown);
            printf("│    %-22s %s\n", "splice_countdown", buf);
        }
        if (packet->transport_private_data_flag && packet->transport_private_data_valid) {
            snprintf(buf, sizeof buf, "length=%u offset=%u",
                     (unsigned)packet->transport_private_data_length, (unsigned)packet->transport_private_data_offset);
            printf("│    %-22s %s\n", "transport_private_data", buf);
        }
        if (packet->adaptation_field_extension_flag && packet->adaptation_extension_valid) {
            snprintf(buf, sizeof buf, "length=%u", (unsigned)packet->adaptation_extension_length);
            printf("│    %-22s %s\n", "adaptation_extension", buf);
        }
        printf("├──────────────────────────────────────────────────\n");
    }

    if (has_payload) {
        snprintf(buf, sizeof buf, "offset=%u length=%u",
                 (unsigned)packet->payload_offset, (unsigned)packet->payload_length);
        pkt_line("Payload", buf);
    } else
        pkt_line("Payload", "(none)");

    printf("└──────────────────────────────────────────────────\n\n");
}

void print_psi_header(psi_header_t* header) {
    printf("0x%02X\t table_id\n", header->table_id);
    printf("%s\t section_syntax_indicator\n", BOOL_STRING(header->section_syntax_indicator));
    printf("%hu\t section_length\n", header->section_length);
    printf("0x%04X\t transport_stream_id\n", header->transport_stream_id);
    printf("%d\t version_number\n", header->version_number);
    printf("%s\t current_next_indicator\n", BOOL_STRING(header->current_next_indicator));
    printf("%d\t section_number\n", header->section_number);
    printf("%d\t last_section_number\n", header->last_section_number);
    printf("0x%04X\t section_offset\n", header->section_offset);
}

const char* pid_type_to_string(pid_type_t type) {
    switch(type) {
        case PID_UNKNOWN:
            return "UNKNOWN";
        case PID_PAT:
            return "PAT";
        case PID_PMT:
            return "PMT";
        case PID_SI:
            return "SI";
        case PID_VIDEO:
            return "VIDEO";
        case PID_AUDIO:
            return "AUDIO";
        case PID_NULL:
            return "NULL";
        default:
            return "";
    }
}

void pid_count_list_init(pid_count_list_t* list) {
    list->capacity = 64;
    list->count = 0;
    list->pids = (pid_count_t*)malloc(sizeof(pid_count_t) * list->capacity);
}

void pid_count_list_update(pid_count_list_t* list, uint16_t pid) {
    int idx = (int)pid_count_list_find(list, pid);
    if (idx != -1) {
        list->pids[idx].count++;
    } else {
        pid_count_list_push(list, pid);
    }
}

void pid_count_list_push(pid_count_list_t* list, uint16_t pid) {
    if (pid_count_list_contains(list, pid)) {
        return;
    } else {
        list->pids[list->count].pid = pid;
        list->pids[list->count].count = 1;
        list->pids[list->count].type = PID_UNKNOWN;
        list->count++;
        if (list->count == list->capacity) {
            list->capacity *= 2;
            list->pids = realloc(list->pids, sizeof(pid_count_t) * list->capacity);
        }
    }
}

int pid_count_list_contains(pid_count_list_t* list, uint16_t pid) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->pids[i].pid == pid) {
            return 1;
        }
    }
    return 0;
}

int pid_count_list_find(pid_count_list_t* list, uint16_t pid) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->pids[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

void pid_count_list_cleanup(pid_count_list_t* list) {
    free(list->pids);
}

void pid_count_list_update_type(pid_count_list_t* list, uint16_t pid, pid_type_t type) {
    int idx = (int)pid_count_list_find(list, pid);
    if (idx != -1) {
        list->pids[idx].type = type;
    }
}

#define PES_PACKET_LIST_INITIAL_CAPACITY 32u

void pes_packet_list_init(pes_packet_list_t* list) {
    list->pid = 0;
    list->packets = NULL;
    list->count = 0;
    list->capacity = 0;
}

void pes_packet_list_push(pes_packet_list_t* list, const pes_packet_t* p) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2u : PES_PACKET_LIST_INITIAL_CAPACITY;
        pes_packet_t* new_packets = (pes_packet_t*)realloc(list->packets, sizeof(pes_packet_t) * new_cap);
        if (new_packets == NULL) {
            return;
        }
        list->packets = new_packets;
        list->capacity = new_cap;
    }
    list->packets[list->count++] = *p;
}

void pes_packet_list_cleanup(pes_packet_list_t* list) {
    free(list->packets);
    list->packets = NULL;
    list->count = 0;
    list->capacity = 0;
}

#define PES_PACKET_LIST_TABLE_INITIAL_CAPACITY 16u

void pes_packet_list_table_init(pes_packet_list_table_t* table) {
    table->lists = NULL;
    table->count = 0;
    table->capacity = 0;
}

int pes_packet_list_table_find(const pes_packet_list_table_t* table, uint16_t pid) {
    for (size_t i = 0; i < table->count; i++) {
        if (table->lists[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

pes_packet_list_t* pes_packet_list_table_get_or_create(pes_packet_list_table_t* table, uint16_t pid) {
    int idx = pes_packet_list_table_find(table, pid);
    if (idx >= 0) {
        return &table->lists[(size_t)idx];
    }
    if (table->count >= table->capacity) {
        size_t new_cap = table->capacity ? table->capacity * 2u : PES_PACKET_LIST_TABLE_INITIAL_CAPACITY;
        pes_packet_list_t* new_lists = (pes_packet_list_t*)realloc(
            table->lists, sizeof(pes_packet_list_t) * new_cap);
        if (new_lists == NULL) {
            return NULL;
        }
        table->lists = new_lists;
        table->capacity = new_cap;
    }
    pes_packet_list_t* list = &table->lists[table->count++];
    pes_packet_list_init(list);
    list->pid = pid;
    return list;
}

void pes_packet_list_table_push_packet(pes_packet_list_table_t* table, uint16_t pid, const pes_packet_t* p) {
    pes_packet_list_t* list = pes_packet_list_table_get_or_create(table, pid);
    if (list != NULL) {
        pes_packet_list_push(list, p);
    }
}

void pes_packet_list_table_cleanup(pes_packet_list_table_t* table) {
    for (size_t i = 0; i < table->count; i++) {
        pes_packet_list_cleanup(&table->lists[i]);
    }
    free(table->lists);
    table->lists = NULL;
    table->count = 0;
    table->capacity = 0;
}

#define PES_BUFFER_TABLE_INITIAL_CAPACITY 16u
#define PES_BUFFER_ENTRY_INITIAL_CAPACITY 64u

static int pes_buffer_table_find(const pes_buffer_table_t* table, uint16_t pid) {
    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

void pes_buffer_table_init(pes_buffer_table_t* table) {
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}

pes_buffer_entry_t* pes_buffer_table_get_or_create(pes_buffer_table_t* table, uint16_t pid) {
    int idx = pes_buffer_table_find(table, pid);
    if (idx >= 0) {
        return &table->entries[(size_t)idx];
    }
    if (table->count >= table->capacity) {
        size_t new_cap = table->capacity ? table->capacity * 2u : PES_BUFFER_TABLE_INITIAL_CAPACITY;
        pes_buffer_entry_t* new_entries = (pes_buffer_entry_t*)realloc(
            table->entries, sizeof(pes_buffer_entry_t) * new_cap);
        if (new_entries == NULL) {
            return NULL;
        }
        table->entries = new_entries;
        table->capacity = new_cap;
    }
    pes_buffer_entry_t* entry = &table->entries[table->count++];
    entry->pid = pid;
    entry->buffer = NULL;
    entry->length = 0;
    entry->capacity = 0;
    return entry;
}

void pes_buffer_table_append(pes_buffer_entry_t* entry, const uint8_t* data, size_t len) {
    if (len == 0) {
        return;
    }
    if (entry->length + len > entry->capacity) {
        size_t new_cap = entry->capacity ? entry->capacity * 2u : PES_BUFFER_ENTRY_INITIAL_CAPACITY;
        while (new_cap < entry->length + len) {
            new_cap *= 2u;
        }
        uint8_t* new_buf = (uint8_t*)realloc(entry->buffer, new_cap);
        if (new_buf == NULL) {
            return;
        }
        entry->buffer = new_buf;
        entry->capacity = new_cap;
    }
    memcpy(entry->buffer + entry->length, data, len);
    entry->length += len;
}

void pes_buffer_table_clear_length(pes_buffer_entry_t* entry) {
    entry->length = 0;
}

void pes_buffer_table_cleanup(pes_buffer_table_t* table) {
    for (size_t i = 0; i < table->count; i++) {
        free(table->entries[i].buffer);
        table->entries[i].buffer = NULL;
        table->entries[i].length = 0;
        table->entries[i].capacity = 0;
    }
    free(table->entries);
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}

void print_hexdump(const uint8_t* buffer, size_t length) {
    const size_t width = 16;
    for (size_t i = 0; i < length; i += width) {
        printf("%08zx  ", i);
        for (size_t j = 0; j < width; j++) {
            if (i + j < length)
                printf("%02x ", buffer[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < width && i + j < length; j++) {
            unsigned char c = buffer[i + j];
            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
}

uint64_t pcr_to_time(uint64_t pcr_base, uint64_t pcr_ext) {
    return pcr_base * 300 + pcr_ext;
}

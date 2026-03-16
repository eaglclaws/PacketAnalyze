#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#define BOOL_STRING(x) (x ? "TRUE" : "FALSE")

#define MAX_PID 8192
#define CC_NEVER_SEEN 16
static uint8_t s_previous_continuity_counter[MAX_PID];
static uint8_t s_previous_had_payload[MAX_PID];

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

void pat_table_clean(pat_table_t* table) {
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
        s_previous_had_payload[i] = 0;
    }
}

void ts_cc_check(const ts_packet_t* packet) {
    if (packet->sync_byte != 0x47) {
        printf("Sync byte error: PID: 0x%04X, SB: 0x%02X\n", packet->pid, packet->sync_byte);
    }
    if (packet->pid == TS_PID_NULL || packet->pid >= MAX_PID)
        return;
    if (s_previous_continuity_counter[packet->pid] > 15 || !s_previous_had_payload[packet->pid])
        return;
    uint8_t expected = (s_previous_continuity_counter[packet->pid] + 1) % 16;
    if (packet->continuity_counter != expected) {
        printf("Continuity counter error: PID: 0x%04X, CC: %u -> %u\n",
               packet->pid, (unsigned)s_previous_continuity_counter[packet->pid], (unsigned)packet->continuity_counter);
    }
}

void ts_cc_update(const ts_packet_t* packet) {
    if (packet->pid < MAX_PID) {
        s_previous_continuity_counter[packet->pid] = packet->continuity_counter;
        s_previous_had_payload[packet->pid] = (uint8_t)(packet->payload_length > 0 ? 1 : 0);
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

void print_ts_report(const pat_table_t* pat, const pmt_t* pmt_table, const pid_count_list_t* list, long packet_count) {
    printf("\n");
    printf("┌────────────────────────────────────────────────── Summary\n");
    printf("│  Total packets            %ld\n", packet_count);
    printf("└──────────────────────────────────────────────────\n\n");

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

void ts_cleanup(pat_table_t* pat, pmt_t* pmt_table, size_t pmt_table_capacity, pid_count_list_t* list) {
    if (pmt_table) {
        for (size_t i = 0; i < pmt_table_capacity; i++)
            free(pmt_table[i].es_list);
        free(pmt_table);
    }
    pat_table_clean(pat);
    pid_count_list_clean(list);
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

void print_packet_header(ts_packet_t* packet) {
    int has_adaptation = (packet->adaptation_field_control & 0x02u) != 0u;
    int has_payload    = (packet->adaptation_field_control & 0x01u) != 0u;
    char buf[64];

    printf("\n");
    printf("┌────────────────────────────────────────────────── TS packet\n");
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

void pid_count_list_clean(pid_count_list_t* list) {
    free(list->pids);
}

void pid_count_list_update_type(pid_count_list_t* list, uint16_t pid, pid_type_t type) {
    int idx = (int)pid_count_list_find(list, pid);
    if (idx != -1) {
        list->pids[idx].type = type;
    }
}

#include "utils.h"

#include <stdio.h>

/*
 * Rendering utilities:
 * - human-readable reports (PAT/PMT/PID/PES)
 * - packet header box views
 * - generic hexdump output
 */

#define PKT_FMT "│  %-24s %s\n"
#define PES_LINE_FMT "│  %-26s %s\n"

/* ============================================================================
 * Shared formatting helpers
 * ========================================================================== */
typedef enum line_style_s {
    LINE_STYLE_PACKET = 0,
    LINE_STYLE_PES = 1
} line_style_t;

static void print_labeled_line(line_style_t style, const char* label, const char* value) {
    if (style == LINE_STYLE_PES) {
        printf(PES_LINE_FMT, label, value);
    } else {
        printf(PKT_FMT, label, value);
    }
}

static void format_pts_dts_string(uint64_t ts_90k, char* buf, size_t buf_size) {
    uint64_t total_ms = (ts_90k * 1000u) / 90000u;
    uint64_t hours = total_ms / 3600000u;
    uint64_t minutes = (total_ms % 3600000u) / 60000u;
    uint64_t seconds = (total_ms % 60000u) / 1000u;
    uint64_t millis = total_ms % 1000u;
    snprintf(buf, buf_size, "0x%012llX (%02llu:%02llu:%02llu.%03llu)",
             (unsigned long long)ts_90k,
             (unsigned long long)hours,
             (unsigned long long)minutes,
             (unsigned long long)seconds,
             (unsigned long long)millis);
}

/* ============================================================================
 * Report / summary printing
 * ========================================================================== */
void print_pid_ratio_header(const pid_count_list_t* list, long total_packets) {
    if (total_packets <= 0) {
        return;
    }
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

/* ============================================================================
 * PES printing
 * ========================================================================== */
void print_pes_header(const pes_packet_t* p) {
    char buf[64];
    printf("\n");
    printf("┌────────────────────────────────────────────────── PES header\n");
    snprintf(buf, sizeof buf, "0x%06X", p->packet_start_code_prefix);
    print_labeled_line(LINE_STYLE_PES, "packet_start_code_prefix", buf);
    snprintf(buf, sizeof buf, "0x%02X", (unsigned)p->stream_id);
    print_labeled_line(LINE_STYLE_PES, "stream_id", buf);
    snprintf(buf, sizeof buf, "%u", (unsigned)p->packet_length);
    print_labeled_line(LINE_STYLE_PES, "packet_length", buf);
    snprintf(buf, sizeof buf, "%u%u", p->scrambling_control / 2, p->scrambling_control % 2);
    print_labeled_line(LINE_STYLE_PES, "scrambling_control", buf);
    print_labeled_line(LINE_STYLE_PES, "priority_indicator", BOOL_STRING(p->priority_indicator));
    print_labeled_line(LINE_STYLE_PES, "data_alignment_indicator", BOOL_STRING(p->data_alignment_indicator));
    print_labeled_line(LINE_STYLE_PES, "copyright_flag", BOOL_STRING(p->copyright_flag));
    print_labeled_line(LINE_STYLE_PES, "original_or_copy", BOOL_STRING(p->original_or_copy));
    snprintf(buf, sizeof buf, "%u%u", p->PTS_DTS_flags / 2, p->PTS_DTS_flags % 2);
    print_labeled_line(LINE_STYLE_PES, "PTS_DTS_flags", buf);
    print_labeled_line(LINE_STYLE_PES, "escr_flag", BOOL_STRING(p->escr_flag));
    print_labeled_line(LINE_STYLE_PES, "es_rate_flag", BOOL_STRING(p->es_rate_flag));
    print_labeled_line(LINE_STYLE_PES, "dsm_trick_mode_flag", BOOL_STRING(p->dsm_trick_mode_flag));
    print_labeled_line(LINE_STYLE_PES, "additional_copy_info_flag", BOOL_STRING(p->additional_copy_info_flag));
    print_labeled_line(LINE_STYLE_PES, "crc_flag", BOOL_STRING(p->crc_flag));
    print_labeled_line(LINE_STYLE_PES, "extension_flag", BOOL_STRING(p->extension_flag));
    snprintf(buf, sizeof buf, "%u", (unsigned)p->header_length);
    print_labeled_line(LINE_STYLE_PES, "header_length", buf);
    printf("└──────────────────────────────────────────────────\n");
}

void print_pts_dts(const pes_packet_t* p) {
    char buf[64];
    printf("\n");
    printf("┌────────────────────────────────────────────────── PTS/DTS\n");
    if (p->PTS_DTS_flags >= 2u) {
        format_pts_dts_string(p->pts, buf, sizeof buf);
        print_labeled_line(LINE_STYLE_PES, "PTS", buf);
        if (p->PTS_DTS_flags == 3u) {
            format_pts_dts_string(p->dts, buf, sizeof buf);
            print_labeled_line(LINE_STYLE_PES, "DTS", buf);
        }
    } else {
        print_labeled_line(LINE_STYLE_PES, "PTS", "(not present)");
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
        for (size_t j = 0; j < n; j++) {
            printf("├── PES #%zu of %zu ───────────────────────────────┤\n", j + 1, n);
            print_pes_header(&plist->packets[j]);
            print_pts_dts(&plist->packets[j]);
        }
        printf("└──────────────────────────────────────────────────\n");
    }
}

/* ============================================================================
 * TS/PSI packet printing
 * ========================================================================== */
void print_packet_header(ts_packet_t* packet, size_t packet_index) {
    int has_adaptation = (packet->adaptation_field_control & 0x02u) != 0u;
    int has_payload = (packet->adaptation_field_control & 0x01u) != 0u;
    char buf[64];

    printf("\n");
    printf("┌────────────────────────────────────────────────── TS packet\n");
    snprintf(buf, sizeof buf, "%zu", packet_index);
    print_labeled_line(LINE_STYLE_PACKET, "packet_index", buf);
    snprintf(buf, sizeof buf, "0x%02X", packet->sync_byte);
    print_labeled_line(LINE_STYLE_PACKET, "sync_byte", buf);
    snprintf(buf, sizeof buf, "0x%04X", packet->pid);
    print_labeled_line(LINE_STYLE_PACKET, "PID", buf);
    print_labeled_line(LINE_STYLE_PACKET, "TEI", BOOL_STRING(packet->tei));
    print_labeled_line(LINE_STYLE_PACKET, "PUSI", BOOL_STRING(packet->pusi));
    print_labeled_line(LINE_STYLE_PACKET, "transport_priority", BOOL_STRING(packet->transport_priority));
    snprintf(buf, sizeof buf, "%u", (unsigned)packet->tsc);
    print_labeled_line(LINE_STYLE_PACKET, "TSC", buf);
    {
        const char* afc_str = packet->adaptation_field_control == 1 ? "1 (payload only)" :
                              packet->adaptation_field_control == 2 ? "2 (adaptation only)" :
                              packet->adaptation_field_control == 3 ? "3 (adaptation+payload)" : "reserved";
        print_labeled_line(LINE_STYLE_PACKET, "adaptation_field_control", afc_str);
    }
    snprintf(buf, sizeof buf, "%u", (unsigned)packet->continuity_counter);
    print_labeled_line(LINE_STYLE_PACKET, "continuity_counter", buf);
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
            } else {
                printf("│    %-22s %s\n", "PCR", "(flag set, not parsed)");
            }
        }
        if (packet->opcr_flag) {
            if (packet->opcr_valid) {
                snprintf(buf, sizeof buf, "%llu (27 MHz)", (unsigned long long)(packet->opcr_base * 300u + packet->opcr_ext));
                printf("│    %-22s %s\n", "OPCR", buf);
            } else {
                printf("│    %-22s %s\n", "OPCR", "(flag set, not parsed)");
            }
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
        print_labeled_line(LINE_STYLE_PACKET, "Payload", buf);
    } else {
        print_labeled_line(LINE_STYLE_PACKET, "Payload", "(none)");
    }

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

/* ============================================================================
 * Generic binary dump
 * ========================================================================== */
void print_hexdump(const uint8_t* buffer, size_t length) {
    const size_t width = 16;
    for (size_t i = 0; i < length; i += width) {
        printf("%08zx  ", i);
        for (size_t j = 0; j < width; j++) {
            if (i + j < length) {
                printf("%02x ", buffer[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) {
                printf(" ");
            }
        }
        printf(" |");
        for (size_t j = 0; j < width && i + j < length; j++) {
            unsigned char c = buffer[i + j];
            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
}

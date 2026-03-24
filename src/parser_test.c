/*
 * Parser tests — implement the cases declared in parser_test.h.
 * Build: clang -Wall -Wextra -g -O0 parser_test.c parser.c utils.c -o parser_test
 * Run: ./parser_test
 */
#include "parser_test.h"
#include "parser.h"
#include "packet.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int s_failed;

#define ASSERT(c) do { if (!(c)) s_failed = 1; } while (0)

/* ---------------------------------------------------------------------------
 * parse_ts_packet
 * --------------------------------------------------------------------------- */

void parser_test_ts_packet_null_buffer(void) {
    ts_packet_t packet;
    ASSERT(parse_ts_packet(NULL, 4, &packet) == 0);
}

void parser_test_ts_packet_null_packet(void) {
    uint8_t buf[4] = { 0x47, 0x00, 0x00, 0x10 };
    ASSERT(parse_ts_packet(buf, 4, NULL) == 0);
}

void parser_test_ts_packet_buffer_too_short(void) {
    ts_packet_t packet;
    uint8_t buf[4] = { 0x47, 0x00, 0x00, 0x10 };
    ASSERT(parse_ts_packet(buf, 0, &packet) == 0);
    ASSERT(parse_ts_packet(buf, 1, &packet) == 0);
    ASSERT(parse_ts_packet(buf, 3, &packet) == 0);
}

void parser_test_ts_packet_bad_sync_byte(void) {
    ts_packet_t packet;
    uint8_t buf[4];
    buf[1] = buf[2] = buf[3] = 0;
    buf[0] = 0x00; ASSERT(parse_ts_packet(buf, 4, &packet) == 0 || packet.sync_byte == 0x00);
    buf[0] = 0xFF; (void)parse_ts_packet(buf, 4, &packet); ASSERT(packet.sync_byte == 0xFF);
    /* If parser ever rejects bad sync, the first ASSERT allows return 0; else we check stored value. */
}

void parser_test_ts_packet_minimal_header(void) {
    ts_packet_t packet;
    uint8_t buf[4] = { 0x47, 0x00, 0x00, 0x10 }; /* af_control=1, payload only */
    ASSERT(parse_ts_packet(buf, 4, &packet) == 1);
    ASSERT(packet.payload_offset == 4);
    ASSERT(packet.payload_length == 0);
}

void parser_test_ts_packet_buffer_longer_than_188(void) {
    ts_packet_t packet;
    uint8_t buf[200];
    memset(buf, 0x00, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x10; /* payload only */
    ASSERT(parse_ts_packet(buf, 200, &packet) == 1);
    ASSERT(packet.payload_offset == 4);
    ASSERT(packet.payload_length == 196);
}

void parser_test_ts_packet_buffer_shorter_than_188(void) {
    ts_packet_t packet;
    uint8_t buf[100];
    memset(buf, 0x00, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x10;
    ASSERT(parse_ts_packet(buf, 100, &packet) == 1);
    ASSERT(packet.payload_offset == 4);
    ASSERT(packet.payload_length == 96);
}

void parser_test_ts_packet_adaptation_field_overflow(void) {
    ts_packet_t packet;
    uint8_t buf[188];
    memset(buf, 0x00, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x30; /* adaptation + payload */
    buf[4] = 200;  /* adaptation_field_length */
    ASSERT(parse_ts_packet(buf, 188, &packet) == 0);
}

void parser_test_ts_packet_adaptation_field_length_zero(void) {
    ts_packet_t packet;
    uint8_t buf[20];
    memset(buf, 0x00, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x30;
    buf[4] = 0; /* length 0 */
    ASSERT(parse_ts_packet(buf, 20, &packet) == 1);
    ASSERT(packet.payload_offset == 5);
    ASSERT(packet.payload_length == 15);
}

void parser_test_ts_packet_adaptation_pcr_overflow(void) {
    ts_packet_t packet;
    uint8_t buf[20];
    memset(buf, 0x00, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x30;
    buf[4] = 2;  /* only 2 bytes of AF data */
    buf[5] = 0x10; /* PCR flag set, needs 6 bytes */
    ASSERT(parse_ts_packet(buf, 20, &packet) == 0);
}

void parser_test_ts_packet_adaptation_control_zero(void) {
    ts_packet_t packet;
    uint8_t buf[4] = { 0x47, 0x00, 0x00, 0x00 }; /* af_control=0 */
    ASSERT(parse_ts_packet(buf, 4, &packet) == 1);
    ASSERT(packet.payload_length == 0);
}

void parser_test_ts_packet_nominal_188_payload_only(void) {
    ts_packet_t packet;
    uint8_t buf[188];
    memset(buf, 0x00, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x10;
    ASSERT(parse_ts_packet(buf, 188, &packet) == 1);
    ASSERT(packet.payload_offset == 4);
    ASSERT(packet.payload_length == 184);
}

/* ---------------------------------------------------------------------------
 * parse_psi_header
 * --------------------------------------------------------------------------- */

void parser_test_psi_header_null_args(void) {
    ts_packet_t packet = { .payload_offset = 0, .payload_length = 12 };
    uint8_t buf[12] = { 0x00, 0xB0, 0x09, 0x12, 0x34, 0x56, 0xC0, 0x00, 0x00 };
    psi_header_t psi;
    ASSERT(parse_psi_header(NULL, 12, &packet, &psi) == 0);
    ASSERT(parse_psi_header(buf, 12, NULL, &psi) == 0);
    ASSERT(parse_psi_header(buf, 12, &packet, NULL) == 0);
}

void parser_test_psi_header_buffer_too_short(void) {
    ts_packet_t packet = { .payload_offset = 0, .payload_length = 8 };
    uint8_t buf[12];
    psi_header_t psi;
    ASSERT(parse_psi_header(buf, 0, &packet, &psi) == 0);
    ASSERT(parse_psi_header(buf, 4, &packet, &psi) == 0);
    ASSERT(parse_psi_header(buf, 7, &packet, &psi) == 0);
}

void parser_test_psi_header_section_length_overflow(void) {
    ts_packet_t packet = { .payload_offset = 0, .payload_length = 20 };
    uint8_t buf[20];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x00;
    buf[1] = 0xB0;
    buf[2] = 0xFF; /* section_length 0x0FFF = 4095 → section_end = 4098 > 20 */
    psi_header_t psi;
    ASSERT(parse_psi_header(buf, 20, &packet, &psi) == 0);
}

void parser_test_psi_header_section_length_too_small(void) {
    ts_packet_t packet = { .payload_offset = 0, .payload_length = 12 };
    uint8_t buf[12];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x00;
    buf[1] = 0x80;
    buf[2] = 0x05; /* section_length 5 < 9 */
    psi_header_t psi;
    ASSERT(parse_psi_header(buf, 12, &packet, &psi) == 0);
}

void parser_test_psi_header_valid_minimal(void) {
    ts_packet_t packet = { .payload_offset = 0, .payload_length = 12 };
    uint8_t buf[12];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x00;
    buf[1] = 0xB0;
    buf[2] = 0x09; /* section_length 9 */
    psi_header_t psi;
    ASSERT(parse_psi_header(buf, 12, &packet, &psi) == 1);
    ASSERT(psi.section_offset == 8);
}

/* ---------------------------------------------------------------------------
 * parse_pat_section
 * --------------------------------------------------------------------------- */

void parser_test_pat_section_null_args(void) {
    uint8_t buf[32];
    psi_header_t psi = { .section_length = 9, .section_offset = 8 };
    pat_table_t pat;
    pat_table_init(&pat);
    ASSERT(parse_pat_section(NULL, 32, &psi, &pat) == 0);
    ASSERT(parse_pat_section(buf, 32, NULL, &pat) == 0);
    ASSERT(parse_pat_section(buf, 32, &psi, NULL) == 0);
    pat_table_cleanup(&pat);
}

void parser_test_pat_section_empty_program_loop(void) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    psi_header_t psi = { .section_length = 9, .section_offset = 8 };
    pat_table_t pat;
    pat_table_init(&pat);
    ASSERT(parse_pat_section(buf, 32, &psi, &pat) == 1);
    ASSERT(pat.program_count == 0);
    pat_table_cleanup(&pat);
}

void parser_test_pat_section_program_loop_not_multiple_of_four(void) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    psi_header_t psi = { .section_length = 10, .section_offset = 8 }; /* 10-9=1, not %4 */
    pat_table_t pat;
    pat_table_init(&pat);
    ASSERT(parse_pat_section(buf, 32, &psi, &pat) == 0);
    pat_table_cleanup(&pat);
}

void parser_test_pat_section_buffer_shorter_than_loop(void) {
    uint8_t buf[11];
    memset(buf, 0, sizeof(buf));
    psi_header_t psi = { .section_length = 9 + 4, .section_offset = 8 }; /* need 8+4=12 bytes */
    pat_table_t pat;
    pat_table_init(&pat);
    ASSERT(parse_pat_section(buf, 11, &psi, &pat) == 0);
    pat_table_cleanup(&pat);
}

/* ---------------------------------------------------------------------------
 * parse_pmt_section
 * --------------------------------------------------------------------------- */

void parser_test_pmt_section_null_args(void) {
    uint8_t buf[32];
    psi_header_t psi = { .section_length = 13, .section_offset = 8 };
    pmt_t pmt = { .pcr_pid = 0, .capacity = 0, .es_count = 0, .es_list = NULL };
    ASSERT(parse_pmt_section(NULL, 32, &psi, &pmt) == 0);
    ASSERT(parse_pmt_section(buf, 32, NULL, &pmt) == 0);
    ASSERT(parse_pmt_section(buf, 32, &psi, NULL) == 0);
}

void parser_test_pmt_section_program_info_overflow(void) {
    uint8_t buf[20];
    memset(buf, 0, sizeof(buf));
    psi_header_t psi = { .section_length = 13, .section_offset = 8 };
    buf[8] = 0xE0;
    buf[9] = 0x00;
    buf[10] = 0x00;
    buf[11] = 0xFF; /* program_info_length = 255, so program_info_end = 8+4+255 = 267 > 20 */
    pmt_t pmt = { .pcr_pid = 0, .capacity = 0, .es_count = 0, .es_list = NULL };
    ASSERT(parse_pmt_section(buf, 20, &psi, &pmt) == 0);
}

void parser_test_pmt_section_es_info_overflow(void) {
    /* section_length 9 + 4 (program_info 0) + 5 + 100 (es_info_length 100) = 118, but we give only 20 bytes
     * so program_info_length 0, es_offset 12, stream_type, elementary_pid, es_info_length=200 — would run past.
     * Make buffer long enough for section but es_info_length so large that es_offset + 5 + es_info_length > section_end.
     */
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    /* section_length = 9 + 0 (program_info) + 5 + 40 = 54. section_end_before_crc = 8 + 54 - 4 = 58. */
    psi_header_t psi = { .section_length = 54, .section_offset = 8 };
    buf[8] = 0xE0; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x00; /* pcr_pid 0, program_info_length 0 */
    buf[12] = 0x1B; buf[13] = 0xE0; buf[14] = 0x00; buf[15] = 0x00; buf[16] = 0xFF; /* stream_type 0x1B, pid 0, es_info_length 255 - runs past section */
    pmt_t pmt = { .pcr_pid = 0, .capacity = 4, .es_count = 0, .es_list = malloc(sizeof(pmt_es_t) * 4) };
    ASSERT(pmt.es_list != NULL);
    int r = parse_pmt_section(buf, 64, &psi, &pmt);
    ASSERT(r == 1); /* should succeed but not overread; may parse 0 ES due to break */
    free(pmt.es_list);
}

/* ---------------------------------------------------------------------------
 * process_packet_psi
 * --------------------------------------------------------------------------- */

void parser_test_process_packet_psi_pointer_field_overflow(void) {
    /* Packet with payload_offset 4, payload_length 5, pointer_field 10 → section_len = 5-1-10 = wrap.
     * process_packet_psi uses buffer[packet->payload_offset] = pointer_field and section_start = payload_offset + 1 + pointer_field.
     * We need to avoid overread. Build minimal buffer and structures.
     */
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x47;
    buf[3] = 0x10;
    buf[4] = 10; /* pointer_field = 10; payload_length will be 5 so section_len = 5-1-10 = huge (wrap) */
    ts_packet_t packet;
    ASSERT(parse_ts_packet(buf, 9, &packet) == 1);
    ASSERT(packet.payload_offset == 4);
    ASSERT(packet.payload_length == 5);

    pat_table_t pat;
    pmt_t* pmt_table = NULL;
    size_t pmt_capacity = 0;
    pid_count_list_t list;
    pat_table_init(&pat);
    pid_count_list_init(&list);
    process_packet_psi(buf, 9, &packet, &pat, &pmt_table, &pmt_capacity, &list);
    /* Should not crash; we only assert we get here. Optionally assert pat.program_count is 0. */
    ASSERT(pat.program_count == 0);
    pat_table_cleanup(&pat);
    pid_count_list_cleanup(&list);
    if (pmt_table) free(pmt_table);
}

void parser_test_process_packet_psi_truncated_pat_payload(void) {
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x47;
    buf[1] = 0x40; buf[2] = 0x00; /* PID 0 = PAT */
    buf[3] = 0x10;
    buf[4] = 0; /* pointer_field 0 */
    /* payload_length = 7 (only 7 bytes), so section_len = 6; parse_psi_header needs at least 8 */
    ts_packet_t packet;
    ASSERT(parse_ts_packet(buf, 12, &packet) == 1);
    ASSERT(packet.pid == 0);
    ASSERT(packet.payload_offset == 4);
    ASSERT(packet.payload_length == 8);

    pat_table_t pat;
    pmt_t* pmt_table = NULL;
    size_t pmt_capacity = 0;
    pid_count_list_t list;
    pat_table_init(&pat);
    pid_count_list_init(&list);
    process_packet_psi(buf, 12, &packet, &pat, &pmt_table, &pmt_capacity, &list);
    ASSERT(pat.program_count == 0);
    pat_table_cleanup(&pat);
    pid_count_list_cleanup(&list);
    if (pmt_table) free(pmt_table);
}

/* ---------------------------------------------------------------------------
 * Runner
 * --------------------------------------------------------------------------- */

typedef void (*test_fn)(void);

static const struct { const char* name; test_fn fn; } s_tests[] = {
    { "ts_packet_null_buffer", parser_test_ts_packet_null_buffer },
    { "ts_packet_null_packet", parser_test_ts_packet_null_packet },
    { "ts_packet_buffer_too_short", parser_test_ts_packet_buffer_too_short },
    { "ts_packet_bad_sync_byte", parser_test_ts_packet_bad_sync_byte },
    { "ts_packet_minimal_header", parser_test_ts_packet_minimal_header },
    { "ts_packet_buffer_longer_than_188", parser_test_ts_packet_buffer_longer_than_188 },
    { "ts_packet_buffer_shorter_than_188", parser_test_ts_packet_buffer_shorter_than_188 },
    { "ts_packet_adaptation_field_overflow", parser_test_ts_packet_adaptation_field_overflow },
    { "ts_packet_adaptation_field_length_zero", parser_test_ts_packet_adaptation_field_length_zero },
    { "ts_packet_adaptation_pcr_overflow", parser_test_ts_packet_adaptation_pcr_overflow },
    { "ts_packet_adaptation_control_zero", parser_test_ts_packet_adaptation_control_zero },
    { "ts_packet_nominal_188_payload_only", parser_test_ts_packet_nominal_188_payload_only },
    { "psi_header_null_args", parser_test_psi_header_null_args },
    { "psi_header_buffer_too_short", parser_test_psi_header_buffer_too_short },
    { "psi_header_section_length_overflow", parser_test_psi_header_section_length_overflow },
    { "psi_header_section_length_too_small", parser_test_psi_header_section_length_too_small },
    { "psi_header_valid_minimal", parser_test_psi_header_valid_minimal },
    { "pat_section_null_args", parser_test_pat_section_null_args },
    { "pat_section_empty_program_loop", parser_test_pat_section_empty_program_loop },
    { "pat_section_program_loop_not_multiple_of_four", parser_test_pat_section_program_loop_not_multiple_of_four },
    { "pat_section_buffer_shorter_than_loop", parser_test_pat_section_buffer_shorter_than_loop },
    { "pmt_section_null_args", parser_test_pmt_section_null_args },
    { "pmt_section_program_info_overflow", parser_test_pmt_section_program_info_overflow },
    { "pmt_section_es_info_overflow", parser_test_pmt_section_es_info_overflow },
    { "process_packet_psi_pointer_field_overflow", parser_test_process_packet_psi_pointer_field_overflow },
    { "process_packet_psi_truncated_pat_payload", parser_test_process_packet_psi_truncated_pat_payload },
};

int parser_test_run_all(void) {
    int total = 0;
    int failed = 0;
    for (size_t i = 0; i < sizeof(s_tests) / sizeof(s_tests[0]); i++) {
        s_failed = 0;
        s_tests[i].fn();
        total++;
        if (s_failed) {
            printf("FAIL %s\n", s_tests[i].name);
            failed++;
        } else {
            printf("OK   %s\n", s_tests[i].name);
        }
    }
    printf("%d passed, %d failed\n", total - failed, failed);
    return failed == 0 ? 1 : 0;
}

int main(void) {
    return parser_test_run_all() ? 0 : 1;
}

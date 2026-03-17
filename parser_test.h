#ifndef PARSER_TEST_H
#define PARSER_TEST_H

#include <stddef.h>

/*
 * Parser test API: declare and run must-have tests for parser.c.
 * Implement these in parser_test.c and link with parser.o, packet.o, utils.o.
 *
 * Usage:
 *   int main(void) {
 *     return parser_test_run_all() ? 0 : 1;
 *   }
 */

/* Return 1 if all tests passed, 0 if any failed. */
int parser_test_run_all(void);

/* ---------------------------------------------------------------------------
 * parse_ts_packet — must-have tests
 * --------------------------------------------------------------------------- */

/* Null / invalid inputs: parse_ts_packet returns 0 and does not crash. */
void parser_test_ts_packet_null_buffer(void);
void parser_test_ts_packet_null_packet(void);

/* Buffer too short: less than 4 bytes → return 0. */
void parser_test_ts_packet_buffer_too_short(void);

/* Broken sync byte: buffer[0] != 0x47. Parser should either return 0 or
 * document that caller must check packet->sync_byte == 0x47; test the
 * chosen behaviour (reject invalid sync or assert stored value). */
void parser_test_ts_packet_bad_sync_byte(void);

/* Valid sync byte 0x47, minimal 4-byte header, no adaptation, no payload
 * (af_control=1 but buffer_len==4 → payload_length 0). Expect return 1,
 * payload_offset 4, payload_length 0. */
void parser_test_ts_packet_minimal_header(void);

/* Payload size vs buffer_len: buffer longer than 188 bytes. Parser should
 * set payload_length = buffer_len - payload_offset (trust buffer_len, do
 * not assume 188). */
void parser_test_ts_packet_buffer_longer_than_188(void);

/* Payload size vs buffer_len: buffer shorter than 188 (e.g. 100 bytes).
 * With af_control=1, expect return 1, payload_offset 4, payload_length 96. */
void parser_test_ts_packet_buffer_shorter_than_188(void);

/* Adaptation field length larger than available buffer: e.g. 188-byte buffer,
 * af_control=3, adaptation_field_length=200. Parser should return 0
 * (4 + 1 + 200 > 188). */
void parser_test_ts_packet_adaptation_field_overflow(void);

/* Adaptation field present but length 0: af_control=3, buffer[4]=0.
 * Expect return 1, no optional AF data, payload starts at byte 5. */
void parser_test_ts_packet_adaptation_field_length_zero(void);

/* Adaptation field with PCR flag but not enough bytes (e.g. af_length=2,
 * pcr_flag=1 needs 6 bytes). Parser should return 0. */
void parser_test_ts_packet_adaptation_pcr_overflow(void);

/* Adaptation field control = 0 (reserved). Parser should still return 1,
 * no adaptation parsed, no payload (payload_length 0). */
void parser_test_ts_packet_adaptation_control_zero(void);

/* Exact 188-byte packet, payload only (af_control=1): return 1,
 * payload_offset 4, payload_length 184. */
void parser_test_ts_packet_nominal_188_payload_only(void);

/* ---------------------------------------------------------------------------
 * parse_psi_header — must-have tests
 * --------------------------------------------------------------------------- */

/* Null inputs → return 0. */
void parser_test_psi_header_null_args(void);

/* Buffer shorter than 8 bytes (fixed header) → return 0. */
void parser_test_psi_header_buffer_too_short(void);

/* section_length such that section_end (3 + section_length) > buffer_len.
 * Parser should return 0. */
void parser_test_psi_header_section_length_overflow(void);

/* section_length < 9 (invalid per spec) → return 0. */
void parser_test_psi_header_section_length_too_small(void);

/* Valid minimal section: buffer_len >= 12, section_length 9 (no program/ES
 * data beyond fixed header). Expect return 1, section_offset 8. */
void parser_test_psi_header_valid_minimal(void);

/* ---------------------------------------------------------------------------
 * parse_pat_section — must-have tests
 * --------------------------------------------------------------------------- */

/* Null inputs → return 0. */
void parser_test_pat_section_null_args(void);

/* section_length 9 → program_loop_bytes 0, no programs. Expect return 1,
 * program_count 0. */
void parser_test_pat_section_empty_program_loop(void);

/* program_loop_bytes not multiple of 4 (e.g. section_length 10) → return 0. */
void parser_test_pat_section_program_loop_not_multiple_of_four(void);

/* Buffer shorter than section_start + program_loop_bytes → return 0. */
void parser_test_pat_section_buffer_shorter_than_loop(void);

/* ---------------------------------------------------------------------------
 * parse_pmt_section — must-have tests
 * --------------------------------------------------------------------------- */

/* Null inputs → return 0. */
void parser_test_pmt_section_null_args(void);

/* program_info_length so large that program_info_end > buffer_len → return 0. */
void parser_test_pmt_section_program_info_overflow(void);

/* ES descriptor es_info_length runs past section (into CRC). Parser should
 * stop at section boundary (break), not overread. */
void parser_test_pmt_section_es_info_overflow(void);

/* ---------------------------------------------------------------------------
 * process_packet_psi — must-have tests
 * --------------------------------------------------------------------------- */

/* pointer_field larger than (payload_length - 1): causes section_len
 * underflow if using unsigned. Either parser/psi logic should reject or
 * clamp; test that we do not overread or crash. */
void parser_test_process_packet_psi_pointer_field_overflow(void);

/* PAT packet with truncated payload (payload_length < 8). Should not
 * overread; parse_psi_header or PAT path should fail safely. */
void parser_test_process_packet_psi_truncated_pat_payload(void);

#endif /* PARSER_TEST_H */

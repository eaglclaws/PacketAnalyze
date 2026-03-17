#ifndef PARSER_H
#define PARSER_H
#include <stddef.h>
#include <stdint.h>

#include "packet.h"
#include "utils.h"

int parse_ts_packet(const uint8_t* buffer, size_t buffer_len, ts_packet_t* packet);

int parse_psi_header(const uint8_t* buffer, size_t buffer_len, const ts_packet_t* packet, psi_header_t* psi_header);

int parse_pat_section(const uint8_t* buffer, size_t buffer_len, const psi_header_t* psi_header, pat_table_t* pat);

int parse_pmt_section(const uint8_t* buffer, size_t buffer_len, const psi_header_t* psi_header, pmt_t* pmt);

/* Update pid list and parse PAT/PMT when applicable; grow pmt_table to match pat. */
void process_packet_psi(const uint8_t* buffer, size_t buffer_len, const ts_packet_t* packet,
                        pat_table_t* pat, pmt_t** pmt_table, size_t* pmt_table_capacity, pid_count_list_t* list);

/* Parse PES packet header (first 9 bytes of optional header). Returns 1 on success, 0 if buffer too short. */
int parse_pes_header(const uint8_t* buffer, size_t buffer_len, pes_packet_t* out);

/* Fill pts/dts in pes_packet_t from PES optional header. Call after parse_pes_header. Returns 1 on success. */
int populate_pes_pts_dts(const uint8_t* buffer, size_t buffer_len, pes_packet_t* out);

#endif // PARSER_H

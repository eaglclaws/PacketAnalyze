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
#endif // PARSER_H

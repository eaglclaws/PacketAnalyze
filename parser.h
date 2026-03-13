#ifndef PARSER_H
#define PARSER_H
#include <stddef.h>
#include <stdint.h>

#include "packet.h"

int parse_ts_packet(const uint8_t* buffer, size_t buffer_len, ts_packet_t* packet);

int parse_psi_header(const uint8_t* buffer, size_t buffer_len, const ts_packet_t* packet, psi_header_t* psi_header);

int parse_pat_section(const uint8_t* buffer, size_t buffer_len, const psi_header_t* psi_header, pat_table_t* pat);
#endif // PARSER_H

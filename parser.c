#include "parser.h"
#include "packet.h"
#include <stdlib.h>
static void reset_adaptation_fields(ts_packet_t* packet) {
    packet->adaptation_field_length = 0;

    packet->discontinuity_indicator = 0;
    packet->random_access_indicator = 0;
    packet->es_priority_indicator = 0;
    packet->pcr_flag = 0;
    packet->opcr_flag = 0;
    packet->splicing_point_flag = 0;
    packet->transport_private_data_flag = 0;
    packet->adaptation_field_extension_flag = 0;

    packet->pcr_valid = 0;
    packet->pcr_base = 0;
    packet->pcr_ext = 0;

    packet->opcr_valid = 0;
    packet->opcr_base = 0;
    packet->opcr_ext = 0;

    packet->splice_countdown_valid = 0;
    packet->splice_countdown = 0;

    packet->transport_private_data_valid = 0;
    packet->transport_private_data_length = 0;
    packet->transport_private_data_offset = 0;

    packet->adaptation_extension_valid = 0;
    packet->adaptation_extension_length = 0;
    packet->adaptation_extension_offset = 0;

    packet->payload_offset = 0;
    packet->payload_length = 0;
}

static uint8_t parse_pcr_6bytes(const uint8_t* p, uint64_t* base_out, uint16_t* ext_out) {
    // PCR/OPCR: 33-bit base, 6 reserved, 9-bit extension.
    const uint64_t base =
        ((uint64_t)p[0] << 25) |
        ((uint64_t)p[1] << 17) |
        ((uint64_t)p[2] << 9) |
        ((uint64_t)p[3] << 1) |
        ((uint64_t)(p[4] & 0x80u) >> 7);
    const uint16_t ext = (uint16_t)(((uint16_t)(p[4] & 0x01u) << 8) | (uint16_t)p[5]);

    *base_out = base;
    *ext_out = ext;
    return 1;
}

int parse_ts_packet(const uint8_t* buffer, size_t buffer_len, ts_packet_t* packet) {
    if (buffer == NULL || packet == NULL) {
        return 0;
    }
    if (buffer_len < 4) {
        return 0;
    }

    reset_adaptation_fields(packet);

    packet->sync_byte = buffer[0];

    // Byte 1 (buffer[1]): 1 bit TEI, 1 bit PUSI, 1 bit TP, 5 bits PID(12:8)
    packet->tei = (buffer[1] & 0x80) >> 7;
    packet->pusi = (buffer[1] & 0x40) >> 6;
    packet->transport_priority = (buffer[1] & 0x20) >> 5;

    // PID: 13 bits, bits 4-0 of buffer[1] (PID 12:8), all 8 bits of buffer[2] (PID 7:0)
    packet->pid = (uint16_t)(((buffer[1] & 0x1Fu) << 8) | buffer[2]);

    // Byte 3 (buffer[3]): 2 bits TSC, 2 bits Adaptation field control, 4 bits continuity counter
    packet->tsc = (buffer[3] & 0xC0) >> 6;
    packet->adaptation_field_control = (buffer[3] & 0x30) >> 4;
    packet->continuity_counter = buffer[3] & 0x0F;

    // Adaptation field exists when adaptation_field_control is 2 or 3.
    // (1 => payload only; 2 => adaptation only; 3 => adaptation + payload)
    if ((packet->adaptation_field_control & 0x02u) != 0u) {
        if (buffer_len < 5) {
            return 0;
        }

        packet->adaptation_field_length = buffer[4];
        const size_t af_total_bytes = (size_t)packet->adaptation_field_length + 1u; // +1 for length byte itself
        if (buffer_len < (4u + af_total_bytes)) {
            return 0;
        }

        if (packet->adaptation_field_length > 0u) {
            const uint8_t flags = buffer[5];
            packet->discontinuity_indicator = (flags & 0x80u) >> 7;
            packet->random_access_indicator = (flags & 0x40u) >> 6;
            packet->es_priority_indicator = (flags & 0x20u) >> 5;
            packet->pcr_flag = (flags & 0x10u) >> 4;
            packet->opcr_flag = (flags & 0x08u) >> 3;
            packet->splicing_point_flag = (flags & 0x04u) >> 2;
            packet->transport_private_data_flag = (flags & 0x02u) >> 1;
            packet->adaptation_field_extension_flag = (flags & 0x01u);

            // Walk the adaptation field in spec order.
            size_t idx = 6; // first byte after flags
            const size_t af_end = 5u + (size_t)packet->adaptation_field_length; // last byte index inside AF data

            if (packet->pcr_flag != 0u) {
                if ((idx + 6u) > (af_end + 1u)) {
                    return 0;
                }
                packet->pcr_valid = parse_pcr_6bytes(&buffer[idx], &packet->pcr_base, &packet->pcr_ext);
                idx += 6u;
            }

            if (packet->opcr_flag != 0u) {
                if ((idx + 6u) > (af_end + 1u)) {
                    return 0;
                }
                packet->opcr_valid = parse_pcr_6bytes(&buffer[idx], &packet->opcr_base, &packet->opcr_ext);
                idx += 6u;
            }

            if (packet->splicing_point_flag != 0u) {
                if (idx > af_end) {
                    return 0;
                }
                packet->splice_countdown = buffer[idx];
                packet->splice_countdown_valid = 1;
                idx += 1u;
            }

            if (packet->transport_private_data_flag != 0u) {
                if (idx > af_end) {
                    return 0;
                }
                const uint8_t len = buffer[idx];
                idx += 1u;
                if ((idx + (size_t)len) > (af_end + 1u)) {
                    return 0;
                }
                packet->transport_private_data_valid = 1;
                packet->transport_private_data_length = len;
                packet->transport_private_data_offset = (uint16_t)idx;
                idx += (size_t)len;
            }

            if (packet->adaptation_field_extension_flag != 0u) {
                if (idx > af_end) {
                    return 0;
                }
                const uint8_t len = buffer[idx];
                idx += 1u;
                if ((idx + (size_t)len) > (af_end + 1u)) {
                    return 0;
                }
                packet->adaptation_extension_valid = 1;
                packet->adaptation_extension_length = len;
                packet->adaptation_extension_offset = (uint16_t)idx;
                idx += (size_t)len;
            }
        }
    }

    /* Payload is present when adaptation_field_control is 1 (payload only) or 3 (adaptation + payload). */
    if ((packet->adaptation_field_control & 0x01u) != 0u) {
        if ((packet->adaptation_field_control & 0x02u) != 0u) {
            packet->payload_offset = (uint16_t)(5u + (size_t)packet->adaptation_field_length);
        } else {
            packet->payload_offset = 4u;
        }
        if (buffer_len >= (size_t)packet->payload_offset) {
            packet->payload_length = (uint16_t)(buffer_len - (size_t)packet->payload_offset);
        }
    }

    return 1;
}

int parse_psi_header(const uint8_t* buffer, size_t buffer_len, const ts_packet_t* packet, psi_header_t* psi_header) {
    if (buffer == NULL || packet == NULL || psi_header == NULL) {
        return 0;
    }
    if (buffer_len < 4) {
        return 0;
    }
    if (packet->payload_offset >= buffer_len) {
        return 0;
    }
    if (packet->payload_offset + 1 > buffer_len) {
        return 0;
    }
    size_t table_start = packet->payload_offset + buffer[packet->payload_offset] + 1;
    if (table_start + 8u > buffer_len) {
        return 0;
    }
    psi_header->table_id = buffer[table_start];
    psi_header->section_syntax_indicator = (buffer[table_start + 1] & 0x80u) >> 7;
    psi_header->section_length = (uint16_t)(((buffer[table_start + 1] & 0x0Fu) << 8) | buffer[table_start + 2]);
    size_t section_end = table_start + 3u + (size_t)psi_header->section_length;
    if (section_end > buffer_len) {
        return 0;
    }
    if (psi_header->section_length < 9) {
        return 0;
    }
    psi_header->transport_stream_id = (uint16_t)((uint16_t)buffer[table_start + 3] << 8) | buffer[table_start + 4];
    psi_header->version_number = (buffer[table_start + 5] & 0x3E) >> 1;
    psi_header->current_next_indicator = buffer[table_start + 5] & 0x01;
    psi_header->section_number = buffer[table_start + 6];
    psi_header->last_section_number = buffer[table_start + 7];
    psi_header->section_offset = (uint16_t)(table_start + 8u);
    return 1;
}

int parse_pat_section(const uint8_t* buffer, size_t buffer_len, const psi_header_t* psi_header, pat_table_t* pat) {
    if (buffer == NULL || psi_header == NULL || pat == NULL) {
        return 0;
    }
    size_t section_start = psi_header->section_offset;
    if (section_start > buffer_len) {
        return 0;
    }
    int list_idx = 0;
    for (size_t idx = section_start; idx < section_start + psi_header->section_length - 4; idx+=4) {
        uint16_t program_number = (uint16_t)((buffer[idx] << 8) | buffer[idx + 1]);
        uint16_t pid = (uint16_t)(((buffer[idx + 2] & 0x1Fu) << 8) | buffer[idx + 3]);
        int skip = 0;
        for (size_t i = 0; i < pat->program_count; i++) {
            skip = pat->programs[i].program_number == program_number;
            if (skip) break;
        }
        if (skip) {
            continue;
        }
        pat->programs[list_idx].program_number = program_number;
        pat->programs[list_idx].pid = pid;
        pat->program_count++;
        if (pat->program_count == pat->capacity) {
            pat->capacity *= 2;
            pat->programs = realloc(pat->programs, sizeof(pat_program_t) * pat->capacity);
        }
        list_idx++;
    }
    pat->header = *psi_header;
    return 1;
}

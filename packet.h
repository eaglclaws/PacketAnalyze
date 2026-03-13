#ifndef PACKET_H
#define PACKET_H
#include <stdint.h>
#include <stddef.h>
typedef struct ts_packet_s {
    uint8_t sync_byte;
    uint8_t tei;
    uint8_t pusi;
    uint8_t transport_priority;
    uint16_t pid;
    uint8_t tsc;
    uint8_t adaptation_field_control;
    uint8_t continuity_counter;

    uint8_t adaptation_field_length;
    uint8_t discontinuity_indicator;
    uint8_t random_access_indicator;
    uint8_t es_priority_indicator;
    uint8_t pcr_flag;
    uint8_t opcr_flag;
    uint8_t splicing_point_flag;
    uint8_t transport_private_data_flag;
    uint8_t adaptation_field_extension_flag;

    uint8_t pcr_valid;
    uint64_t pcr_base;
    uint16_t pcr_ext;

    uint8_t opcr_valid;
    uint64_t opcr_base;
    uint16_t opcr_ext;

    uint8_t splice_countdown_valid;
    uint8_t splice_countdown;

    uint8_t transport_private_data_valid;
    uint8_t transport_private_data_length;
    uint16_t transport_private_data_offset;

    uint8_t adaptation_extension_valid;
    uint8_t adaptation_extension_length;
    uint16_t adaptation_extension_offset;

    uint16_t payload_offset;  /* index in packet buffer where payload starts */
    uint16_t payload_length; /* number of payload bytes (0 if no payload) */
} ts_packet_t;

typedef struct psi_header_s {
    uint8_t table_id;
    uint8_t section_syntax_indicator;
    uint16_t section_length;
    uint16_t transport_stream_id;
    uint8_t version_number;
    uint8_t current_next_indicator;
    uint8_t section_number;
    uint8_t last_section_number;
    uint16_t section_offset;
} psi_header_t;

typedef struct pat_program_s {
    uint16_t program_number;
    uint16_t pid;
} pat_program_t;

typedef struct pat_table_s {
    psi_header_t header;
    size_t capacity;
    size_t program_count;
    pat_program_t* programs;
} pat_table_t;

typedef struct pat_s {
    uint16_t* pid_list;
} pat_t;
#endif // PACKET_H

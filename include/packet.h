#ifndef PACKET_H
#define PACKET_H
#include <stdint.h>
#include <stddef.h>

/* ==== Well-known TS PIDs ==== */
#define TS_PID_PAT  0x0000u
#define TS_PID_NULL 0x1FFFu

/* ==== Parsed TS packet fields ==== */
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

/* ==== Parsed PSI section common header ==== */
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


/* ==== PAT program mapping ==== */
typedef struct pat_program_s {
    uint16_t program_number;
    uint16_t pid;
} pat_program_t;

/* ==== Parsed PAT table ==== */
typedef struct pat_table_s {
    psi_header_t header;
    size_t capacity;
    size_t program_count;
    pat_program_t* programs;
} pat_table_t;


/* Legacy wrapper kept for compatibility. */
typedef struct pat_s {
    uint16_t* pid_list;
} pat_t;

/* ==== PMT ES metadata ==== */
/* Descriptor-derived fields; empty/0 means not present. */
#define PMT_ES_LANGUAGE_LEN 4  /* ISO 639-2/B 3 chars + NUL */

typedef struct pmt_es_s {
    uint8_t stream_type;
    uint16_t elementary_pid;
    char language_code[PMT_ES_LANGUAGE_LEN];  /* e.g. "eng", from ISO_639_language_descriptor (0x0A) */
    uint8_t avc_profile_idc;   /* from AVC_video_descriptor (0x28), 0 if not present */
    uint8_t avc_level_idc;    /* from AVC_video_descriptor (0x28), 0 if not present */
} pmt_es_t;

/* ==== Parsed PMT table entry ==== */
typedef struct pmt_s {
    uint16_t pcr_pid;
    size_t capacity;
    size_t es_count;
    pmt_es_t* es_list;
} pmt_t;

/* ==== Parsed PES header + timing ==== */
typedef struct pes_packet_s {
    uint32_t packet_start_code_prefix;
    uint8_t stream_id;
    uint16_t packet_length;
    uint8_t scrambling_control;
    uint8_t priority_indicator;
    uint8_t data_alignment_indicator;
    uint8_t copyright_flag;
    uint8_t original_or_copy;
    uint8_t PTS_DTS_flags;
    uint8_t escr_flag;
    uint8_t es_rate_flag;
    uint8_t dsm_trick_mode_flag;
    uint8_t additional_copy_info_flag;
    uint8_t crc_flag;
    uint8_t extension_flag;
    uint8_t header_length;
    uint64_t pts;  /* valid when PTS_DTS_flags >= 2 */
    uint64_t dts;  /* valid when PTS_DTS_flags == 3 */
} pes_packet_t;

/* ==== Collected PES packets by PID ==== */
typedef struct pes_packet_list_s {
    uint16_t pid;
    pes_packet_t* packets;
    size_t count;
    size_t capacity;
} pes_packet_list_t;

/* Dynamic array of pes_packet_list_t (one list per PID). */
typedef struct pes_packet_list_table_s {
    pes_packet_list_t* lists;
    size_t count;
    size_t capacity;
} pes_packet_list_table_t;

/* One accumulating PES buffer per PID (for reassembling PES across TS packets). */
typedef struct pes_buffer_entry_s {
    uint16_t pid;
    uint8_t* buffer;
    size_t length;
    size_t capacity;
} pes_buffer_entry_t;

typedef struct pes_buffer_table_s {
    pes_buffer_entry_t* entries;
    size_t count;
    size_t capacity;
} pes_buffer_table_t;

#endif // PACKET_H

#ifndef UTILS_H
#define UTILS_H
#include "packet.h"
#include <stdint.h>
#include <stdio.h>
#define BOOL_STRING(x) ((x) ? "TRUE" : "FALSE")

/* ============================================================================
 * Stream and PID classification
 * ========================================================================== */
typedef enum stream_category_e {
    STREAM_OTHER,
    STREAM_VIDEO,
    STREAM_AUDIO,
} stream_category_t;

/* Table 2-34: returns VIDEO, AUDIO, or OTHER for a PMT stream_type (uint8_t). */
stream_category_t stream_category_from_type(uint8_t stream_type);

/* Human-readable codec name for a PMT stream_type; "Unknown" if not in table. */
const char* stream_type_to_codec_string(uint8_t stream_type);

typedef enum pid_type_e {
    PID_UNKNOWN,
    PID_PAT,
    PID_PMT,
    PID_SI,
    PID_VIDEO,
    PID_AUDIO,
    PID_NULL,
    PID_COUNT
} pid_type_t;

typedef struct pid_count_s {
    uint16_t pid;
    size_t count;
    pid_type_t type;
} pid_count_t;

typedef struct pid_count_list_s {
    pid_count_t* pids;
    size_t count;
    size_t capacity;
} pid_count_list_t;

#define VALIDATION_SAMPLE_LIMIT 12u

/* ============================================================================
 * Storage helpers
 * ========================================================================== */
/* Initialize/cleanup PAT program table. */
void pat_table_init(pat_table_t* table);
void pat_table_cleanup(pat_table_t* table);
/* Append one PAT program mapping to table. */
void pat_table_push(pat_table_t* table, pat_program_t program);

/* Ensure PMT table slot count matches PAT program count. */
void pmt_table_ensure_capacity(const pat_table_t* pat, pmt_t** pmt_table, size_t* capacity);

/* Convert internal PID type to display string. */
const char* pid_type_to_string(pid_type_t type);
/* PID list CRUD helpers. */
void pid_count_list_init(pid_count_list_t* list);
void pid_count_list_update(pid_count_list_t* list, uint16_t pid);
void pid_count_list_push(pid_count_list_t* list, uint16_t pid);
int pid_count_list_contains(pid_count_list_t* list, uint16_t pid);
int pid_count_list_find(pid_count_list_t* list, uint16_t pid);
void pid_count_list_cleanup(pid_count_list_t* list);
void pid_count_list_update_type(pid_count_list_t* list, uint16_t pid, pid_type_t type);

/* PES packet list helpers (single PID). */
void pes_packet_list_init(pes_packet_list_t* list);
void pes_packet_list_push(pes_packet_list_t* list, const pes_packet_t* p);
void pes_packet_list_cleanup(pes_packet_list_t* list);

/* PES packet list table helpers (multi PID). */
void pes_packet_list_table_init(pes_packet_list_table_t* table);
int pes_packet_list_table_find(const pes_packet_list_table_t* table, uint16_t pid);
pes_packet_list_t* pes_packet_list_table_get_or_create(pes_packet_list_table_t* table, uint16_t pid);
void pes_packet_list_table_push_packet(pes_packet_list_table_t* table, uint16_t pid, const pes_packet_t* p);
void pes_packet_list_table_cleanup(pes_packet_list_table_t* table);

/* PES byte-buffer table helpers for reassembly. */
void pes_buffer_table_init(pes_buffer_table_t* table);
pes_buffer_entry_t* pes_buffer_table_get_or_create(pes_buffer_table_t* table, uint16_t pid);
void pes_buffer_table_append(pes_buffer_entry_t* entry, const uint8_t* data, size_t len);
void pes_buffer_table_clear_length(pes_buffer_entry_t* entry);
void pes_buffer_table_cleanup(pes_buffer_table_t* table);

/* Cleanup combined parse state for PAT/PMT/PID tables. */
void ts_state_cleanup(pat_table_t* pat, pmt_t* pmt_table, size_t pmt_table_capacity, pid_count_list_t* list);

/* ============================================================================
 * Continuity and validation helpers
 * ========================================================================== */
/* Initialize continuity counter tracking state. */
void ts_cc_init(void);
/* Validate one TS packet continuity/sync. If summarize!=0, accumulate summary stats. */
int ts_cc_check(const ts_packet_t* packet, FILE* out, size_t packet_index, int summarize);
/* Reset and print accumulated validation summary. */
void validation_summary_init(void);
void validation_summary_print(FILE* out);
/* Total errors currently accumulated in validation summary state. */
size_t validation_summary_total_errors(void);
/* Sync-loss count currently accumulated in validation summary state. */
size_t validation_summary_sync_errors(void);

/* Update continuity tracking state after packet validation. */
void ts_cc_update(const ts_packet_t* packet);
/* Return non-zero for standard SI PID ranges used by DVB/MPEG-TS tables. */
int is_well_known_si_pid(uint16_t pid);

/* Report PIDs that appear in list but are not in PAT/PMT (or null). Sets *errors_found if any. */
void report_undefined_pids(const pat_table_t* pat, const pmt_t* pmt_table, size_t pmt_capacity,
                           const pid_count_list_t* list, int* errors_found);

/* ============================================================================
 * Printing and reports
 * ========================================================================== */
/* Print one parsed TS packet in box format. */
void print_packet_header(ts_packet_t* packet, size_t packet_index);
/* Print raw PSI header fields (debug-oriented output). */
void print_psi_header(psi_header_t* header);

/* Print packet-count and ratio table by PID. */
void print_pid_ratio_header(const pid_count_list_t* list, long total_packets);

/* Print PAT, PID list, and PMT ES list. */
void print_ts_report(const pat_table_t* pat, const pmt_t* pmt_table, const pid_count_list_t* list);

/* Print binary buffer as hex + ASCII dump. */
void print_hexdump(const uint8_t* buffer, size_t length);

/* Convert PCR base/ext fields to 27MHz tick domain. */
uint64_t pcr_to_time(uint64_t pcr_base, uint64_t pcr_ext);

/* Print PES packet header in box format. */
void print_pes_header(const pes_packet_t* p);

/* Print PTS/DTS from PES packet in box format (only PTS when flags >= 2, DTS when flags == 3). */
void print_pts_dts(const pes_packet_t* p);

/* Single-line summary: #index, stream_id, PTS, DTS (if present). */
void print_pes_one_line(const pes_packet_t* p, size_t index);

/* PES report: streams summary from PMT, then per-PID PES packet list (first/last 10). */
void print_pes_streams_summary(const pmt_t* pmt_table, size_t pmt_table_capacity);
void print_pes_packet_list_report(const pes_packet_list_table_t* table);

#endif // UTILS_H

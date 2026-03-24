/**
 * @file utils.h
 * @brief Public utility API for TS classification, validation, storage, and reporting.
 */

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

/**
 * @brief Classify PMT stream_type into broad media category.
 * @param[in] stream_type PMT stream_type value.
 * @return STREAM_VIDEO, STREAM_AUDIO, or STREAM_OTHER.
 */
stream_category_t stream_category_from_type(uint8_t stream_type);

/**
 * @brief Convert PMT stream_type to human-readable codec label.
 * @param[in] stream_type PMT stream_type value.
 * @return Static string label (e.g. "AVC/H.264", "AAC", or "Unknown").
 */
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

/** @name Storage helpers */
/**@{*/
/** @brief Initialize PAT table storage. */
void pat_table_init(pat_table_t* table);
/** @brief Release PAT table storage. */
void pat_table_cleanup(pat_table_t* table);
/** @brief Append one PAT program mapping to table. */
void pat_table_push(pat_table_t* table, pat_program_t program);

/** @brief Ensure PMT table slot count matches PAT program count. */
void pmt_table_ensure_capacity(const pat_table_t* pat, pmt_t** pmt_table, size_t* capacity);

/** @brief Convert internal PID type to display string. */
const char* pid_type_to_string(pid_type_t type);
/** @brief Initialize PID count list. */
void pid_count_list_init(pid_count_list_t* list);
/** @brief Increment packet count for PID, creating entry if needed. */
void pid_count_list_update(pid_count_list_t* list, uint16_t pid);
/** @brief Push PID entry if not present. */
void pid_count_list_push(pid_count_list_t* list, uint16_t pid);
/** @brief Check whether PID exists in list. */
int pid_count_list_contains(pid_count_list_t* list, uint16_t pid);
/** @brief Find PID index in list, or -1 if not found. */
int pid_count_list_find(pid_count_list_t* list, uint16_t pid);
/** @brief Release PID count list storage. */
void pid_count_list_cleanup(pid_count_list_t* list);
/** @brief Update semantic PID type for a PID entry. */
void pid_count_list_update_type(pid_count_list_t* list, uint16_t pid, pid_type_t type);

/** @brief Initialize PES packet list for one PID. */
void pes_packet_list_init(pes_packet_list_t* list);
/** @brief Append PES packet to list. */
void pes_packet_list_push(pes_packet_list_t* list, const pes_packet_t* p);
/** @brief Release PES packet list storage. */
void pes_packet_list_cleanup(pes_packet_list_t* list);

/** @brief Initialize multi-PID PES packet table. */
void pes_packet_list_table_init(pes_packet_list_table_t* table);
/** @brief Find PID index in PES packet table, or -1 if not found. */
int pes_packet_list_table_find(const pes_packet_list_table_t* table, uint16_t pid);
/** @brief Get existing PID list or create a new one in PES packet table. */
pes_packet_list_t* pes_packet_list_table_get_or_create(pes_packet_list_table_t* table, uint16_t pid);
/** @brief Append PES packet under given PID in table. */
void pes_packet_list_table_push_packet(pes_packet_list_table_t* table, uint16_t pid, const pes_packet_t* p);
/** @brief Release PES packet table storage. */
void pes_packet_list_table_cleanup(pes_packet_list_table_t* table);

/** @brief Initialize PES reassembly byte-buffer table. */
void pes_buffer_table_init(pes_buffer_table_t* table);
/** @brief Get existing buffer entry by PID or create one. */
pes_buffer_entry_t* pes_buffer_table_get_or_create(pes_buffer_table_t* table, uint16_t pid);
/** @brief Append bytes to a PES buffer entry. */
void pes_buffer_table_append(pes_buffer_entry_t* entry, const uint8_t* data, size_t len);
/** @brief Clear buffered PES length while keeping allocation. */
void pes_buffer_table_clear_length(pes_buffer_entry_t* entry);
/** @brief Release PES reassembly buffer table storage. */
void pes_buffer_table_cleanup(pes_buffer_table_t* table);

/** @brief Cleanup combined PAT/PMT/PID parse state. */
void ts_state_cleanup(pat_table_t* pat, pmt_t* pmt_table, size_t pmt_table_capacity, pid_count_list_t* list);
/**@}*/

/** @name Continuity and validation helpers */
/**@{*/
/** @brief Initialize continuity-counter tracking state. */
void ts_cc_init(void);
/**
 * @brief Validate one packet for sync-byte and continuity issues.
 * @param[in] packet Parsed TS packet.
 * @param[in] out Optional stream for immediate messages, or NULL.
 * @param[in] packet_index Zero-based packet index.
 * @param[in] summarize Non-zero to accumulate summary counters.
 * @return Non-zero if issue is detected for this packet.
 */
int ts_cc_check(const ts_packet_t* packet, FILE* out, size_t packet_index, int summarize);
/** @brief Reset accumulated validation summary counters. */
void validation_summary_init(void);
/** @brief Print accumulated validation summary. */
void validation_summary_print(FILE* out);
/** @brief Get total accumulated sync+CC validation errors. */
size_t validation_summary_total_errors(void);
/** @brief Get accumulated sync-loss count. */
size_t validation_summary_sync_errors(void);

/** @brief Update continuity tracking state after packet handling. */
void ts_cc_update(const ts_packet_t* packet);
/** @brief Return non-zero for standard DVB/MPEG-TS SI PIDs. */
int is_well_known_si_pid(uint16_t pid);

/**
 * @brief Print undefined PID entries not declared by PAT/PMT.
 * @param[in] pat Parsed PAT table.
 * @param[in] pmt_table Parsed PMT table.
 * @param[in] pmt_capacity PMT table slot count.
 * @param[in] list Observed PID list.
 * @param[in,out] errors_found Optional issue flag to set when undefined PID appears.
 */
void report_undefined_pids(const pat_table_t* pat, const pmt_t* pmt_table, size_t pmt_capacity,
                           const pid_count_list_t* list, int* errors_found);
/**@}*/

/** @name Printing and reports */
/**@{*/
/** @brief Print one parsed TS packet in box format. */
void print_packet_header(ts_packet_t* packet, size_t packet_index);
/** @brief Print raw PSI header fields (debug-oriented output). */
void print_psi_header(psi_header_t* header);

/** @brief Print packet-count and ratio table by PID. */
void print_pid_ratio_header(const pid_count_list_t* list, long total_packets);

/** @brief Print PAT, PID list, and PMT ES list. */
void print_ts_report(const pat_table_t* pat, const pmt_t* pmt_table, const pid_count_list_t* list);

/** @brief Print binary buffer as hex + ASCII dump. */
void print_hexdump(const uint8_t* buffer, size_t length);

/** @brief Convert PCR base/ext fields to 27 MHz tick domain. */
uint64_t pcr_to_time(uint64_t pcr_base, uint64_t pcr_ext);

/** @brief Print PES packet header in box format. */
void print_pes_header(const pes_packet_t* p);

/** @brief Print PTS/DTS from PES packet in box format. */
void print_pts_dts(const pes_packet_t* p);

/** @brief Print single-line PES summary (index, stream_id, PTS/DTS). */
void print_pes_one_line(const pes_packet_t* p, size_t index);

/** @brief Print PES stream summary from PMT. */
void print_pes_streams_summary(const pmt_t* pmt_table, size_t pmt_table_capacity);
/** @brief Print per-PID PES packet list report. */
void print_pes_packet_list_report(const pes_packet_list_table_t* table);
/**@}*/

#endif // UTILS_H

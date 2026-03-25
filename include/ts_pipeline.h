#ifndef TS_PIPELINE_H
#define TS_PIPELINE_H

#include <stdio.h>
#include "packet.h"
#include "utils.h"

/**
 * @file ts_pipeline.h
 * @brief Public analysis and CLI pipeline API for MPEG-TS processing.
 *
 * This module exposes:
 * - analysis-first functions that return structured results
 * - CLI runner wrappers used by main entry points
 */

/* ============================================================================
 * Result models (analysis-first)
 * ========================================================================== */
typedef struct ts_psi_result_s {
    pat_table_t pat;
    pmt_t* pmt_table;
    size_t pmt_table_capacity;
    pid_count_list_t pid_list;
} ts_psi_result_t;

typedef struct ts_packets_result_s {
    pid_count_list_t pid_list;
    ts_packet_t* packets;
    size_t packet_count;
    size_t packet_capacity;
} ts_packets_result_t;

typedef struct ts_pes_result_s {
    ts_psi_result_t psi;
    pes_packet_list_table_t pes_packet_table;
} ts_pes_result_t;

typedef struct ts_validate_result_s {
    ts_psi_result_t psi;
    int errors_found;
    size_t undefined_pid_count;
} ts_validate_result_t;

typedef struct ts_jitter_preview_row_s {
    size_t packet_index;
    double actual_ms;
    double ideal_ms;
    double offset_ms;
    int actual_valid;
    int ideal_valid;
    int offset_valid;
} ts_jitter_preview_row_t;

typedef struct ts_jitter_result_s {
    ts_psi_result_t psi;
    uint16_t pcr_pid;
    uint64_t first_pcr;
    uint64_t last_pcr;
    size_t first_byte_offset;
    size_t last_byte_offset;
    double bitrate;
    size_t pcr_sample_total;
    ts_jitter_preview_row_t* preview_rows;
    size_t preview_row_count;
} ts_jitter_result_t;

/** @name Analysis-first API */
/**@{*/
/**
 * @brief Analyze PSI state (PAT/PMT/PID map) without printing.
 *
 * Rewinds @p file and parses aligned 188-byte TS packets (no resync).
 *
 * @param[in]  file Input file handle.
 * @param[out] out  PSI result container.
 * @retval 0 Success.
 * @retval 1 Failure.
 * @pre @p file != NULL and @p out != NULL.
 * @post Caller must free resources with free_psi_result() on success.
 */
int analyze_psi(FILE* file, ts_psi_result_t* out);
/**
 * @brief Release heap-owned memory inside a PSI result.
 *
 * @param[in,out] result PSI result to clean up. No effect if NULL.
 */
void free_psi_result(ts_psi_result_t* result);

/**
 * @brief Analyze packet stream into parsed packet rows and PID counts.
 *
 * Rewinds @p file and parses aligned 188-byte TS packets (no resync).
 *
 * @param[in]  file Input file handle.
 * @param[out] out  Packet analysis result container.
 * @retval 0 Success.
 * @retval 1 Failure.
 * @pre @p file != NULL and @p out != NULL.
 * @post Caller must free resources with free_packets_result() on success.
 */
int analyze_packets(FILE* file, ts_packets_result_t* out);
/**
 * @brief Release heap-owned memory inside a packet analysis result.
 *
 * @param[in,out] result Packet result to clean up. No effect if NULL.
 */
void free_packets_result(ts_packets_result_t* result);

/**
 * @brief Analyze PES packets grouped by PID.
 *
 * Performs PSI discovery and PES reassembly on aligned 188-byte TS packets.
 *
 * @param[in]  file Input file handle.
 * @param[out] out  PES analysis result container.
 * @retval 0 Success.
 * @retval 1 Failure.
 * @pre @p file != NULL and @p out != NULL.
 * @post Caller must free resources with free_pes_result() on success.
 */
int analyze_pes(FILE* file, ts_pes_result_t* out);
/**
 * @brief Release heap-owned memory inside a PES analysis result.
 *
 * @param[in,out] result PES result to clean up. No effect if NULL.
 */
void free_pes_result(ts_pes_result_t* result);

/**
 * @brief Analyze validation findings for sync/CC and undefined PID issues.
 *
 * Rewinds @p file and accumulates validation summary counters.
 *
 * @param[in]  file Input file handle.
 * @param[out] out  Validation result container.
 * @retval 0 Success.
 * @retval 1 Failure.
 * @pre @p file != NULL and @p out != NULL.
 * @post Caller must free resources with free_validate_result() on success.
 */
int analyze_validate(FILE* file, ts_validate_result_t* out);
/**
 * @brief Release heap-owned memory inside a validation result.
 *
 * @param[in,out] result Validation result to clean up. No effect if NULL.
 */
void free_validate_result(ts_validate_result_t* result);

/**
 * @brief Analyze PCR jitter metrics and rows.
 *
 * Selects PCR PID candidates from PSI, computes bitrate, fits a linear reference
 * PCR(byte_offset) over all PCR samples (least squares), then emits per-PCR rows:
 * interval ActualΔ from measured PCR, IdealΔ from the reference slope, Jitter = ActualΔ − IdealΔ.
 *
 * @param[in]  file Input file handle.
 * @param[out] out  Jitter result container.
 * @retval 0 Success.
 * @retval 1 Failure.
 * @pre @p file != NULL and @p out != NULL.
 * @post Caller must free resources with free_jitter_result() on success.
 */
int analyze_jitter(FILE* file, ts_jitter_result_t* out);
/**
 * @brief Release heap-owned memory inside a jitter result.
 *
 * @param[in,out] result Jitter result to clean up. No effect if NULL.
 */
void free_jitter_result(ts_jitter_result_t* result);
/**@}*/

/** @name CLI runner wrappers */
/**@{*/
/**
 * @brief Print packet-level report to stdout.
 * @param[in] file Input file handle.
 * @retval 0 Success.
 * @retval 1 Failure.
 */
int run_mode_packets(FILE* file);
/**
 * @brief Print PSI report (PAT/PMT/PID map) to stdout.
 * @param[in] file Input file handle.
 * @retval 0 Success.
 * @retval 1 Failure.
 */
int run_mode_psi(FILE* file);
/**
 * @brief Print validation report to stdout.
 * @param[in] file Input file handle.
 * @param[in] path Display path used in report text.
 * @retval 0 Success.
 * @retval 1 Failure.
 */
int run_mode_validate(FILE* file, const char* path);
/**
 * @brief Print hexdump for a packet number.
 * @param[in] file Input file handle.
 * @param[in] packet_number Zero-based packet index.
 * @retval 0 Success.
 * @retval 1 Failure.
 */
int run_mode_hexdump(FILE* file, long packet_number);
/**
 * @brief Print jitter metrics and full per-PCR row table (linear reference model).
 * @param[in] file Input file handle.
 * @retval 0 Success.
 * @retval 1 Failure.
 */
int run_mode_jitter_test(FILE* file);
/**
 * @brief Print PES summary and per-PID packet list report.
 * @param[in] file Input file handle.
 * @retval 0 Success.
 * @retval 1 Failure.
 */
int run_mode_pes(FILE* file);
/**@}*/

#endif // TS_PIPELINE_H

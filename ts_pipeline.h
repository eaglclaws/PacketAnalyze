#ifndef TS_PIPELINE_H
#define TS_PIPELINE_H

#include <stdio.h>
#include "packet.h"
#include "utils.h"

/*
 * TS pipeline public API
 * ----------------------
 * This module exposes:
 * 1) analysis-first functions that return structured results
 * 2) CLI runner wrappers used by main.c
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
    size_t preview_rows_omitted;
} ts_jitter_result_t;

/* ============================================================================
 * Analysis-first API
 * ========================================================================== */
int analyze_psi(FILE* file, ts_psi_result_t* out);
void free_psi_result(ts_psi_result_t* result);

int analyze_packets(FILE* file, ts_packets_result_t* out);
void free_packets_result(ts_packets_result_t* result);

int analyze_pes(FILE* file, ts_pes_result_t* out);
void free_pes_result(ts_pes_result_t* result);

int analyze_validate(FILE* file, ts_validate_result_t* out);
void free_validate_result(ts_validate_result_t* result);

int analyze_jitter(FILE* file, ts_jitter_result_t* out, int full_preview);
void free_jitter_result(ts_jitter_result_t* result);

/* ============================================================================
 * CLI runner wrappers
 * ========================================================================== */
/* Keep main.c thin: each wrapper consumes an opened FILE* and prints CLI output. */
int run_mode_packets(FILE* file);
int run_mode_psi(FILE* file);
int run_mode_validate(FILE* file, const char* path);
int run_mode_hexdump(FILE* file, long packet_number);
int run_mode_jitter_test(FILE* file);
int run_mode_pes(FILE* file);

#endif // TS_PIPELINE_H

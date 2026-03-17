#ifndef UTILS_H
#define UTILS_H
#include "packet.h"
#include <stdint.h>
#include <stdio.h>

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

//int pat_contains_pid(pat_table_t* pat, uint16_t pid);
void print_packet_header(ts_packet_t* packet);
const char* pid_type_to_string(pid_type_t type);
void pid_count_list_init(pid_count_list_t* list);
void pid_count_list_update(pid_count_list_t* list, uint16_t pid);
void pid_count_list_push(pid_count_list_t* list, uint16_t pid);
int pid_count_list_contains(pid_count_list_t* list, uint16_t pid);
int pid_count_list_find(pid_count_list_t* list, uint16_t pid);
void pid_count_list_cleanup(pid_count_list_t* list);
void pid_count_list_update_type(pid_count_list_t* list, uint16_t pid, pid_type_t type);
void print_psi_header(psi_header_t* header);

void pat_table_init(pat_table_t* table);
void pat_table_cleanup(pat_table_t* table);
void pat_table_push(pat_table_t* table, pat_program_t program);

/* Continuity counter state (per-PID). Call init once; check then update each packet. */
void ts_cc_init(void);
/* If out is non-NULL, print sync/CC errors to out. Returns 1 if an error was reported, 0 otherwise. */
int ts_cc_check(const ts_packet_t* packet, FILE* out);

void ts_cc_update(const ts_packet_t* packet);

/* Report PIDs that appear in list but are not in PAT/PMT (or null). Sets *errors_found if any. */
void report_undefined_pids(const pat_table_t* pat, const pmt_t* pmt_table, size_t pmt_capacity,
                           const pid_count_list_t* list, int* errors_found);

/* Print PID ratio header (count and % per PID) for --packets mode. */
void print_pid_ratio_header(const pid_count_list_t* list, long total_packets);

/* Grow pmt_table array to match pat->program_count; init new slots. */
void pmt_table_ensure_capacity(const pat_table_t* pat, pmt_t** pmt_table, size_t* capacity);

/* Print PAT, PID list, and PMT ES list. */
void print_ts_report(const pat_table_t* pat, const pmt_t* pmt_table, const pid_count_list_t* list);

/* Free pmt_table slots and array, cleanup pat and list. */
void ts_state_cleanup(pat_table_t* pat, pmt_t* pmt_table, size_t pmt_table_capacity, pid_count_list_t* list);

void print_hexdump(const uint8_t* buffer, size_t length);
#endif // UTILS_H

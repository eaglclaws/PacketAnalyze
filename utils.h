#ifndef UTILS_H
#define UTILS_H
#include "packet.h"
#include <stdint.h>

typedef enum pid_type_e {
    PID_UNKNOWN,
    PID_PAT,
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

int pat_contains_pid(pat_table_t* pat, uint16_t pid);
void print_packet_header(ts_packet_t* packet);
const char* pid_type_to_string(pid_type_t type);
void pid_count_list_init(pid_count_list_t* list);
void pid_count_list_update(pid_count_list_t* list, uint16_t pid);
void pid_count_list_push(pid_count_list_t* list, uint16_t pid);
int pid_count_list_contains(pid_count_list_t* list, uint16_t pid);
int pid_count_list_find(pid_count_list_t* list, uint16_t pid);
void pid_count_list_clean(pid_count_list_t* list);
#endif // UTILS_H

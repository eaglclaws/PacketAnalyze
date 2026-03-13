#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#define BOOL_STRING(x) (x ? "TRUE" : "FALSE")

int pat_contains_pid(pat_table_t* pat, uint16_t pid) {
    int ret = 0;
    for (size_t i = 0; i < pat->program_count; i++) {
        if (pat->programs[i].pid == pid) {
            return 1;
        }
    }
    return ret;
}

void print_packet_header(ts_packet_t* packet) {
        printf("0x%02X\t sync_byte\n", packet->sync_byte);
        printf("%s\t tei\n", BOOL_STRING(packet->tei));
        printf("%s\t pusi\n", BOOL_STRING(packet->pusi));
        printf("%s\t transport_priority\n", BOOL_STRING(packet->transport_priority));
        printf("0x%04X\t pid\n", packet->pid);
        printf("%d%d\t tsc\n", packet->tsc / 2, packet->tsc % 2);
        printf("%d%d\t adaptation_field_control\n", packet->adaptation_field_control / 2, packet->adaptation_field_control % 2);
        printf("%d\t continuity_counter\n", packet->continuity_counter);
        
        printf("===Adaptation field===\n");
        
        printf("%d\t adaptation_field_length\n", packet->adaptation_field_length);
        printf("%s\t discontinuity_indicator\n", BOOL_STRING(packet->discontinuity_indicator));
        printf("%s\t random_access_indicator\n", BOOL_STRING(packet->random_access_indicator));
        printf("%s\t es_priority_indicator\n", BOOL_STRING(packet->es_priority_indicator));
        printf("%s\t pcr_flag\n", BOOL_STRING(packet->pcr_flag));
        printf("%s\t opcr_flag\n", BOOL_STRING(packet->opcr_flag));
        printf("%s\t splicing_point_flag\n", BOOL_STRING(packet->splicing_point_flag));
        printf("%s\t transport_private_data_flag\n", BOOL_STRING(packet->transport_private_data_flag));
        printf("%s\t adaptation_field_extension_flag\n", BOOL_STRING(packet->adaptation_field_extension_flag));
        
        printf("===Optional fields===\n");

        if(packet->pcr_valid)
            printf("%lld\t pcr\n", packet->pcr_base * 300 + packet->pcr_ext);

        if(packet->opcr_valid)
            printf("%lld\t opcr\n", packet->opcr_base * 300 + packet->opcr_ext);

        if(packet->splice_countdown_valid)
            printf("%d\t splice_countdown\n", packet->splice_countdown);

        if(packet->transport_private_data_valid) {
            printf("%d\t transport_private_data_length\n", packet->transport_private_data_length);
            printf("%d\t transport_private_data_offset\n", packet->transport_private_data_offset);
        }
    
        if(packet->adaptation_extension_valid) {
            printf("%d\t adaptation_extension_length\n", packet->adaptation_extension_length);
            printf("%d\t adaptation_extension_offset\n", packet->adaptation_extension_offset);
        }
        
        printf("===Struct data==\n");

        printf("%d\t payload_offset\n", packet->payload_offset);
        printf("%d\t payload_length\n", packet->payload_length);
        printf("======\n\n");
}

const char* pid_type_to_string(pid_type_t type) {
    switch(type) {
        case PID_UNKNOWN:
            return "UNKNOWN";
        case PID_PAT:
            return "PAT";
        default:
            return "";
    }
}

void pid_count_list_init(pid_count_list_t* list) {
    list->capacity = 64;
    list->count = 0;
    list->pids = (pid_count_t*)malloc(sizeof(pid_count_t) * list->capacity);
}

void pid_count_list_update(pid_count_list_t* list, uint16_t pid) {
    int idx = (int)pid_count_list_find(list, pid);
    if (idx != -1) {
        list->pids[idx].count++;
    } else {
        pid_count_list_push(list, pid);
    }
}

void pid_count_list_push(pid_count_list_t* list, uint16_t pid) {
    if (pid_count_list_contains(list, pid)) {
        return;
    } else {
        list->pids[list->count].pid = pid;
        list->pids[list->count].count = 1;
        list->pids[list->count].type = PID_UNKNOWN;
        list->count++;
        if (list->count == list->capacity) {
            list->capacity *= 2;
            list->pids = realloc(list->pids, sizeof(pid_count_t) * list->capacity);
        }
    }
}

int pid_count_list_contains(pid_count_list_t* list, uint16_t pid) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->pids[i].pid == pid) {
            return 1;
        }
    }
    return 0;
}

int pid_count_list_find(pid_count_list_t* list, uint16_t pid) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->pids[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

void pid_count_list_clean(pid_count_list_t* list) {
    free(list->pids);
}

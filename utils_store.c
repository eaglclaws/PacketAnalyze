#include "utils.h"

#include <stdlib.h>
#include <string.h>

/*
 * Storage/lifecycle utilities:
 * - PAT/PMT dynamic tables
 * - PID count list
 * - PES packet/buffer collections
 */

#define MAX_PID 8192
#define PES_PACKET_LIST_INITIAL_CAPACITY 32u
#define PES_PACKET_LIST_TABLE_INITIAL_CAPACITY 16u
#define PES_BUFFER_TABLE_INITIAL_CAPACITY 16u
#define PES_BUFFER_ENTRY_INITIAL_CAPACITY 64u

/* ============================================================================
 * PAT / PMT storage
 * ========================================================================== */
void pat_table_init(pat_table_t* table) {
    table->program_count = 0;
    table->capacity = 2;
    table->programs = (pat_program_t*)malloc(sizeof(pat_program_t) * table->capacity);
}

void pat_table_cleanup(pat_table_t* table) {
    free(table->programs);
}

void pat_table_push(pat_table_t* table, pat_program_t program) {
    if (table->program_count == table->capacity) {
        table->capacity *= 2;
        table->programs = (pat_program_t*)realloc(table->programs, sizeof(pat_program_t) * table->capacity);
    }
    table->programs[table->program_count++] = program;
}

void pmt_table_ensure_capacity(const pat_table_t* pat, pmt_t** pmt_table, size_t* capacity) {
    while (*capacity < pat->program_count) {
        size_t new_cap = (*capacity == 0) ? 2 : *capacity * 2;
        if (new_cap < pat->program_count) {
            new_cap = pat->program_count;
        }
        *pmt_table = (pmt_t*)realloc(*pmt_table, new_cap * sizeof(pmt_t));
        for (size_t k = *capacity; k < new_cap; k++) {
            (*pmt_table)[k].pcr_pid = 0;
            (*pmt_table)[k].es_count = 0;
            (*pmt_table)[k].capacity = 2;
            (*pmt_table)[k].es_list = (pmt_es_t*)malloc(sizeof(pmt_es_t) * 2);
        }
        *capacity = new_cap;
    }
}

/* ============================================================================
 * PID count list storage
 * ========================================================================== */
const char* pid_type_to_string(pid_type_t type) {
    switch (type) {
        case PID_UNKNOWN: return "UNKNOWN";
        case PID_PAT: return "PAT";
        case PID_PMT: return "PMT";
        case PID_SI: return "SI";
        case PID_VIDEO: return "VIDEO";
        case PID_AUDIO: return "AUDIO";
        case PID_NULL: return "NULL";
        default: return "";
    }
}

void pid_count_list_init(pid_count_list_t* list) {
    list->capacity = 64;
    list->count = 0;
    list->pids = (pid_count_t*)malloc(sizeof(pid_count_t) * list->capacity);
}

int pid_count_list_find(pid_count_list_t* list, uint16_t pid) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->pids[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

int pid_count_list_contains(pid_count_list_t* list, uint16_t pid) {
    return pid_count_list_find(list, pid) != -1;
}

void pid_count_list_push(pid_count_list_t* list, uint16_t pid) {
    if (pid_count_list_contains(list, pid)) {
        return;
    }
    list->pids[list->count].pid = pid;
    list->pids[list->count].count = 1;
    list->pids[list->count].type = PID_UNKNOWN;
    list->count++;
    if (list->count == list->capacity) {
        list->capacity *= 2;
        list->pids = (pid_count_t*)realloc(list->pids, sizeof(pid_count_t) * list->capacity);
    }
}

void pid_count_list_update(pid_count_list_t* list, uint16_t pid) {
    int idx = pid_count_list_find(list, pid);
    if (idx != -1) {
        list->pids[idx].count++;
    } else {
        pid_count_list_push(list, pid);
    }
}

void pid_count_list_cleanup(pid_count_list_t* list) {
    free(list->pids);
}

void pid_count_list_update_type(pid_count_list_t* list, uint16_t pid, pid_type_t type) {
    int idx = pid_count_list_find(list, pid);
    if (idx != -1) {
        list->pids[idx].type = type;
    }
}

/* ============================================================================
 * PES packet list storage
 * ========================================================================== */
void pes_packet_list_init(pes_packet_list_t* list) {
    list->pid = 0;
    list->packets = NULL;
    list->count = 0;
    list->capacity = 0;
}

void pes_packet_list_push(pes_packet_list_t* list, const pes_packet_t* p) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2u : PES_PACKET_LIST_INITIAL_CAPACITY;
        pes_packet_t* new_packets = (pes_packet_t*)realloc(list->packets, sizeof(pes_packet_t) * new_cap);
        if (new_packets == NULL) {
            return;
        }
        list->packets = new_packets;
        list->capacity = new_cap;
    }
    list->packets[list->count++] = *p;
}

void pes_packet_list_cleanup(pes_packet_list_t* list) {
    free(list->packets);
    list->packets = NULL;
    list->count = 0;
    list->capacity = 0;
}

void pes_packet_list_table_init(pes_packet_list_table_t* table) {
    table->lists = NULL;
    table->count = 0;
    table->capacity = 0;
}

int pes_packet_list_table_find(const pes_packet_list_table_t* table, uint16_t pid) {
    for (size_t i = 0; i < table->count; i++) {
        if (table->lists[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

pes_packet_list_t* pes_packet_list_table_get_or_create(pes_packet_list_table_t* table, uint16_t pid) {
    int idx = pes_packet_list_table_find(table, pid);
    if (idx >= 0) {
        return &table->lists[(size_t)idx];
    }
    if (table->count >= table->capacity) {
        size_t new_cap = table->capacity ? table->capacity * 2u : PES_PACKET_LIST_TABLE_INITIAL_CAPACITY;
        pes_packet_list_t* new_lists = (pes_packet_list_t*)realloc(table->lists, sizeof(pes_packet_list_t) * new_cap);
        if (new_lists == NULL) {
            return NULL;
        }
        table->lists = new_lists;
        table->capacity = new_cap;
    }
    pes_packet_list_t* list = &table->lists[table->count++];
    pes_packet_list_init(list);
    list->pid = pid;
    return list;
}

void pes_packet_list_table_push_packet(pes_packet_list_table_t* table, uint16_t pid, const pes_packet_t* p) {
    pes_packet_list_t* list = pes_packet_list_table_get_or_create(table, pid);
    if (list != NULL) {
        pes_packet_list_push(list, p);
    }
}

void pes_packet_list_table_cleanup(pes_packet_list_table_t* table) {
    for (size_t i = 0; i < table->count; i++) {
        pes_packet_list_cleanup(&table->lists[i]);
    }
    free(table->lists);
    table->lists = NULL;
    table->count = 0;
    table->capacity = 0;
}

/* ============================================================================
 * PES reassembly buffer storage
 * ========================================================================== */
static int pes_buffer_table_find(const pes_buffer_table_t* table, uint16_t pid) {
    for (size_t i = 0; i < table->count; i++) {
        if (table->entries[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

void pes_buffer_table_init(pes_buffer_table_t* table) {
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}

pes_buffer_entry_t* pes_buffer_table_get_or_create(pes_buffer_table_t* table, uint16_t pid) {
    int idx = pes_buffer_table_find(table, pid);
    if (idx >= 0) {
        return &table->entries[(size_t)idx];
    }
    if (table->count >= table->capacity) {
        size_t new_cap = table->capacity ? table->capacity * 2u : PES_BUFFER_TABLE_INITIAL_CAPACITY;
        pes_buffer_entry_t* new_entries = (pes_buffer_entry_t*)realloc(table->entries, sizeof(pes_buffer_entry_t) * new_cap);
        if (new_entries == NULL) {
            return NULL;
        }
        table->entries = new_entries;
        table->capacity = new_cap;
    }
    pes_buffer_entry_t* entry = &table->entries[table->count++];
    entry->pid = pid;
    entry->buffer = NULL;
    entry->length = 0;
    entry->capacity = 0;
    return entry;
}

void pes_buffer_table_append(pes_buffer_entry_t* entry, const uint8_t* data, size_t len) {
    if (len == 0) {
        return;
    }
    if (entry->length + len > entry->capacity) {
        size_t new_cap = entry->capacity ? entry->capacity * 2u : PES_BUFFER_ENTRY_INITIAL_CAPACITY;
        while (new_cap < entry->length + len) {
            new_cap *= 2u;
        }
        uint8_t* new_buf = (uint8_t*)realloc(entry->buffer, new_cap);
        if (new_buf == NULL) {
            return;
        }
        entry->buffer = new_buf;
        entry->capacity = new_cap;
    }
    memcpy(entry->buffer + entry->length, data, len);
    entry->length += len;
}

void pes_buffer_table_clear_length(pes_buffer_entry_t* entry) {
    entry->length = 0;
}

void pes_buffer_table_cleanup(pes_buffer_table_t* table) {
    for (size_t i = 0; i < table->count; i++) {
        free(table->entries[i].buffer);
        table->entries[i].buffer = NULL;
        table->entries[i].length = 0;
        table->entries[i].capacity = 0;
    }
    free(table->entries);
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}

/* ============================================================================
 * Cross-structure cleanup
 * ========================================================================== */
void ts_state_cleanup(pat_table_t* pat, pmt_t* pmt_table, size_t pmt_table_capacity, pid_count_list_t* list) {
    if (pmt_table) {
        for (size_t i = 0; i < pmt_table_capacity; i++) {
            free(pmt_table[i].es_list);
        }
        free(pmt_table);
    }
    pat_table_cleanup(pat);
    pid_count_list_cleanup(list);
}

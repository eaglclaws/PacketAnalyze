#include "ts_pipeline.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "packet.h"
#include "parser.h"
#include "utils.h"

#define PACKET_SIZE 188
#define JITTER_PREVIEW_HEAD 40u
#define JITTER_PREVIEW_TAIL 40u

static void print_jitter_header(void) {
    printf("\n");
    printf("┌───────────────────────────────────────────────────────────────────────────────────────\n");
    printf("│  %-10s %-12s %-12s %-12s %s\n", "Packet", "Actual(ms)", "Ideal(ms)", "Offset(ms)", "Visual");
    printf("├───────────────────────────────────────────────────────────────────────────────────────\n");
}

static void print_jitter_row(size_t packet_idx, double actual_ms, double ideal_ms, double offset_ms) {
    const double scale_ms = 25.0;
    const int half_width = 22;
    int steps = (int)llround(offset_ms / scale_ms);
    if (steps > half_width) steps = half_width;
    if (steps < -half_width) steps = -half_width;

    char visual[64];
    int pos = 0;
    for (int i = -half_width; i <= half_width; i++) {
        if (i == 0) {
            visual[pos++] = '|';
        } else if (i == steps) {
            visual[pos++] = '*';
        } else {
            visual[pos++] = '.';
        }
    }
    visual[pos] = '\0';

    printf("│  %-10zu %-12.3f %-12.3f %-+12.3f %s\n",
           packet_idx, actual_ms, ideal_ms, offset_ms, visual);
}

typedef int (*ts_packet_handler_fn)(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx);

typedef struct packets_count_ctx_s {
    pid_count_list_t* pid_list;
    long total_packets;
} packets_count_ctx_t;

typedef struct psi_walk_ctx_s {
    pat_table_t* pat;
    pmt_t** pmt_table;
    size_t* pmt_table_capacity;
    pid_count_list_t* pid_list;
    int cc_summarize;
    int* errors_found; /* nullable */
} psi_walk_ctx_t;

typedef struct pcr_count_ctx_s {
    uint16_t target_pid;
    size_t count;
} pcr_count_ctx_t;

typedef struct jitter_stats_ctx_s {
    psi_walk_ctx_t psi;
    uint16_t pcr_pid;
    uint64_t first_pcr;
    uint64_t last_pcr;
    size_t first_byte_offset;
    size_t last_byte_offset;
    size_t pcr_sample_total;
    int first_found;
} jitter_stats_ctx_t;

typedef struct jitter_preview_ctx_s {
    psi_walk_ctx_t psi;
    uint16_t pcr_pid;
    uint64_t first_pcr;
    size_t first_byte_offset;
    double bitrate;
    size_t pcr_sample_total;
    size_t pcr_sample_index;
    int first_found;
    int omission_printed;
} jitter_preview_ctx_t;

typedef struct pes_walk_ctx_s {
    pat_table_t* pat;
    pmt_t** pmt_table;
    size_t* pmt_table_capacity;
    pid_count_list_t* pid_list;
    pes_packet_list_table_t* pes_packet_table;
    pes_buffer_table_t* pes_buffer_table;
    pes_packet_t* pes_packet;
    int had_error;
} pes_walk_ctx_t;

static int walk_ts_packets(FILE* file, ts_packet_handler_fn handler, void* ctx) {
    uint8_t buffer[PACKET_SIZE];
    size_t packet_index = 0;
    while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
        ts_packet_t packet;
        parse_ts_packet(buffer, PACKET_SIZE, &packet);
        if (!handler(buffer, &packet, packet_index, ctx)) {
            return 0;
        }
        packet_index++;
    }
    return 1;
}

static int pmt_contains_es_pid(const pmt_t* pmt_table, size_t pmt_table_capacity, uint16_t pid) {
    for (size_t i = 0; i < pmt_table_capacity; i++) {
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            if (pmt_table[i].es_list[j].elementary_pid == pid) {
                return 1;
            }
        }
    }
    return 0;
}

static int packets_count_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    (void)raw;
    (void)packet_index;
    packets_count_ctx_t* state = (packets_count_ctx_t*)ctx;
    pid_count_list_update(state->pid_list, packet->pid);
    state->total_packets++;
    return 1;
}

static int packets_print_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    (void)raw;
    (void)ctx;
    print_packet_header((ts_packet_t*)packet, packet_index);
    return 1;
}

static int psi_walk_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    psi_walk_ctx_t* state = (psi_walk_ctx_t*)ctx;
    if (ts_cc_check(packet, NULL, packet_index, state->cc_summarize) && state->errors_found != NULL) {
        *state->errors_found = 1;
    }
    process_packet_psi(raw, PACKET_SIZE, packet, state->pat, state->pmt_table, state->pmt_table_capacity, state->pid_list);
    ts_cc_update(packet);
    return 1;
}

static int pcr_count_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    (void)raw;
    (void)packet_index;
    pcr_count_ctx_t* state = (pcr_count_ctx_t*)ctx;
    if (packet->pcr_valid && packet->pid == state->target_pid) {
        state->count++;
    }
    return 1;
}

static int jitter_stats_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    jitter_stats_ctx_t* state = (jitter_stats_ctx_t*)ctx;
    psi_walk_handler(raw, packet, packet_index, &state->psi);
    if (packet->pcr_valid && packet->pid == state->pcr_pid) {
        uint64_t pcr = pcr_to_time(packet->pcr_base, packet->pcr_ext);
        state->pcr_sample_total++;
        if (!state->first_found) {
            state->first_pcr = pcr;
            state->first_byte_offset = packet_index * PACKET_SIZE;
            state->first_found = 1;
            return 1;
        }
        if (pcr > state->last_pcr) {
            state->last_pcr = pcr;
            state->last_byte_offset = packet_index * PACKET_SIZE;
        }
    }
    return 1;
}

static int jitter_preview_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    jitter_preview_ctx_t* state = (jitter_preview_ctx_t*)ctx;
    psi_walk_handler(raw, packet, packet_index, &state->psi);
    if (packet->pcr_valid && packet->pid == state->pcr_pid) {
        uint64_t pcr = pcr_to_time(packet->pcr_base, packet->pcr_ext);
        if (!state->first_found) {
            state->first_pcr = pcr;
            state->first_byte_offset = packet_index * PACKET_SIZE;
            state->first_found = 1;
        }
        {
            double actual_time_seconds = (double)(pcr - state->first_pcr) / 27000000.0;
            size_t actual_byte_offset = packet_index * PACKET_SIZE;
            double ideal_time_seconds = (double)(actual_byte_offset - state->first_byte_offset) * 8.0 / state->bitrate;
            double offset_ms = (actual_time_seconds - ideal_time_seconds) * 1000.0;
            const int in_head = (state->pcr_sample_index < JITTER_PREVIEW_HEAD);
            const size_t tail_start = (state->pcr_sample_total > JITTER_PREVIEW_TAIL)
                ? (state->pcr_sample_total - JITTER_PREVIEW_TAIL) : 0u;
            const int in_tail = (state->pcr_sample_index >= tail_start);
            if (in_head || in_tail) {
                print_jitter_row(packet_index, actual_time_seconds * 1000.0, ideal_time_seconds * 1000.0, offset_ms);
            } else if (!state->omission_printed) {
                const size_t omitted = (state->pcr_sample_total > (JITTER_PREVIEW_HEAD + JITTER_PREVIEW_TAIL))
                    ? (state->pcr_sample_total - JITTER_PREVIEW_HEAD - JITTER_PREVIEW_TAIL)
                    : 0u;
                printf("│  ... %zu rows omitted ...\n", omitted);
                state->omission_printed = 1;
            }
        }
        state->pcr_sample_index++;
    }
    return 1;
}

static int pes_pass1_discovery_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    pes_walk_ctx_t* state = (pes_walk_ctx_t*)ctx;
    ts_cc_check(packet, NULL, packet_index, 0);
    process_packet_psi(raw, PACKET_SIZE, packet, state->pat, state->pmt_table, state->pmt_table_capacity, state->pid_list);
    ts_cc_update(packet);
    return 1;
}

static int pes_pass2_collect_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    pes_walk_ctx_t* state = (pes_walk_ctx_t*)ctx;
    ts_cc_check(packet, NULL, packet_index, 0);
    if (pmt_contains_es_pid(*(state->pmt_table), *(state->pmt_table_capacity), packet->pid)) {
        pes_buffer_entry_t* entry = pes_buffer_table_get_or_create(state->pes_buffer_table, packet->pid);
        if (entry == NULL) {
            printf("Memory allocation failed (PES buffer table).\n");
            state->had_error = 1;
            return 0;
        }
        if (packet->pusi && packet->payload_length > 0) {
            if (entry->length > 0) {
                if (parse_pes_header(entry->buffer, entry->length, state->pes_packet)
                        && populate_pes_pts_dts(entry->buffer, entry->length, state->pes_packet)) {
                    pes_packet_list_table_push_packet(state->pes_packet_table, packet->pid, state->pes_packet);
                }
            }
            pes_buffer_table_clear_length(entry);
            pes_buffer_table_append(entry, raw + packet->payload_offset, packet->payload_length);
        } else if (packet->payload_length > 0) {
            pes_buffer_table_append(entry, raw + packet->payload_offset, packet->payload_length);
        }
    }
    ts_cc_update(packet);
    return 1;
}

int run_mode_packets(FILE* file) {
    pid_count_list_t list;
    pid_count_list_init(&list);
    packets_count_ctx_t count_ctx = {.pid_list = &list, .total_packets = 0};
    if (!walk_ts_packets(file, packets_count_handler, &count_ctx)) {
        pid_count_list_cleanup(&list);
        return 1;
    }
    print_pid_ratio_header(&list, count_ctx.total_packets);
    rewind(file);
    if (!walk_ts_packets(file, packets_print_handler, NULL)) {
        pid_count_list_cleanup(&list);
        return 1;
    }
    pid_count_list_cleanup(&list);
    return 0;
}

int run_mode_psi(FILE* file) {
    pat_table_t current_pat;
    pat_table_init(&current_pat);
    pmt_t* pmt_table = NULL;
    size_t pmt_table_capacity = 0;
    pid_count_list_t list;
    pid_count_list_init(&list);
    psi_walk_ctx_t psi_ctx = {
        .pat = &current_pat,
        .pmt_table = &pmt_table,
        .pmt_table_capacity = &pmt_table_capacity,
        .pid_list = &list,
        .cc_summarize = 0,
        .errors_found = NULL
    };
    ts_cc_init();
    if (!walk_ts_packets(file, psi_walk_handler, &psi_ctx)) {
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        return 1;
    }
    print_ts_report(&current_pat, pmt_table, &list);
    ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
    return 0;
}

int run_mode_validate(FILE* file, const char* path) {
    pat_table_t current_pat;
    pat_table_init(&current_pat);
    pmt_t* pmt_table = NULL;
    size_t pmt_table_capacity = 0;
    pid_count_list_t list;
    pid_count_list_init(&list);
    int errors_found = 0;
    psi_walk_ctx_t validate_ctx = {
        .pat = &current_pat,
        .pmt_table = &pmt_table,
        .pmt_table_capacity = &pmt_table_capacity,
        .pid_list = &list,
        .cc_summarize = 1,
        .errors_found = &errors_found
    };
    ts_cc_init();
    validation_summary_init();
    printf("\n");
    printf("┌────────────────────────────────────────────────── Validation\n");
    if (!walk_ts_packets(file, psi_walk_handler, &validate_ctx)) {
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        return 1;
    }
    validation_summary_print(stdout);
    if (validation_summary_total_errors() > 0u) {
        errors_found = 1;
    }
    report_undefined_pids(&current_pat, pmt_table, pmt_table_capacity, &list, &errors_found);
    if (!errors_found) {
        printf("│  No errors in %s\n", path);
    }
    printf("└──────────────────────────────────────────────────\n");
    ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
    return 0;
}

int run_mode_hexdump(FILE* file, long packet_number) {
    uint8_t buffer[PACKET_SIZE];
    if (packet_number < 0) {
        fprintf(stderr, "packet_number must be >= 0\n");
        return 1;
    }
    if (fseek(file, packet_number * (long)PACKET_SIZE, SEEK_SET) != 0) {
        perror("fseek");
        return 1;
    }
    {
        size_t n = fread(buffer, 1, PACKET_SIZE, file);
        if (n > 0 && buffer[0] != 0x47) {
            fprintf(stderr, "Warning: first byte is 0x%02X (expected TS sync 0x47). Wrong file or packet index?\n", buffer[0]);
        }
        print_hexdump(buffer, n);
    }
    return 0;
}

int run_mode_jitter_test(FILE* file) {
    pat_table_t current_pat;
    pat_table_init(&current_pat);
    pmt_t* pmt_table = NULL;
    size_t pmt_table_capacity = 0;
    pid_count_list_t list;
    pid_count_list_init(&list);
    uint64_t first_pcr = 0;
    uint64_t last_pcr = 0;
    size_t first_byte_offset = 0;
    size_t last_byte_offset = 0;
    double bitrate = 0;
    int first_found = 0;
    uint16_t pcr_pid = 0xFFFFu;
    psi_walk_ctx_t jitter_psi_ctx = {
        .pat = &current_pat,
        .pmt_table = &pmt_table,
        .pmt_table_capacity = &pmt_table_capacity,
        .pid_list = &list,
        .cc_summarize = 0,
        .errors_found = NULL
    };
    ts_cc_init();
    if (!walk_ts_packets(file, psi_walk_handler, &jitter_psi_ctx)) {
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        return 1;
    }
    if (pmt_table == NULL || pmt_table_capacity == 0) {
        printf("Unable to determine PMT/PCR PID.\n");
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        return 1;
    }

    {
        uint16_t* candidates = (uint16_t*)malloc(sizeof(uint16_t) * pmt_table_capacity);
        size_t* candidate_counts = (size_t*)malloc(sizeof(size_t) * pmt_table_capacity);
        size_t candidate_count = 0;
        if (candidates == NULL || candidate_counts == NULL) {
            printf("Memory allocation failed while selecting PCR PID.\n");
            free(candidates);
            free(candidate_counts);
            ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
            return 1;
        }

        for (size_t i = 0; i < pmt_table_capacity; i++) {
            uint16_t candidate = pmt_table[i].pcr_pid;
            int exists = 0;
            if (candidate == 0u || candidate == TS_PID_NULL) {
                continue;
            }
            for (size_t j = 0; j < candidate_count; j++) {
                if (candidates[j] == candidate) {
                    exists = 1;
                    break;
                }
            }
            if (!exists) {
                candidates[candidate_count++] = candidate;
            }
        }

        if (candidate_count == 0) {
            printf("No valid PCR PID found in PMT.\n");
            free(candidates);
            free(candidate_counts);
            ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
            return 1;
        }

        for (size_t i = 0; i < candidate_count; i++) {
            pcr_count_ctx_t count_ctx = {.target_pid = candidates[i], .count = 0};
            rewind(file);
            if (!walk_ts_packets(file, pcr_count_handler, &count_ctx)) {
                free(candidates);
                free(candidate_counts);
                ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
                return 1;
            }
            candidate_counts[i] = count_ctx.count;
        }

        {
            size_t best_idx = 0;
            for (size_t i = 1; i < candidate_count; i++) {
                if (candidate_counts[i] > candidate_counts[best_idx]) {
                    best_idx = i;
                }
            }
            if (candidate_counts[best_idx] == 0) {
                printf("No PCR samples found on any PMT PCR PID.\n");
                free(candidates);
                free(candidate_counts);
                ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
                return 1;
            }
            pcr_pid = candidates[best_idx];
            printf("PCR PID: 0x%04X (selected, %zu samples)\n", pcr_pid, candidate_counts[best_idx]);
        }

        free(candidates);
        free(candidate_counts);
    }

    {
        jitter_stats_ctx_t stats_ctx;
        size_t pcr_sample_total = 0;
        rewind(file);
        stats_ctx.psi = jitter_psi_ctx;
        stats_ctx.pcr_pid = pcr_pid;
        stats_ctx.first_pcr = 0;
        stats_ctx.last_pcr = 0;
        stats_ctx.first_byte_offset = 0;
        stats_ctx.last_byte_offset = 0;
        stats_ctx.pcr_sample_total = 0;
        stats_ctx.first_found = 0;
        if (!walk_ts_packets(file, jitter_stats_handler, &stats_ctx)) {
            ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
            return 1;
        }
        pcr_sample_total = stats_ctx.pcr_sample_total;
        first_pcr = stats_ctx.first_pcr;
        last_pcr = stats_ctx.last_pcr;
        first_byte_offset = stats_ctx.first_byte_offset;
        last_byte_offset = stats_ctx.last_byte_offset;
        first_found = stats_ctx.first_found;

        if (!first_found || pcr_sample_total < 2 || last_pcr <= first_pcr || last_byte_offset <= first_byte_offset) {
            printf("Not enough PCR samples to compute jitter for PID 0x%04X.\n", pcr_pid);
            ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
            return 1;
        }
        bitrate = (double)(last_byte_offset - first_byte_offset) * 8.0 / ((double)(last_pcr - first_pcr) / 27000000.0);
        printf("First PCR: %llu, Last PCR: %llu\n", first_pcr, last_pcr);
        printf("First byte offset: %zu, Last byte offset: %zu\n", first_byte_offset, last_byte_offset);
        printf("Bitrate: %f bps\n", bitrate);
        printf("Preview rows: first %u + last %u (total PCR samples: %zu)\n",
               (unsigned)JITTER_PREVIEW_HEAD, (unsigned)JITTER_PREVIEW_TAIL, pcr_sample_total);
        print_jitter_header();
        rewind(file);
        {
            jitter_preview_ctx_t preview_ctx;
            preview_ctx.psi = jitter_psi_ctx;
            preview_ctx.pcr_pid = pcr_pid;
            preview_ctx.first_pcr = 0;
            preview_ctx.first_byte_offset = 0;
            preview_ctx.bitrate = bitrate;
            preview_ctx.pcr_sample_total = pcr_sample_total;
            preview_ctx.pcr_sample_index = 0;
            preview_ctx.first_found = 0;
            preview_ctx.omission_printed = 0;
            if (!walk_ts_packets(file, jitter_preview_handler, &preview_ctx)) {
                ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
                return 1;
            }
        }
        printf("└───────────────────────────────────────────────────────────────────────────────────────\n");
    }

    ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
    return 0;
}

int run_mode_pes(FILE* file) {
    pat_table_t current_pat;
    pat_table_init(&current_pat);
    pmt_t* pmt_table = NULL;
    size_t pmt_table_capacity = 0;
    pid_count_list_t list;
    pid_count_list_init(&list);

    pes_packet_t pes_packet;
    pes_packet_list_table_t pes_packet_list_table;
    pes_packet_list_table_init(&pes_packet_list_table);
    pes_buffer_table_t pes_buffer_table;
    pes_buffer_table_init(&pes_buffer_table);
    pes_walk_ctx_t pes_ctx = {
        .pat = &current_pat,
        .pmt_table = &pmt_table,
        .pmt_table_capacity = &pmt_table_capacity,
        .pid_list = &list,
        .pes_packet_table = &pes_packet_list_table,
        .pes_buffer_table = &pes_buffer_table,
        .pes_packet = &pes_packet,
        .had_error = 0
    };

    ts_cc_init();
    if (!walk_ts_packets(file, pes_pass1_discovery_handler, &pes_ctx)) {
        pes_buffer_table_cleanup(&pes_buffer_table);
        pes_packet_list_table_cleanup(&pes_packet_list_table);
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        return 1;
    }
    print_pes_streams_summary(pmt_table, pmt_table_capacity);
    rewind(file);
    if (!walk_ts_packets(file, pes_pass2_collect_handler, &pes_ctx) || pes_ctx.had_error) {
        pes_buffer_table_cleanup(&pes_buffer_table);
        pes_packet_list_table_cleanup(&pes_packet_list_table);
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        return 1;
    }
    print_pes_packet_list_report(&pes_packet_list_table);
    pes_buffer_table_cleanup(&pes_buffer_table);
    pes_packet_list_table_cleanup(&pes_packet_list_table);
    ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
    return 0;
}

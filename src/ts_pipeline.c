#include "ts_pipeline.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet.h"
#include "parser.h"
#include "utils.h"

/*
 * TS pipeline module:
 * - shared packet walker
 * - mode-specific packet handlers
 * - run_mode_* entry points used by main.c
 */

#define PACKET_SIZE 188

/* ============================================================================
 * Jitter preview rendering
 * ========================================================================== */
static void print_jitter_header(void) {
    printf("\n");
    printf("┌───────────────────────────────────────────────────────────────────────────────────────\n");
    printf("│  %-10s %-12s %-12s %-12s %s\n", "Packet", "ActualΔ(ms)", "IdealΔ(ms)", "Jitter(ms)", "Visual");
    printf("├───────────────────────────────────────────────────────────────────────────────────────\n");
}

static void print_jitter_row(size_t packet_idx, double actual_ms, int actual_valid,
                             double ideal_ms, int ideal_valid,
                             double offset_ms, int offset_valid) {
    const double scale_ms = 25.0;
    const int half_width = 22;
    int steps = 0;
    if (offset_valid) {
        steps = (int)llround(offset_ms / scale_ms);
        if (steps > half_width) steps = half_width;
        if (steps < -half_width) steps = -half_width;
    }

    char visual[64];
    char actual_text[16];
    char ideal_text[16];
    char offset_text[16];
    int pos = 0;
    if (offset_valid) {
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
    } else {
        snprintf(visual, sizeof(visual), "N/A");
    }
    if (actual_valid) {
        snprintf(actual_text, sizeof(actual_text), "%.3f", actual_ms);
    } else {
        snprintf(actual_text, sizeof(actual_text), "N/A");
    }
    if (ideal_valid) {
        snprintf(ideal_text, sizeof(ideal_text), "%.3f", ideal_ms);
    } else {
        snprintf(ideal_text, sizeof(ideal_text), "N/A");
    }
    if (offset_valid) {
        snprintf(offset_text, sizeof(offset_text), "%+.3f", offset_ms);
    } else {
        snprintf(offset_text, sizeof(offset_text), "N/A");
    }

    printf("│  %-10zu %-12s %-12s %-12s %s\n",
           packet_idx, actual_text, ideal_text, offset_text, visual);
}

typedef int (*ts_packet_handler_fn)(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx);

/* ============================================================================
 * Shared handler contexts
 * ========================================================================== */
typedef struct packets_collect_ctx_s {
    ts_packets_result_t* out;
} packets_collect_ctx_t;

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
    uint16_t pcr_pid;
    uint64_t first_pcr;
    uint64_t last_pcr;
    size_t first_byte_offset;
    size_t last_byte_offset;
    size_t pcr_sample_total;
    int first_found;
} jitter_stats_ctx_t;

typedef struct jitter_preview_ctx_s {
    uint16_t pcr_pid;
    uint64_t prev_pcr;
    size_t prev_byte_offset;
    double reg_b; /* ticks per byte: PCR ≈ a + reg_b * byte_offset (a from fit, not needed per interval) */
    int reg_valid;
    int first_found;
    ts_jitter_preview_row_t* rows;
    size_t row_count;
    size_t row_capacity;
} jitter_preview_ctx_t;

typedef struct pcr_sample_s {
    size_t byte_offset;
    uint64_t pcr;
} pcr_sample_t;

typedef struct pcr_collect_ctx_s {
    uint16_t pcr_pid;
    pcr_sample_t* samples;
    size_t count;
    size_t capacity;
} pcr_collect_ctx_t;

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

/* ============================================================================
 * Shared walker and low-level helpers
 * ========================================================================== */
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

/* ============================================================================
 * Packet handlers (reused by mode runners)
 * ========================================================================== */
static int packets_result_append(ts_packets_result_t* out, const ts_packet_t* packet) {
    if (out->packet_count == out->packet_capacity) {
        size_t new_cap = out->packet_capacity == 0u ? 1024u : out->packet_capacity * 2u;
        ts_packet_t* new_packets = (ts_packet_t*)realloc(out->packets, sizeof(ts_packet_t) * new_cap);
        if (new_packets == NULL) {
            return 0;
        }
        out->packets = new_packets;
        out->packet_capacity = new_cap;
    }
    out->packets[out->packet_count++] = *packet;
    return 1;
}

static int packets_collect_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    packets_collect_ctx_t* state = (packets_collect_ctx_t*)ctx;
    (void)raw;
    (void)packet_index;
    pid_count_list_update(&state->out->pid_list, packet->pid);
    return packets_result_append(state->out, packet);
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
    (void)raw;
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

static int pcr_collect_append(pcr_collect_ctx_t* c, size_t byte_offset, uint64_t pcr) {
    if (c->count == c->capacity) {
        size_t new_cap = c->capacity == 0u ? 128u : c->capacity * 2u;
        pcr_sample_t* p = (pcr_sample_t*)realloc(c->samples, sizeof(pcr_sample_t) * new_cap);
        if (p == NULL) {
            return 0;
        }
        c->samples = p;
        c->capacity = new_cap;
    }
    c->samples[c->count].byte_offset = byte_offset;
    c->samples[c->count].pcr = pcr;
    c->count++;
    return 1;
}

static int pcr_collect_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    pcr_collect_ctx_t* state = (pcr_collect_ctx_t*)ctx;
    (void)raw;
    if (packet->pcr_valid && packet->pid == state->pcr_pid) {
        uint64_t pcr = pcr_to_time(packet->pcr_base, packet->pcr_ext);
        if (!pcr_collect_append(state, packet_index * PACKET_SIZE, pcr)) {
            return 0;
        }
    }
    return 1;
}

/* Least squares: pcr_ticks ≈ a + b * byte_offset. Returns 0 if singular or n < 2. */
static int pcr_fit_linear(const pcr_sample_t* samples, size_t n, double* out_a, double* out_b) {
    if (samples == NULL || n < 2u || out_a == NULL || out_b == NULL) {
        return 0;
    }
    double sum_x = 0.0;
    double sum_y = 0.0;
    double sum_xx = 0.0;
    double sum_xy = 0.0;
    for (size_t i = 0; i < n; i++) {
        double x = (double)samples[i].byte_offset;
        double y = (double)samples[i].pcr;
        sum_x += x;
        sum_y += y;
        sum_xx += x * x;
        sum_xy += x * y;
    }
    double nn = (double)n;
    double denom = nn * sum_xx - sum_x * sum_x;
    if (fabs(denom) < 1e-3) {
        return 0;
    }
    double b = (nn * sum_xy - sum_x * sum_y) / denom;
    double a = (sum_y - b * sum_x) / nn;
    *out_a = a;
    *out_b = b;
    return 1;
}

static int jitter_preview_push_row(jitter_preview_ctx_t* state, size_t packet_index,
                                   double actual_ms, int actual_valid,
                                   double ideal_ms, int ideal_valid,
                                   double offset_ms, int offset_valid) {
    if (state->row_count == state->row_capacity) {
        size_t new_cap = state->row_capacity == 0u ? 128u : state->row_capacity * 2u;
        ts_jitter_preview_row_t* new_rows =
            (ts_jitter_preview_row_t*)realloc(state->rows, sizeof(ts_jitter_preview_row_t) * new_cap);
        if (new_rows == NULL) {
            return 0;
        }
        state->rows = new_rows;
        state->row_capacity = new_cap;
    }
    state->rows[state->row_count].packet_index = packet_index;
    state->rows[state->row_count].actual_ms = actual_ms;
    state->rows[state->row_count].ideal_ms = ideal_ms;
    state->rows[state->row_count].offset_ms = offset_ms;
    state->rows[state->row_count].actual_valid = actual_valid;
    state->rows[state->row_count].ideal_valid = ideal_valid;
    state->rows[state->row_count].offset_valid = offset_valid;
    state->row_count++;
    return 1;
}

static int jitter_preview_handler(const uint8_t* raw, const ts_packet_t* packet, size_t packet_index, void* ctx) {
    jitter_preview_ctx_t* state = (jitter_preview_ctx_t*)ctx;
    (void)raw;
    if (packet->pcr_valid && packet->pid == state->pcr_pid) {
        uint64_t pcr = pcr_to_time(packet->pcr_base, packet->pcr_ext);
        size_t actual_byte_offset = packet_index * PACKET_SIZE;
        double actual_time_ms = 0.0;
        double ideal_time_ms = 0.0;
        double offset_ms = 0.0;
        int actual_valid = 0;
        int ideal_valid = 0;
        int offset_valid = 0;
        if (!state->first_found) {
            state->prev_pcr = pcr;
            state->prev_byte_offset = actual_byte_offset;
            state->first_found = 1;
        } else {
            uint64_t delta_pcr = pcr - state->prev_pcr;
            size_t delta_bytes = actual_byte_offset - state->prev_byte_offset;
            if (delta_pcr > 0u && delta_bytes > 0u) {
                double actual_time_seconds = (double)delta_pcr / 27000000.0;
                actual_time_ms = actual_time_seconds * 1000.0;
                actual_valid = 1;
                if (state->reg_valid) {
                    double ideal_delta_ticks = state->reg_b * (double)delta_bytes;
                    double ideal_time_seconds = ideal_delta_ticks / 27000000.0;
                    ideal_time_ms = ideal_time_seconds * 1000.0;
                    ideal_valid = 1;
                    offset_ms = actual_time_ms - ideal_time_ms;
                    offset_valid = 1;
                }
            }
            state->prev_pcr = pcr;
            state->prev_byte_offset = actual_byte_offset;
        }
        {
            if (!jitter_preview_push_row(state, packet_index,
                                         actual_time_ms, actual_valid,
                                         ideal_time_ms, ideal_valid,
                                         offset_ms, offset_valid)) {
                return 0;
            }
        }
    }
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

/* ============================================================================
 * Analysis-first API
 * ========================================================================== */
/* Analyze PSI state (PAT/PMT/PID map) without printing. */
int analyze_psi(FILE* file, ts_psi_result_t* out) {
    if (file == NULL || out == NULL) {
        return 1;
    }
    rewind(file);

    pat_table_init(&out->pat);
    out->pmt_table = NULL;
    out->pmt_table_capacity = 0;
    pid_count_list_init(&out->pid_list);

    {
        psi_walk_ctx_t psi_ctx = {
            .pat = &out->pat,
            .pmt_table = &out->pmt_table,
            .pmt_table_capacity = &out->pmt_table_capacity,
            .pid_list = &out->pid_list,
            .cc_summarize = 0,
            .errors_found = NULL
        };
        ts_cc_init();
        if (!walk_ts_packets(file, psi_walk_handler, &psi_ctx)) {
            ts_state_cleanup(&out->pat, out->pmt_table, out->pmt_table_capacity, &out->pid_list);
            out->pmt_table = NULL;
            out->pmt_table_capacity = 0;
            return 1;
        }
    }
    return 0;
}

/* Release heap allocations inside ts_psi_result_t. */
void free_psi_result(ts_psi_result_t* result) {
    if (result == NULL) {
        return;
    }
    ts_state_cleanup(&result->pat, result->pmt_table, result->pmt_table_capacity, &result->pid_list);
    result->pmt_table = NULL;
    result->pmt_table_capacity = 0;
}

/* Analyze packet stream into parsed packet rows + PID counts. */
int analyze_packets(FILE* file, ts_packets_result_t* out) {
    if (file == NULL || out == NULL) {
        return 1;
    }
    rewind(file);
    pid_count_list_init(&out->pid_list);
    out->packets = NULL;
    out->packet_count = 0;
    out->packet_capacity = 0;
    {
        packets_collect_ctx_t ctx = {.out = out};
        if (!walk_ts_packets(file, packets_collect_handler, &ctx)) {
            free(out->packets);
            out->packets = NULL;
            out->packet_count = 0;
            out->packet_capacity = 0;
            pid_count_list_cleanup(&out->pid_list);
            return 1;
        }
    }
    return 0;
}

/* Release heap allocations inside ts_packets_result_t. */
void free_packets_result(ts_packets_result_t* result) {
    if (result == NULL) {
        return;
    }
    free(result->packets);
    result->packets = NULL;
    result->packet_count = 0;
    result->packet_capacity = 0;
    pid_count_list_cleanup(&result->pid_list);
}

/* Analyze PES packets by PID (includes PSI discovery pass). */
int analyze_pes(FILE* file, ts_pes_result_t* out) {
    if (file == NULL || out == NULL) {
        return 1;
    }
    rewind(file);

    if (analyze_psi(file, &out->psi) != 0) {
        return 1;
    }

    pes_packet_list_table_init(&out->pes_packet_table);

    {
        pes_packet_t pes_packet;
        pes_buffer_table_t pes_buffer_table;
        pes_buffer_table_init(&pes_buffer_table);
        pes_walk_ctx_t pes_ctx = {
            .pat = &out->psi.pat,
            .pmt_table = &out->psi.pmt_table,
            .pmt_table_capacity = &out->psi.pmt_table_capacity,
            .pid_list = &out->psi.pid_list,
            .pes_packet_table = &out->pes_packet_table,
            .pes_buffer_table = &pes_buffer_table,
            .pes_packet = &pes_packet,
            .had_error = 0
        };

        rewind(file);
        if (!walk_ts_packets(file, pes_pass2_collect_handler, &pes_ctx) || pes_ctx.had_error) {
            pes_buffer_table_cleanup(&pes_buffer_table);
            pes_packet_list_table_cleanup(&out->pes_packet_table);
            free_psi_result(&out->psi);
            return 1;
        }
        pes_buffer_table_cleanup(&pes_buffer_table);
    }

    return 0;
}

/* Release heap allocations inside ts_pes_result_t. */
void free_pes_result(ts_pes_result_t* result) {
    if (result == NULL) {
        return;
    }
    pes_packet_list_table_cleanup(&result->pes_packet_table);
    free_psi_result(&result->psi);
}

/* Count undefined PIDs without producing text output. */
static size_t count_undefined_pids_in_list(const pat_table_t* pat, const pmt_t* pmt_table,
                                           size_t pmt_capacity, const pid_count_list_t* list) {
    uint8_t defined[8192];
    size_t count = 0;
    memset(defined, 0, sizeof defined);
    defined[TS_PID_PAT] = 1;
    defined[TS_PID_NULL] = 1;
    for (uint16_t pid = 0; pid < 8192; pid++) {
        if (is_well_known_si_pid(pid)) {
            defined[pid] = 1;
        }
    }
    for (size_t i = 0; i < pat->program_count; i++) {
        if (pat->programs[i].pid < 8192) {
            defined[pat->programs[i].pid] = 1;
        }
    }
    for (size_t i = 0; i < pmt_capacity && pmt_table != NULL; i++) {
        if (pmt_table[i].pcr_pid < 8192) {
            defined[pmt_table[i].pcr_pid] = 1;
        }
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            if (pmt_table[i].es_list[j].elementary_pid < 8192) {
                defined[pmt_table[i].es_list[j].elementary_pid] = 1;
            }
        }
    }
    for (size_t i = 0; i < list->count; i++) {
        uint16_t pid = list->pids[i].pid;
        if (pid < 8192 && !defined[pid]) {
            count++;
        }
    }
    return count;
}

/* Analyze validation findings and summary counters without rendering. */
int analyze_validate(FILE* file, ts_validate_result_t* out) {
    if (file == NULL || out == NULL) {
        return 1;
    }
    rewind(file);
    pat_table_init(&out->psi.pat);
    out->psi.pmt_table = NULL;
    out->psi.pmt_table_capacity = 0;
    pid_count_list_init(&out->psi.pid_list);
    out->errors_found = 0;
    out->undefined_pid_count = 0;

    {
        psi_walk_ctx_t validate_ctx = {
            .pat = &out->psi.pat,
            .pmt_table = &out->psi.pmt_table,
            .pmt_table_capacity = &out->psi.pmt_table_capacity,
            .pid_list = &out->psi.pid_list,
            .cc_summarize = 1,
            .errors_found = &out->errors_found
        };
        ts_cc_init();
        validation_summary_init();
        if (!walk_ts_packets(file, psi_walk_handler, &validate_ctx)) {
            free_psi_result(&out->psi);
            return 1;
        }
    }

    if (validation_summary_total_errors() > 0u) {
        out->errors_found = 1;
    }
    out->undefined_pid_count = count_undefined_pids_in_list(
        &out->psi.pat, out->psi.pmt_table, out->psi.pmt_table_capacity, &out->psi.pid_list);
    if (out->undefined_pid_count > 0u) {
        out->errors_found = 1;
    }
    return 0;
}

/* Release heap allocations inside ts_validate_result_t. */
void free_validate_result(ts_validate_result_t* result) {
    if (result == NULL) {
        return;
    }
    free_psi_result(&result->psi);
    result->errors_found = 0;
    result->undefined_pid_count = 0;
}

/* Analyze jitter metrics and rows without rendering. */
int analyze_jitter(FILE* file, ts_jitter_result_t* out) {
    if (file == NULL || out == NULL) {
        return 1;
    }
    memset(out, 0, sizeof(*out));
    if (analyze_psi(file, &out->psi) != 0) {
        return 1;
    }
    if (out->psi.pmt_table == NULL || out->psi.pmt_table_capacity == 0) {
        free_psi_result(&out->psi);
        return 1;
    }

    {
        uint16_t* candidates = (uint16_t*)malloc(sizeof(uint16_t) * out->psi.pmt_table_capacity);
        size_t* candidate_counts = (size_t*)malloc(sizeof(size_t) * out->psi.pmt_table_capacity);
        size_t candidate_count = 0;
        if (candidates == NULL || candidate_counts == NULL) {
            free(candidates);
            free(candidate_counts);
            free_psi_result(&out->psi);
            return 1;
        }
        for (size_t i = 0; i < out->psi.pmt_table_capacity; i++) {
            uint16_t candidate = out->psi.pmt_table[i].pcr_pid;
            int exists = 0;
            if (candidate == 0u || candidate == TS_PID_NULL) continue;
            for (size_t j = 0; j < candidate_count; j++) {
                if (candidates[j] == candidate) { exists = 1; break; }
            }
            if (!exists) candidates[candidate_count++] = candidate;
        }
        if (candidate_count == 0) {
            free(candidates);
            free(candidate_counts);
            free_psi_result(&out->psi);
            return 1;
        }
        for (size_t i = 0; i < candidate_count; i++) {
            pcr_count_ctx_t count_ctx = {.target_pid = candidates[i], .count = 0};
            rewind(file);
            if (!walk_ts_packets(file, pcr_count_handler, &count_ctx)) {
                free(candidates);
                free(candidate_counts);
                free_psi_result(&out->psi);
                return 1;
            }
            candidate_counts[i] = count_ctx.count;
        }
        {
            size_t best_idx = 0;
            for (size_t i = 1; i < candidate_count; i++) {
                if (candidate_counts[i] > candidate_counts[best_idx]) best_idx = i;
            }
            if (candidate_counts[best_idx] == 0) {
                free(candidates);
                free(candidate_counts);
                free_psi_result(&out->psi);
                return 1;
            }
            out->pcr_pid = candidates[best_idx];
        }
        free(candidates);
        free(candidate_counts);
    }

    {
        jitter_stats_ctx_t stats_ctx;
        rewind(file);
        stats_ctx.pcr_pid = out->pcr_pid;
        stats_ctx.first_pcr = 0;
        stats_ctx.last_pcr = 0;
        stats_ctx.first_byte_offset = 0;
        stats_ctx.last_byte_offset = 0;
        stats_ctx.pcr_sample_total = 0;
        stats_ctx.first_found = 0;
        if (!walk_ts_packets(file, jitter_stats_handler, &stats_ctx)) {
            free_psi_result(&out->psi);
            return 1;
        }
        out->pcr_sample_total = stats_ctx.pcr_sample_total;
        out->first_pcr = stats_ctx.first_pcr;
        out->last_pcr = stats_ctx.last_pcr;
        out->first_byte_offset = stats_ctx.first_byte_offset;
        out->last_byte_offset = stats_ctx.last_byte_offset;
        if (!stats_ctx.first_found || out->pcr_sample_total < 2 ||
            out->last_pcr <= out->first_pcr || out->last_byte_offset <= out->first_byte_offset) {
            free_psi_result(&out->psi);
            return 1;
        }
    }

    out->bitrate = (double)(out->last_byte_offset - out->first_byte_offset) * 8.0 /
                   ((double)(out->last_pcr - out->first_pcr) / 27000000.0);

    {
        double reg_a = 0.0;
        double reg_b = 0.0;
        int reg_ok = 0;
        pcr_collect_ctx_t collect_ctx = {.pcr_pid = out->pcr_pid, .samples = NULL, .count = 0, .capacity = 0};
        rewind(file);
        if (!walk_ts_packets(file, pcr_collect_handler, &collect_ctx)) {
            free(collect_ctx.samples);
            free_psi_result(&out->psi);
            return 1;
        }
        if (collect_ctx.count >= 2u && pcr_fit_linear(collect_ctx.samples, collect_ctx.count, &reg_a, &reg_b)) {
            reg_ok = 1;
        }
        (void)reg_a; /* intercept only needed for fit; intervals use slope reg_b */
        free(collect_ctx.samples);
        collect_ctx.samples = NULL;
        if (!reg_ok) {
            free_psi_result(&out->psi);
            return 1;
        }

        jitter_preview_ctx_t preview_ctx;
        rewind(file);
        preview_ctx.pcr_pid = out->pcr_pid;
        preview_ctx.prev_pcr = 0;
        preview_ctx.prev_byte_offset = 0;
        (void)reg_a;
        preview_ctx.reg_b = reg_b;
        preview_ctx.reg_valid = 1;
        preview_ctx.first_found = 0;
        preview_ctx.rows = NULL;
        preview_ctx.row_count = 0;
        preview_ctx.row_capacity = 0;
        if (!walk_ts_packets(file, jitter_preview_handler, &preview_ctx)) {
            free(preview_ctx.rows);
            free_psi_result(&out->psi);
            return 1;
        }
        out->preview_rows = preview_ctx.rows;
        out->preview_row_count = preview_ctx.row_count;
    }

    return 0;
}

/* Release heap allocations inside ts_jitter_result_t. */
void free_jitter_result(ts_jitter_result_t* result) {
    if (result == NULL) {
        return;
    }
    free(result->preview_rows);
    result->preview_rows = NULL;
    result->preview_row_count = 0;
    free_psi_result(&result->psi);
}

/* ============================================================================
 * CLI runner wrappers
 * ========================================================================== */
int run_mode_packets(FILE* file) {
    size_t sync_loss_count = 0;
    ts_validate_result_t validate_result;
    if (analyze_validate(file, &validate_result) == 0) {
        sync_loss_count = validation_summary_sync_errors();
        free_validate_result(&validate_result);
    }

    ts_packets_result_t result;
    if (analyze_packets(file, &result) != 0) {
        return 1;
    }
    if (sync_loss_count > 0u) {
        printf("WARNING: %zu sync loss event(s) detected. Decoded packet fields may be unreliable.\n", sync_loss_count);
        printf("         Input contract is aligned 188-byte TS from byte 0 (no resync).\n\n");
    }
    print_pid_ratio_header(&result.pid_list, (long)result.packet_count);
    for (size_t i = 0; i < result.packet_count; i++) {
        print_packet_header(&result.packets[i], i);
    }
    free_packets_result(&result);
    return 0;
}

int run_mode_psi(FILE* file) {
    ts_psi_result_t result;
    if (analyze_psi(file, &result) != 0) {
        return 1;
    }
    print_ts_report(&result.pat, result.pmt_table, &result.pid_list);
    free_psi_result(&result);
    return 0;
}

int run_mode_validate(FILE* file, const char* path) {
    ts_validate_result_t result;
    if (analyze_validate(file, &result) != 0) {
        return 1;
    }
    printf("\n");
    printf("┌────────────────────────────────────────────────── Validation\n");
    validation_summary_print(stdout);
    {
        int tmp = 0;
        report_undefined_pids(&result.psi.pat, result.psi.pmt_table, result.psi.pmt_table_capacity, &result.psi.pid_list, &tmp);
    }
    if (!result.errors_found) {
        printf("│  No errors in %s\n", path);
    }
    printf("└──────────────────────────────────────────────────\n");
    free_validate_result(&result);
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
    ts_jitter_result_t result;
    if (analyze_jitter(file, &result) != 0) {
        printf("Unable to determine PMT/PCR PID.\n");
        return 1;
    }
    printf("PCR PID: 0x%04X (selected, %zu samples)\n", result.pcr_pid, result.pcr_sample_total);
    printf("First PCR: %llu, Last PCR: %llu\n",
           (unsigned long long)result.first_pcr, (unsigned long long)result.last_pcr);
    printf("First byte offset: %zu, Last byte offset: %zu\n", result.first_byte_offset, result.last_byte_offset);
    printf("Bitrate: %f bps\n", result.bitrate);
    printf("Jitter model: per-interval Δ vs linear PCR×byte fit (least squares on all PCR samples)\n");
    printf("%zu rows\n", result.preview_row_count);
    print_jitter_header();
    {
        for (size_t i = 0; i < result.preview_row_count; i++) {
            print_jitter_row(result.preview_rows[i].packet_index,
                             result.preview_rows[i].actual_ms,
                             result.preview_rows[i].actual_valid,
                             result.preview_rows[i].ideal_ms,
                             result.preview_rows[i].ideal_valid,
                             result.preview_rows[i].offset_ms,
                             result.preview_rows[i].offset_valid);
        }
    }
    printf("└───────────────────────────────────────────────────────────────────────────────────────\n");
    free_jitter_result(&result);
    return 0;
}

int run_mode_pes(FILE* file) {
    ts_pes_result_t result;
    if (analyze_pes(file, &result) != 0) {
        return 1;
    }
    print_pes_streams_summary(result.psi.pmt_table, result.psi.pmt_table_capacity);
    print_pes_packet_list_report(&result.pes_packet_table);
    free_pes_result(&result);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include <limits.h>
#include "packet.h"
#include "parser.h"
#include "utils.h"

#define PACKET_SIZE 188

static int compare_double_asc(const void* a, const void* b) {
    const double da = *(const double*)a;
    const double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

/* Linear-interpolated percentile from sorted ascending values. q in [0, 1]. */
static double percentile_sorted(const double* sorted, size_t n, double q) {
    if (sorted == NULL || n == 0) {
        return 0.0;
    }
    if (q <= 0.0) {
        return sorted[0];
    }
    if (q >= 1.0) {
        return sorted[n - 1];
    }
    {
        const double pos = q * (double)(n - 1);
        const size_t lo = (size_t)pos;
        const size_t hi = (lo + 1 < n) ? (lo + 1) : lo;
        const double w = pos - (double)lo;
        return sorted[lo] * (1.0 - w) + sorted[hi] * w;
    }
}

static void moving_average_centered(const double* in, double* out, size_t n, size_t window) {
    if (in == NULL || out == NULL || n == 0) {
        return;
    }
    if (window == 0) {
        window = 1;
    }
    if ((window % 2u) == 0u) {
        window += 1u;
    }
    {
        const size_t half = window / 2u;
        for (size_t i = 0; i < n; i++) {
            const size_t lo = (i > half) ? (i - half) : 0u;
            const size_t hi = ((i + half + 1u) < n) ? (i + half + 1u) : n;
            double sum = 0.0;
            size_t cnt = 0;
            for (size_t k = lo; k < hi; k++) {
                sum += in[k];
                cnt++;
            }
            out[i] = (cnt > 0u) ? (sum / (double)cnt) : 0.0;
        }
    }
}

static void print_pcr_sample_preview(const size_t* pkt_idx, const double* t_pcr, size_t n) {
    const size_t preview = 10;
    if (pkt_idx == NULL || t_pcr == NULL || n == 0) {
        return;
    }
    printf("PCR samples (packet -> seconds):\n");
    if (n <= preview * 2) {
        for (size_t i = 0; i < n; i++) {
            printf("  %zu -> %.6f\n", pkt_idx[i], t_pcr[i]);
        }
        return;
    }
    for (size_t i = 0; i < preview; i++) {
        printf("  %zu -> %.6f\n", pkt_idx[i], t_pcr[i]);
    }
    printf("  ... (%zu samples omitted) ...\n", n - preview * 2);
    for (size_t i = n - preview; i < n; i++) {
        printf("  %zu -> %.6f\n", pkt_idx[i], t_pcr[i]);
    }
}

static void print_offset_sparkline_ms(const char* title, const double* offsets_sec, size_t n) {
    static const char levels[] = " .:-=+*#%@";
    const size_t levels_count = sizeof(levels) - 1; /* excludes '\0' */
    const size_t width = 80;
    double max_abs = 0.0;

    if (offsets_sec == NULL || n == 0) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        const double v = fabs(offsets_sec[i]);
        if (v > max_abs) max_abs = v;
    }

    printf("\n%s\n  ", title);
    if (max_abs <= 0.0) {
        for (size_t i = 0; i < width; i++) {
            putchar(levels[0]);
        }
        printf("\n");
        return;
    }

    for (size_t col = 0; col < width; col++) {
        const size_t start = (col * n) / width;
        const size_t end = ((col + 1) * n) / width;
        const size_t to = (end > start) ? end : (start + 1);
        double local_peak = 0.0;
        for (size_t i = start; i < to && i < n; i++) {
            const double v = fabs(offsets_sec[i]);
            if (v > local_peak) local_peak = v;
        }
        {
            const double ratio = local_peak / max_abs;
            size_t idx = (size_t)llround(ratio * (double)(levels_count - 1));
            if (idx >= levels_count) idx = levels_count - 1;
            putchar(levels[idx]);
        }
    }
    printf("\n");
}

static void print_abs_offset_histogram_ms(const double* offsets_sec, size_t n) {
    const size_t bins = 20;
    const size_t bar_width = 44;
    size_t counts[bins];
    size_t max_count = 0;
    double max_abs_ms = 0.0;

    if (offsets_sec == NULL || n == 0) {
        return;
    }
    for (size_t i = 0; i < bins; i++) {
        counts[i] = 0;
    }
    for (size_t i = 0; i < n; i++) {
        const double v_ms = fabs(offsets_sec[i]) * 1000.0;
        if (v_ms > max_abs_ms) max_abs_ms = v_ms;
    }
    if (max_abs_ms <= 0.0) {
        max_abs_ms = 1.0;
    }

    for (size_t i = 0; i < n; i++) {
        const double v_ms = fabs(offsets_sec[i]) * 1000.0;
        size_t b = (size_t)((v_ms / max_abs_ms) * (double)bins);
        if (b >= bins) b = bins - 1;
        counts[b]++;
        if (counts[b] > max_count) max_count = counts[b];
    }

    printf("\n|offset| histogram (ms):\n");
    for (size_t b = 0; b < bins; b++) {
        const double lo = ((double)b / (double)bins) * max_abs_ms;
        const double hi = ((double)(b + 1) / (double)bins) * max_abs_ms;
        size_t chars = 0;
        if (max_count > 0) {
            chars = (counts[b] * bar_width) / max_count;
        }
        printf("  %8.3f - %8.3f | ", lo, hi);
        for (size_t c = 0; c < chars; c++) putchar('#');
        printf(" (%zu)\n", counts[b]);
    }
}

static void usage(const char* prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s --packets <file>     Print header for every packet, with PID ratio stats (pipe to less)\n", prog);
    fprintf(stderr, "  %s --psi-analyze <file>  Print PAT, PMT, and descriptor values\n", prog);
    fprintf(stderr, "  %s --validate <file>     Report CC errors, sync loss, undefined PIDs; or 'No errors in <file>'\n", prog);
    fprintf(stderr, "  %s --hexdump <file> <packet_number> Print hexdump of packet at given number\n", prog);
    fprintf(stderr, "  %s --jitter-test <file>   Print jitter metrics + CLI visualization\n", prog);
}

int main(int argc, char* argv[]) {
    const char* mode = (argc >= 2) ? argv[1] : "";
    int mode_packets   = (strcmp(mode, "--packets") == 0);
    int mode_psi       = (strcmp(mode, "--psi-analyze") == 0);
    int mode_validate  = (strcmp(mode, "--validate") == 0);
    int mode_hexdump   = (strcmp(mode, "--hexdump") == 0);
    int mode_jitter_test = (strcmp(mode, "--jitter-test") == 0);

    if (mode_hexdump) {
        if (argc != 4) {
            usage(argv[0]);
            return 1;
        }
    } else if (argc != 3) {
        usage(argv[0]);
        return 1;
    }

    if (!mode_packets && !mode_psi && !mode_validate && !mode_hexdump && !mode_jitter_test) {
        usage(argv[0]);
        return 1;
    }

    const char* path = argv[2];
    FILE* file = fopen(path, "rb");
    if (!file) {
        perror(path);
        return 1;
    }

    uint8_t buffer[PACKET_SIZE];
    long packet_count = 0;
    pid_count_list_t list;
    pid_count_list_init(&list);

    if (mode_packets) {
        /* Pass 1: count packets per PID */
        while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
            ts_packet_t packet;
            parse_ts_packet(buffer, PACKET_SIZE, &packet);
            pid_count_list_update(&list, packet.pid);
            packet_count++;
        }
        print_pid_ratio_header(&list, packet_count);
        rewind(file);
        /* Pass 2: print every packet header */
        while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
            ts_packet_t packet;
            parse_ts_packet(buffer, PACKET_SIZE, &packet);
            print_packet_header(&packet);
        }
        pid_count_list_cleanup(&list);
        fclose(file);
        return 0;
    }

    if (mode_psi) {
        pat_table_t current_pat;
        pat_table_init(&current_pat);
        pmt_t* pmt_table = NULL;
        size_t pmt_table_capacity = 0;
        ts_cc_init();

        while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
            ts_packet_t packet;
            parse_ts_packet(buffer, PACKET_SIZE, &packet);
            ts_cc_check(&packet, NULL);  /* don't print errors in psi-analyze */
            process_packet_psi(buffer, PACKET_SIZE, &packet, &current_pat, &pmt_table, &pmt_table_capacity, &list);
            ts_cc_update(&packet);
            packet_count++;
        }
        print_ts_report(&current_pat, pmt_table, &list);
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        fclose(file);
        return 0;
    }

    /* mode_validate */
    if (mode_validate) {
        pat_table_t current_pat;
        pat_table_init(&current_pat);
        pmt_t* pmt_table = NULL;
        size_t pmt_table_capacity = 0;
        int errors_found = 0;
        ts_cc_init();

        while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
            ts_packet_t packet;
            parse_ts_packet(buffer, PACKET_SIZE, &packet);
            if (ts_cc_check(&packet, stdout))
                errors_found = 1;
            process_packet_psi(buffer, PACKET_SIZE, &packet, &current_pat, &pmt_table, &pmt_table_capacity, &list);
            ts_cc_update(&packet);
            packet_count++;
        }
        report_undefined_pids(&current_pat, pmt_table, pmt_table_capacity, &list, &errors_found);
        if (!errors_found)
            printf("No errors in %s\n", path);
        ts_state_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
        fclose(file);
        return 0;
    }

    if (mode_hexdump) {
        long packet_number = atol(argv[3]);
        if (packet_number < 0) {
            fprintf(stderr, "packet_number must be >= 0\n");
            fclose(file);
            return 1;
        }
        if (fseek(file, packet_number * (long)PACKET_SIZE, SEEK_SET) != 0) {
            perror("fseek");
            fclose(file);
            return 1;
        }
        size_t n = fread(buffer, 1, PACKET_SIZE, file);
        if (n > 0 && buffer[0] != 0x47) {
            fprintf(stderr, "Warning: first byte is 0x%02X (expected TS sync 0x47). Wrong file or packet index?\n", buffer[0]);
        }
        print_hexdump(buffer, n);
        fclose(file);
        return 0;
    }

    if (mode_jitter_test) {
    
    }
    return 0;
}

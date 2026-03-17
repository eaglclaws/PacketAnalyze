#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ts_pipeline.h"

static void usage(const char* prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s --packets <file>     Print header for every packet, with PID ratio stats (pipe to less)\n", prog);
    fprintf(stderr, "  %s --psi-analyze <file>  Print PAT, PMT, and descriptor values\n", prog);
    fprintf(stderr, "  %s --validate <file>     Report CC errors, sync loss, undefined PIDs; or 'No errors in <file>'\n", prog);
    fprintf(stderr, "  %s --hexdump <file> <packet_number> Print hexdump of packet at given number\n", prog);
    fprintf(stderr, "  %s --jitter-test <file>   Print jitter metrics + CLI visualization\n", prog);
    fprintf(stderr, "  %s --pes <file>          Print PES data in program elements\n", prog);
}

int main(int argc, char* argv[]) {
    const char* mode = (argc >= 2) ? argv[1] : "";
    int mode_packets = (strcmp(mode, "--packets") == 0);
    int mode_psi = (strcmp(mode, "--psi-analyze") == 0);
    int mode_validate = (strcmp(mode, "--validate") == 0);
    int mode_hexdump = (strcmp(mode, "--hexdump") == 0);
    int mode_jitter_test = (strcmp(mode, "--jitter-test") == 0);
    int mode_pes = (strcmp(mode, "--pes") == 0);

    if (mode_hexdump) {
        if (argc != 4) {
            usage(argv[0]);
            return 1;
        }
    } else if (argc != 3) {
        usage(argv[0]);
        return 1;
    }

    if (!mode_packets && !mode_psi && !mode_validate && !mode_hexdump && !mode_jitter_test && !mode_pes) {
        usage(argv[0]);
        return 1;
    }

    {
        const char* path = argv[2];
        FILE* file = fopen(path, "rb");
        int rc = 0;
        if (!file) {
            perror(path);
            return 1;
        }
        if (mode_packets) {
            rc = run_mode_packets(file);
        } else if (mode_psi) {
            rc = run_mode_psi(file);
        } else if (mode_validate) {
            rc = run_mode_validate(file, path);
        } else if (mode_hexdump) {
            long packet_number = atol(argv[3]);
            rc = run_mode_hexdump(file, packet_number);
        } else if (mode_jitter_test) {
            rc = run_mode_jitter_test(file);
        } else if (mode_pes) {
            rc = run_mode_pes(file);
        }
        fclose(file);
        return rc;
    }
}

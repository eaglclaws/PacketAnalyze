#ifndef TS_PIPELINE_H
#define TS_PIPELINE_H

#include <stdio.h>

int run_mode_packets(FILE* file);
int run_mode_psi(FILE* file);
int run_mode_validate(FILE* file, const char* path);
int run_mode_hexdump(FILE* file, long packet_number);
int run_mode_jitter_test(FILE* file);
int run_mode_pes(FILE* file);

#endif // TS_PIPELINE_H

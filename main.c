#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "packet.h"
#include "parser.h"
#include "utils.h"

#define MAX_PID 8192
#define PACKET_SIZE 188

#define PID_PAT 0x0000

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    FILE* file = fopen(argv[1], "rb");
    if (file != NULL) printf("Opened file\n");
    uint8_t buffer[PACKET_SIZE];
    long packet_count = 0;
    pat_table_t current_pat;
    current_pat.program_count = 0;
    current_pat.capacity = 2;
    current_pat.programs = (pat_program_t*)malloc(sizeof(pat_program_t) * current_pat.capacity);
    pid_count_list_t list;
    pid_count_list_init(&list);
    while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
        ts_packet_t packet;
        parse_ts_packet(buffer, PACKET_SIZE, &packet);
        pid_count_list_update(&list, packet.pid);
        packet_count++;
    }
    printf("%ld packets\n", packet_count);
    for (size_t i = 0; i < list.count; i++) {
        printf("PID: 0x%04X = %zu\n", list.pids[i].pid, list.pids[i].count);
    }
    fclose(file);
    return 0;
}

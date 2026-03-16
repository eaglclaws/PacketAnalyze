#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "parser.h"
#include "utils.h"

#define PACKET_SIZE 188

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    FILE* file = fopen(argv[1], "rb");
    if (file != NULL)
        printf("Opened file\n");
    uint8_t buffer[PACKET_SIZE];
    long packet_count = 0;
    pat_table_t current_pat;
    pat_table_init(&current_pat);
    pmt_t* pmt_table = NULL;
    size_t pmt_table_capacity = 0;
    pid_count_list_t list;
    pid_count_list_init(&list);
    int printed_header = 0;
    ts_cc_init();

    while (fread(buffer, 1, PACKET_SIZE, file) == PACKET_SIZE) {
        ts_packet_t packet;
        parse_ts_packet(buffer, PACKET_SIZE, &packet);
        if (packet.adaptation_field_control == 3 && !printed_header) {
            print_packet_header(&packet);
            printed_header = 1;
        }
        ts_cc_check(&packet);
        process_packet_psi(buffer, PACKET_SIZE, &packet, &current_pat, &pmt_table, &pmt_table_capacity, &list);
        ts_cc_update(&packet);
        packet_count++;
    }

    print_ts_report(&current_pat, pmt_table, &list, packet_count);
    ts_cleanup(&current_pat, pmt_table, pmt_table_capacity, &list);
    fclose(file);
    return 0;
}

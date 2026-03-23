#ifndef GUI_PACKET_WIDGETS_H
#define GUI_PACKET_WIDGETS_H

#include <stddef.h>
#include <stdint.h>
#include <gtk/gtk.h>
#include "packet.h"
#include "parser.h"

int gui_path_is_ts_file(const char* path);

GtkWidget* gui_create_popup_content_box(void);
GtkWidget* gui_create_popup_header(const char* title_text, const char* subtitle_text);
void gui_update_stream_overview(GtkWidget* title_widget, GtkWidget* meta_widget, const char* path,
                                size_t packet_count, size_t observed_pid_count, size_t program_count);
GtkWidget* gui_pes_packet_detail_grid(const pes_packet_t* p, size_t index);

void gui_packet_summary_string(const ts_packet_t* p, size_t index, char* buf, size_t buf_size);
char* gui_packet_psi_summary(const uint8_t* raw, const ts_packet_t* p, size_t buffer_len, const pat_table_t* pat);
GtkWidget* gui_packet_detail_grid(const ts_packet_t* p, size_t index, const char* psi_summary);

void gui_expander_set_animated_child(GtkExpander* exp, GtkWidget* child, unsigned int duration_ms);

#endif

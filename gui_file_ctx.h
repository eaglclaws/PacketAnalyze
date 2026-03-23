#ifndef GUI_FILE_CTX_H
#define GUI_FILE_CTX_H

#include <stddef.h>
#include <gtk/gtk.h>
#include "ts_pipeline.h"

typedef struct {
    GtkWindow* window;
    GtkBox* packet_list_box;
    GtkScrolledWindow* packet_scrolled;
    GtkWidget* content_stack;
    GtkWidget* stream_overview_title;
    GtkWidget* stream_overview_meta;
    GtkWidget* stats_btn;
    GtkWidget* validate_btn;
    GtkWidget* jitter_btn;
    GtkWidget* pes_info_btn;
    GtkWidget* loading_label;
    char* current_path;
    ts_packets_result_t pending_packets;
    char** pending_psi_summaries;
    size_t pending_render_index;
    int rendering_chunk;
    double last_scroll_value;
    int has_last_scroll_value;
} gui_file_ctx_t;

#endif

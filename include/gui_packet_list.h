#ifndef GUI_PACKET_LIST_H
#define GUI_PACKET_LIST_H

#include <stddef.h>
#include <gtk/gtk.h>
#include "gui_file_ctx.h"

void gui_packet_list_clear(gui_file_ctx_t* ctx);
void gui_packet_list_free_pending(gui_file_ctx_t* ctx);
void gui_packet_list_append_rows(gui_file_ctx_t* ctx, size_t max_rows,
                                 GCallback right_click_cb, gpointer right_click_user_data,
                                 unsigned int reveal_duration_ms);
void gui_packet_list_on_scroll_changed(gui_file_ctx_t* ctx, GtkAdjustment* adjustment, size_t chunk_size,
                                       GCallback right_click_cb, gpointer right_click_user_data,
                                       unsigned int reveal_duration_ms);
void gui_packet_list_reset_scroll_tracking(gui_file_ctx_t* ctx);

#endif

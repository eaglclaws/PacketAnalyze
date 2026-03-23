#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "gui_packet_list.h"
#include "gui_packet_widgets.h"

static void maybe_append_next_chunk(gui_file_ctx_t* ctx, size_t chunk_size,
                                    GCallback right_click_cb, gpointer right_click_user_data,
                                    unsigned int reveal_duration_ms);

void gui_packet_list_clear(gui_file_ctx_t* ctx) {
    while (1) {
        GtkWidget* child = gtk_widget_get_first_child(GTK_WIDGET(ctx->packet_list_box));
        if (!child) break;
        gtk_box_remove(ctx->packet_list_box, child);
    }
}

void gui_packet_list_free_pending(gui_file_ctx_t* ctx) {
    if (ctx->pending_psi_summaries) {
        for (size_t i = ctx->pending_render_index; i < ctx->pending_packets.packet_count; i++) {
            if (ctx->pending_psi_summaries[i]) free(ctx->pending_psi_summaries[i]);
        }
        free(ctx->pending_psi_summaries);
        ctx->pending_psi_summaries = NULL;
    }
    if (ctx->pending_packets.packets) {
        free_packets_result(&ctx->pending_packets);
    } else {
        memset(&ctx->pending_packets, 0, sizeof(ctx->pending_packets));
    }
    ctx->pending_render_index = 0;
}

void gui_packet_list_append_rows(gui_file_ctx_t* ctx, size_t max_rows,
                                 GCallback right_click_cb, gpointer right_click_user_data,
                                 unsigned int reveal_duration_ms) {
    ctx->rendering_chunk = 1;
    size_t count = ctx->pending_packets.packet_count;
    size_t end = ctx->pending_render_index + max_rows;
    if (end > count) end = count;
    for (size_t i = ctx->pending_render_index; i < end; i++) {
        const ts_packet_t* p = &ctx->pending_packets.packets[i];
        char summary[128];
        gui_packet_summary_string(p, i, summary, sizeof summary);
        GtkWidget* row_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_add_css_class(row_box, "packet-row");
        GtkWidget* exp = gtk_expander_new(summary);
        gtk_widget_add_css_class(exp, "packet-row-expander");
        gtk_widget_set_focusable(exp, FALSE);
        g_object_set_data(G_OBJECT(exp), "accordion-parent", GTK_WIDGET(ctx->packet_list_box));
        g_object_set_data(G_OBJECT(exp), "packet-index", GINT_TO_POINTER((int)i + 1));
        GtkGesture* right_click = GTK_GESTURE(gtk_gesture_click_new());
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(right_click), 3);
        g_signal_connect(right_click, "pressed", right_click_cb, right_click_user_data);
        gtk_widget_add_controller(GTK_WIDGET(exp), GTK_EVENT_CONTROLLER(right_click));
        GtkWidget* summary_label = gtk_expander_get_label_widget(GTK_EXPANDER(exp));
        if (summary_label)
            gtk_widget_add_css_class(summary_label, "packet-summary");
        const char* psi_line = ctx->pending_psi_summaries ? ctx->pending_psi_summaries[i] : NULL;
        GtkWidget* detail_grid = gui_packet_detail_grid(p, i, psi_line);
        gtk_widget_set_margin_top(detail_grid, 8);
        gui_expander_set_animated_child(GTK_EXPANDER(exp), detail_grid, reveal_duration_ms);
        gtk_box_append(GTK_BOX(row_box), exp);
        gtk_box_append(ctx->packet_list_box, row_box);
        if (ctx->pending_psi_summaries && ctx->pending_psi_summaries[i]) {
            free(ctx->pending_psi_summaries[i]);
            ctx->pending_psi_summaries[i] = NULL;
        }
    }
    ctx->pending_render_index = end;
    ctx->rendering_chunk = 0;

    if (ctx->pending_render_index >= count) {
        gui_packet_list_free_pending(ctx);
        return;
    }
}

static void maybe_append_next_chunk(gui_file_ctx_t* ctx, size_t chunk_size,
                                    GCallback right_click_cb, gpointer right_click_user_data,
                                    unsigned int reveal_duration_ms) {
    if (!ctx || ctx->rendering_chunk) return;
    if (!ctx->packet_scrolled) return;
    if (ctx->pending_render_index >= ctx->pending_packets.packet_count) return;

    GtkAdjustment* adj = gtk_scrolled_window_get_vadjustment(ctx->packet_scrolled);
    if (!adj) return;
    double value = gtk_adjustment_get_value(adj);
    double page = gtk_adjustment_get_page_size(adj);
    double upper = gtk_adjustment_get_upper(adj);
    if (value <= 0.0 || upper <= page + 1.0) return;
    double remaining = upper - (value + page);

    if (remaining < 80.0) {
        gui_packet_list_append_rows(ctx, chunk_size, right_click_cb, right_click_user_data, reveal_duration_ms);
    }
}

void gui_packet_list_on_scroll_changed(gui_file_ctx_t* ctx, GtkAdjustment* adjustment, size_t chunk_size,
                                       GCallback right_click_cb, gpointer right_click_user_data,
                                       unsigned int reveal_duration_ms) {
    double value = gtk_adjustment_get_value(adjustment);
    if (!ctx->has_last_scroll_value) {
        ctx->last_scroll_value = value;
        ctx->has_last_scroll_value = 1;
        return;
    }
    double prev = ctx->last_scroll_value;
    ctx->last_scroll_value = value;
    if (value <= prev + 0.5) return;
    maybe_append_next_chunk(ctx, chunk_size, right_click_cb, right_click_user_data, reveal_duration_ms);
}

void gui_packet_list_reset_scroll_tracking(gui_file_ctx_t* ctx) {
    ctx->has_last_scroll_value = 0;
    ctx->last_scroll_value = 0.0;
}

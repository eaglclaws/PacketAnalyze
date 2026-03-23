#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>
#include "gui_entry.h"
#include "gui_dialogs.h"
#include "gui_file_ctx.h"
#include "gui_packet_list.h"
#include "gui_packet_widgets.h"
#include "packet.h"
#include "parser.h"
#include "ts_pipeline.h"
#include "utils.h"

/* PES result for the PES Info dialog; freed when dialog is destroyed. */
static ts_pes_result_t* s_pes_for_dialog = NULL;

#define EXPANDER_REVEAL_DURATION_MS 200
static void on_packet_row_right_click(GtkGestureClick* gesture, int n_press, double x, double y, gpointer user_data);
#define PACKET_RENDER_CHUNK_SIZE 400u

static void pes_dialog_destroyed(GtkWidget* dialog, gpointer user_data) {
    (void)dialog;
    (void)user_data;
    if (s_pes_for_dialog) {
        free_pes_result(s_pes_for_dialog);
        free(s_pes_for_dialog);
        s_pes_for_dialog = NULL;
    }
}


/* Result of background file load; passed to main thread to apply. */
typedef struct {
    ts_packets_result_t result_data;
    char** psi_summaries;
    size_t program_count;
    size_t sync_loss_count;
    char* path;
    gui_file_ctx_t* ctx;
    int success;
} open_file_result_t;


static gboolean main_window_deferred_destroy_cb(gpointer user_data) {
    GtkWindow* win = GTK_WINDOW(user_data);
    gtk_window_destroy(win);
    return G_SOURCE_REMOVE;
}

static gboolean on_main_window_close_request(GtkWindow* win, gpointer user_data) {
    (void)user_data;
    /* Hide immediately for responsive UX, then run normal destroy on idle. */
    gtk_widget_set_visible(GTK_WIDGET(win), FALSE);
    g_idle_add(main_window_deferred_destroy_cb, win);
    return TRUE;
}


static void on_stats_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    gui_show_stats_popup(ctx->window, ctx->current_path);
}

static void on_jitter_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    gui_show_jitter_popup(ctx->window, ctx->current_path);
}


static void on_pes_info_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    if (!ctx->current_path) return;
    FILE* f = fopen(ctx->current_path, "rb");
    if (!f) return;
    ts_pes_result_t* result = (ts_pes_result_t*)calloc(1, sizeof(ts_pes_result_t));
    if (!result) { fclose(f); return; }
    if (analyze_pes(f, result) != 0) {
        free(result);
        fclose(f);
        return;
    }
    fclose(f);
    if (s_pes_for_dialog) {
        free_pes_result(s_pes_for_dialog);
        free(s_pes_for_dialog);
    }
    s_pes_for_dialog = result;

    GtkWidget* dialog = gtk_window_new();
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), ctx->window);
    gtk_window_set_title(GTK_WINDOW(dialog), "PES Info");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 520, 480);
    g_signal_connect(dialog, "destroy", G_CALLBACK(pes_dialog_destroyed), NULL);

    GtkWidget* vbox = gui_create_popup_content_box();
    {
        char subtitle[160];
        snprintf(subtitle, sizeof subtitle, "%zu PID group%s detected",
                 result->pes_packet_table.count, result->pes_packet_table.count == 1 ? "" : "s");
        GtkWidget* header = gui_create_popup_header("PES Info", subtitle);
        gtk_box_append(GTK_BOX(vbox), header);
    }

    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_widget_add_css_class(scrolled, "popup-card");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled), 320);
    gtk_widget_set_hexpand(scrolled, TRUE);
    gtk_widget_set_vexpand(scrolled, TRUE);
    GtkWidget* list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    for (size_t i = 0; i < result->pes_packet_table.count; i++) {
        const pes_packet_list_t* plist = &result->pes_packet_table.lists[i];
        char summary[64];
        snprintf(summary, sizeof summary, "PID 0x%04X  ·  %zu PES packet%s",
                 (unsigned)plist->pid, plist->count, plist->count == 1 ? "" : "s");
        GtkWidget* row_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_add_css_class(row_box, "packet-row");
        GtkWidget* exp = gtk_expander_new(summary);
        gtk_widget_add_css_class(exp, "packet-row-expander");
        g_object_set_data(G_OBJECT(exp), "accordion-parent", list_box);
        GtkWidget* summary_label = gtk_expander_get_label_widget(GTK_EXPANDER(exp));
        if (summary_label)
            gtk_widget_add_css_class(summary_label, "packet-summary");
        GtkWidget* inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
        for (size_t j = 0; j < plist->count; j++) {
            const pes_packet_t* pp = &plist->packets[j];
            char row_summary[80];
            snprintf(row_summary, sizeof row_summary, "PES packet %zu  ·  Stream 0x%02X  ·  %u bytes",
                (size_t)j, (unsigned)pp->stream_id, (unsigned)pp->packet_length);
            GtkWidget* sub_row = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
            gtk_widget_add_css_class(sub_row, "packet-row");
            GtkWidget* sub_exp = gtk_expander_new(row_summary);
            gtk_widget_add_css_class(sub_exp, "packet-row-expander");
            g_object_set_data(G_OBJECT(sub_exp), "accordion-parent", inner);
            GtkWidget* sub_label = gtk_expander_get_label_widget(GTK_EXPANDER(sub_exp));
            if (sub_label)
                gtk_widget_add_css_class(sub_label, "packet-summary");
            GtkWidget* pg = gui_pes_packet_detail_grid(pp, j);
            gtk_widget_set_margin_top(pg, 8);
            gui_expander_set_animated_child(GTK_EXPANDER(sub_exp), pg, EXPANDER_REVEAL_DURATION_MS);
            gtk_box_append(GTK_BOX(sub_row), sub_exp);
            gtk_box_append(GTK_BOX(inner), sub_row);
        }
        gui_expander_set_animated_child(GTK_EXPANDER(exp), inner, EXPANDER_REVEAL_DURATION_MS);
        gtk_box_append(GTK_BOX(row_box), exp);
        gtk_box_append(GTK_BOX(list_box), row_box);
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), list_box);
    gtk_box_append(GTK_BOX(vbox), scrolled);
    GtkWidget* close_btn = gtk_button_new_with_label("Close");
    gtk_widget_add_css_class(close_btn, "popup-close-btn");
    g_signal_connect_swapped(close_btn, "clicked", G_CALLBACK(gtk_window_destroy), dialog);
    gtk_box_append(GTK_BOX(vbox), close_btn);
    gtk_window_set_child(GTK_WINDOW(dialog), vbox);
    gtk_widget_set_focusable(close_btn, TRUE);
    gtk_window_set_focus(GTK_WINDOW(dialog), close_btn);
    gtk_window_present(GTK_WINDOW(dialog));
}

static void on_validate_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    gui_show_validation_popup(ctx->window, ctx->current_path);
}

static void on_packet_row_right_click(GtkGestureClick* gesture, int n_press, double x, double y, gpointer user_data) {
    (void)n_press;
    (void)x;
    (void)y;
    if (gtk_gesture_single_get_current_button(GTK_GESTURE_SINGLE(gesture)) != 3)
        return;
    GtkWidget* expander = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(gesture));
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    if (!ctx->current_path) return;
    gpointer idx_p = g_object_get_data(G_OBJECT(expander), "packet-index");
    if (idx_p == NULL) return;
    size_t packet_index = (size_t)(GPOINTER_TO_INT(idx_p) - 1);
    gui_show_hexdump_popup(ctx->current_path, packet_index, ctx->window);
}

static void on_packet_list_scroll_changed(GtkAdjustment* adjustment, gpointer user_data) {
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    gui_packet_list_on_scroll_changed(ctx, adjustment, PACKET_RENDER_CHUNK_SIZE,
                                      G_CALLBACK(on_packet_row_right_click), ctx,
                                      EXPANDER_REVEAL_DURATION_MS);
}

static gboolean apply_open_result(gpointer data) {
    open_file_result_t* r = (open_file_result_t*)data;
    if (!r) return G_SOURCE_REMOVE;
    gui_file_ctx_t* ctx = r->ctx;

    if (!r->success) {
        gtk_stack_set_visible_child_name(GTK_STACK(ctx->content_stack), "empty");
        if (r->path) g_free(r->path);
        free(r);
        return G_SOURCE_REMOVE;
    }

    gui_packet_list_clear(ctx);
    gui_packet_list_free_pending(ctx);
    if (ctx->packet_scrolled) {
        GtkAdjustment* adj = gtk_scrolled_window_get_vadjustment(ctx->packet_scrolled);
        if (adj) {
            gtk_adjustment_set_value(adj, gtk_adjustment_get_lower(adj));
        }
    }

    ctx->pending_packets = r->result_data;
    memset(&r->result_data, 0, sizeof(r->result_data));
    ctx->pending_psi_summaries = r->psi_summaries;
    r->psi_summaries = NULL;
    ctx->pending_render_index = 0;
    gui_packet_list_reset_scroll_tracking(ctx);
    gui_packet_list_append_rows(ctx, PACKET_RENDER_CHUNK_SIZE,
                                G_CALLBACK(on_packet_row_right_click), ctx,
                                EXPANDER_REVEAL_DURATION_MS);

    gui_update_stream_overview(ctx->stream_overview_title, ctx->stream_overview_meta, r->path,
                               ctx->pending_packets.packet_count, ctx->pending_packets.pid_list.count, r->program_count);

    if (ctx->current_path) g_free(ctx->current_path);
    ctx->current_path = r->path;
    r->path = NULL;
    gtk_widget_set_visible(ctx->stats_btn, TRUE);
    gtk_widget_set_visible(ctx->validate_btn, TRUE);
    gtk_widget_set_visible(ctx->jitter_btn, TRUE);
    gtk_widget_set_visible(ctx->pes_info_btn, TRUE);
    gtk_stack_set_visible_child_name(GTK_STACK(ctx->content_stack), "list");
    if (r->sync_loss_count > 0u) {
        GtkAlertDialog* alert = gtk_alert_dialog_new("Sync loss detected in input stream.");
        char detail[256];
        snprintf(detail, sizeof detail,
                 "%zu sync loss event(s) were detected.\n"
                 "Decoded packet fields may be unreliable because the parser assumes aligned 188-byte packets (no resync).",
                 r->sync_loss_count);
        gtk_alert_dialog_set_detail(alert, detail);
        gtk_alert_dialog_choose(alert, ctx->window, NULL, NULL, NULL);
        g_object_unref(alert);
    }
    free(r);
    return G_SOURCE_REMOVE;
}

typedef struct {
    char* path;
    gui_file_ctx_t* ctx;
} load_file_data_t;

static gpointer load_file_worker(gpointer data) {
    load_file_data_t* ld = (load_file_data_t*)data;
    open_file_result_t* r = (open_file_result_t*)malloc(sizeof(open_file_result_t));
    if (!r) {
        open_file_result_t* err = (open_file_result_t*)malloc(sizeof(open_file_result_t));
        if (err) {
            memset(err, 0, sizeof(*err));
            err->ctx = ld->ctx;
            err->success = 0;
            g_idle_add((GSourceFunc)apply_open_result, err);
        }
        g_free(ld->path);
        free(ld);
        return NULL;
    }
    memset(r, 0, sizeof(*r));
    r->ctx = ld->ctx;
    r->path = ld->path;
    r->success = 0;
    free(ld);

    FILE* f = fopen(r->path, "rb");
    if (!f) {
        g_idle_add((GSourceFunc)apply_open_result, r);
        return NULL;
    }
    if (analyze_packets(f, &r->result_data) != 0) {
        fclose(f);
        g_idle_add((GSourceFunc)apply_open_result, r);
        return NULL;
    }
    rewind(f);
    ts_psi_result_t psi_result;
    if (analyze_psi(f, &psi_result) != 0) {
        free_packets_result(&r->result_data);
        fclose(f);
        g_idle_add((GSourceFunc)apply_open_result, r);
        return NULL;
    }
    r->psi_summaries = (char**)calloc(r->result_data.packet_count, sizeof(char*));
    if (r->psi_summaries) {
        uint8_t raw[188];
        rewind(f);
        for (size_t i = 0; i < r->result_data.packet_count; i++) {
            if (fread(raw, 1, sizeof raw, f) != sizeof raw) break;
            const ts_packet_t* p = &r->result_data.packets[i];
            if (p->pusi && p->payload_length >= 2u)
                r->psi_summaries[i] = gui_packet_psi_summary(raw, p, sizeof raw, &psi_result.pat);
        }
    }
    r->program_count = psi_result.pat.program_count;
    free_psi_result(&psi_result);

    rewind(f);
    {
        ts_validate_result_t validate_result;
        if (analyze_validate(f, &validate_result) == 0) {
            r->sync_loss_count = validation_summary_sync_errors();
            free_validate_result(&validate_result);
        }
    }

    fclose(f);
    r->success = 1;
    g_idle_add((GSourceFunc)apply_open_result, r);
    return NULL;
}

static void on_file_open_callback(GObject* source, GAsyncResult* result, gpointer user_data) {
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    GtkFileDialog* dialog = GTK_FILE_DIALOG(source);
    GError* error = NULL;
    GFile* file = gtk_file_dialog_open_finish(dialog, result, &error);
    g_object_unref(dialog);
    if (error != NULL) {
        if (error->code != G_IO_ERROR_CANCELLED) {
            printf("Open failed: %s\n", error->message);
        }
        g_error_free(error);
        return;
    }
    char* path = g_file_get_path(file);
    g_object_unref(file);
    if (!path) return;

    if (!gui_path_is_ts_file(path)) {
        GtkAlertDialog* alert = gtk_alert_dialog_new("Only transport stream files are supported.");
        gtk_alert_dialog_set_detail(alert, "Please choose a file with extension .ts, .tp, or .m2ts");
        gtk_alert_dialog_choose(alert, ctx->window, NULL, NULL, NULL);
        g_object_unref(alert);
        g_free(path);
        return;
    }

    char* basename = g_path_get_basename(path);
    char* loading_text = g_strdup_printf("Loading %s", basename ? basename : path);
    g_free(basename);
    gtk_label_set_text(GTK_LABEL(ctx->loading_label), loading_text);
    g_free(loading_text);

    gtk_stack_set_visible_child_name(GTK_STACK(ctx->content_stack), "loading");

    load_file_data_t* ld = (load_file_data_t*)malloc(sizeof(load_file_data_t));
    if (!ld) {
        g_free(path);
        gtk_stack_set_visible_child_name(GTK_STACK(ctx->content_stack), "empty");
        return;
    }
    ld->path = path;
    ld->ctx = ctx;
    g_thread_new("packet-load", load_file_worker, ld);
}

static void on_open_file_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_accept_label(dialog, "Open");
    GtkFileFilter* filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Transport stream (*.ts, *.tp, *.m2ts)");
    gtk_file_filter_add_pattern(filter, "*.ts");
    gtk_file_filter_add_pattern(filter, "*.tp");
    gtk_file_filter_add_pattern(filter, "*.m2ts");
    GListStore* filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, filter);
    gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
    g_object_unref(filters);
    gtk_file_dialog_open(dialog, ctx->window, NULL, on_file_open_callback, ctx);
}

static void on_activate(GtkApplication* app, gpointer user_data) {
    (void)user_data;
    printf("Activating\n");
    GtkWidget* window = gtk_application_window_new(GTK_APPLICATION(app));
    g_signal_connect(window, "close-request", G_CALLBACK(on_main_window_close_request), NULL);
    gtk_window_set_title(GTK_WINDOW(window), "Packet Analyzer");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);

    GdkDisplay* display = gtk_widget_get_display(window);
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider,
        "button:hover { background-color: alpha(@theme_fg_color, 0.08); }\n"
        "box.packet-row { border: 1px solid alpha(@theme_fg_color, 0.12); border-radius: 8px; margin: 3px 0; padding: 10px 14px; background-color: alpha(@theme_fg_color, 0.02); }\n"
        ".packet-row-expander box title expander, .packet-row-expander expander { opacity: 0; min-width: 2px; min-height: 2px; }\n"
        "label.packet-summary { font-weight: 600; font-family: monospace; font-size: 0.95em; letter-spacing: 0.04em; color: alpha(@theme_fg_color, 0.92); }\n"
        "grid.detail-grid { padding: 2px 0; }\n"
        "label.detail-label { font-weight: 600; font-size: 0.8em; letter-spacing: 0.06em; text-transform: uppercase; color: alpha(@theme_fg_color, 0.55); min-width: 11em; }\n"
        "label.detail-value { font-family: monospace; font-size: 0.97em; letter-spacing: 0.02em; color: @theme_fg_color; }\n"
        "box.psi-summary-box { border: 1px solid alpha(@theme_fg_color, 0.12); border-radius: 6px; padding: 8px; background-color: alpha(@theme_fg_color, 0.03); }\n"
        "label.psi-summary-chip { font-size: 0.72em; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: alpha(@theme_fg_color, 0.72); }\n"
        "grid.psi-summary-grid { padding: 0; }\n"
        "label.psi-summary-key { font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; color: alpha(@theme_fg_color, 0.58); }\n"
        "label.psi-summary-value { font-family: monospace; font-size: 0.92em; color: @theme_fg_color; }\n"
        "box.popup-container { background: transparent; }\n"
        "label.popup-title { font-size: 1.15em; font-weight: 700; }\n"
        "label.popup-subtitle { color: alpha(@theme_fg_color, 0.65); }\n"
        "label.popup-section-title { font-weight: 700; }\n"
        ".popup-card { border: 1px solid alpha(@theme_fg_color, 0.14); border-radius: 8px; background-color: alpha(@theme_fg_color, 0.03); padding: 8px; }\n"
        "button.popup-close-btn { min-width: 100px; }\n"
        "box.stream-overview-card { border: 1px solid alpha(@theme_fg_color, 0.16); border-radius: 8px; background-color: alpha(@theme_fg_color, 0.04); padding: 10px 12px; }\n"
        "label.stream-overview-title { font-family: monospace; font-size: 1.02em; font-weight: 700; }\n"
        "label.stream-overview-meta { color: alpha(@theme_fg_color, 0.7); }\n"
        "label.validation-status-good { color: #2e7d32; font-weight: 700; }\n"
        "label.validation-status-bad { color: #c62828; font-weight: 700; }\n"
        "grid.validation-summary-grid { border: 1px solid alpha(@theme_fg_color, 0.15); border-radius: 8px; padding: 10px; background-color: alpha(@theme_fg_color, 0.03); }\n"
        "box.validation-metric-tile { padding: 4px 6px; }\n"
        "label.validation-metric-value { font-family: monospace; font-size: 1.05em; font-weight: 700; }\n"
        "label.validation-metric-title { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.05em; color: alpha(@theme_fg_color, 0.62); }\n"
        ".validation-detail-view { font-family: \"JetBrains Mono\", \"Fira Code\", \"Cascadia Code\", \"DejaVu Sans Mono\", \"Liberation Mono\", monospace; font-size: 0.9em; }\n"
        ".hexdump-view { font-family: \"JetBrains Mono\", \"Fira Code\", \"Cascadia Code\", \"DejaVu Sans Mono\", \"Liberation Mono\", monospace; font-size: 0.9em; }\n");
    gtk_style_context_add_provider_for_display(display,
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);
    g_object_unref(provider);

    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_window_set_child(GTK_WINDOW(window), box);

    GtkWidget* btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* open_btn = gtk_button_new_with_label("Open file");
    GtkWidget* stats_btn = gtk_button_new_with_label("Stats");
    GtkWidget* validate_btn = gtk_button_new_with_label("Validate");
    GtkWidget* jitter_btn = gtk_button_new_with_label("Jitter");
    GtkWidget* pes_info_btn = gtk_button_new_with_label("PES Info");
    gtk_widget_set_visible(stats_btn, FALSE);
    gtk_widget_set_visible(validate_btn, FALSE);
    gtk_widget_set_visible(jitter_btn, FALSE);
    gtk_widget_set_visible(pes_info_btn, FALSE);
    gtk_box_append(GTK_BOX(btn_box), open_btn);
    gtk_box_append(GTK_BOX(btn_box), stats_btn);
    gtk_box_append(GTK_BOX(btn_box), validate_btn);
    gtk_box_append(GTK_BOX(btn_box), jitter_btn);
    gtk_box_append(GTK_BOX(btn_box), pes_info_btn);

    GtkWidget* content_stack = gtk_stack_new();
    gtk_widget_set_hexpand(content_stack, TRUE);
    gtk_widget_set_vexpand(content_stack, TRUE);

    GtkWidget* empty_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_vexpand(empty_box, TRUE);
    GtkWidget* empty_label = gtk_label_new("Open a transport stream file to get started\n(.ts, .tp, or .m2ts)");
    gtk_label_set_justify(GTK_LABEL(empty_label), GTK_JUSTIFY_CENTER);
    gtk_label_set_wrap(GTK_LABEL(empty_label), TRUE);
    gtk_widget_set_halign(empty_label, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(empty_label, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(empty_label, TRUE);
    gtk_box_append(GTK_BOX(empty_box), empty_label);
    gtk_stack_add_titled(GTK_STACK(content_stack), empty_box, "empty", "empty");

    GtkWidget* loading_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_vexpand(loading_page, TRUE);
    GtkWidget* loading_center = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget* loading_label = gtk_label_new("Loading…");
    gtk_widget_set_halign(loading_center, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(loading_center, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(loading_center, TRUE);
    gtk_box_append(GTK_BOX(loading_center), loading_label);
    gtk_box_append(GTK_BOX(loading_page), loading_center);
    gtk_stack_add_titled(GTK_STACK(content_stack), loading_page, "loading", "loading");

    GtkWidget* list_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_hexpand(list_page, TRUE);
    gtk_widget_set_vexpand(list_page, TRUE);

    GtkWidget* stream_overview = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(stream_overview, "stream-overview-card");
    GtkWidget* stream_overview_title = gtk_label_new("[No file loaded]");
    gtk_widget_add_css_class(stream_overview_title, "stream-overview-title");
    gtk_label_set_xalign(GTK_LABEL(stream_overview_title), 0.0f);
    GtkWidget* stream_overview_meta = gtk_label_new("Open a file to see stream summary information.");
    gtk_widget_add_css_class(stream_overview_meta, "stream-overview-meta");
    gtk_label_set_xalign(GTK_LABEL(stream_overview_meta), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(stream_overview_meta), TRUE);
    gtk_box_append(GTK_BOX(stream_overview), stream_overview_title);
    gtk_box_append(GTK_BOX(stream_overview), stream_overview_meta);

    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scrolled, TRUE);
    gtk_widget_set_vexpand(scrolled, TRUE);
    GtkWidget* packet_list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), packet_list_box);

    gtk_box_append(GTK_BOX(list_page), stream_overview);
    gtk_box_append(GTK_BOX(list_page), scrolled);
    gtk_stack_add_titled(GTK_STACK(content_stack), list_page, "list", "list");
    gtk_stack_set_visible_child_name(GTK_STACK(content_stack), "empty");

    gtk_box_append(GTK_BOX(box), btn_box);
    gtk_box_append(GTK_BOX(box), content_stack);

    static gui_file_ctx_t file_ctx;
    file_ctx.window = GTK_WINDOW(window);
    file_ctx.packet_list_box = GTK_BOX(packet_list_box);
    file_ctx.packet_scrolled = GTK_SCROLLED_WINDOW(scrolled);
    file_ctx.content_stack = content_stack;
    file_ctx.stream_overview_title = stream_overview_title;
    file_ctx.stream_overview_meta = stream_overview_meta;
    file_ctx.stats_btn = stats_btn;
    file_ctx.validate_btn = validate_btn;
    file_ctx.jitter_btn = jitter_btn;
    file_ctx.pes_info_btn = pes_info_btn;
    file_ctx.loading_label = loading_label;
    file_ctx.current_path = NULL;
    memset(&file_ctx.pending_packets, 0, sizeof(file_ctx.pending_packets));
    file_ctx.pending_psi_summaries = NULL;
    file_ctx.pending_render_index = 0;
    file_ctx.rendering_chunk = 0;
    file_ctx.last_scroll_value = 0.0;
    file_ctx.has_last_scroll_value = 0;
    g_signal_connect(gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scrolled)),
                     "value-changed", G_CALLBACK(on_packet_list_scroll_changed), &file_ctx);
    g_signal_connect(open_btn, "clicked", G_CALLBACK(on_open_file_clicked), &file_ctx);
    g_signal_connect(stats_btn, "clicked", G_CALLBACK(on_stats_clicked), &file_ctx);
    g_signal_connect(validate_btn, "clicked", G_CALLBACK(on_validate_clicked), &file_ctx);
    g_signal_connect(jitter_btn, "clicked", G_CALLBACK(on_jitter_clicked), &file_ctx);
    g_signal_connect(pes_info_btn, "clicked", G_CALLBACK(on_pes_info_clicked), &file_ctx);

    gtk_window_present(GTK_WINDOW(window));
}

int run_gui(int argc, char* argv[]) {
    printf("Running GUI\n");
    GtkApplication* app = gtk_application_new("org.sukhyeon.packet-analyzer", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
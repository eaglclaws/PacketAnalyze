#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>
#include "gui_entry.h"
#include "packet.h"
#include "parser.h"
#include "ts_pipeline.h"
#include "utils.h"

#define MAX_PID 8192
#define TS_PACKET_SIZE 188

typedef struct {
    GtkWindow* window;
    GtkBox* packet_list_box;
    GtkWidget* content_stack;
    GtkWidget* stream_overview_title;
    GtkWidget* stream_overview_meta;
    GtkWidget* stats_btn;
    GtkWidget* validate_btn;
    GtkWidget* jitter_btn;
    GtkWidget* pes_info_btn;
    GtkWidget* loading_label;
    char* current_path;
} gui_file_ctx_t;

/* PES result for the PES Info dialog; freed when dialog is destroyed. */
static ts_pes_result_t* s_pes_for_dialog = NULL;

#define EXPANDER_REVEAL_DURATION_MS 200
static void expander_set_animated_child(GtkExpander* exp, GtkWidget* child, unsigned int duration_ms);
static void packet_summary_string(const ts_packet_t* p, size_t index, char* buf, size_t buf_size);

static void pes_dialog_destroyed(GtkWidget* dialog, gpointer user_data) {
    (void)dialog;
    (void)user_data;
    if (s_pes_for_dialog) {
        free_pes_result(s_pes_for_dialog);
        free(s_pes_for_dialog);
        s_pes_for_dialog = NULL;
    }
}

/* Format PTS/DTS (90 kHz units) as "HH:MM:SS.mmm". */
static void format_pts_dts(uint64_t ts_90k, char* buf, size_t buf_size) {
    uint64_t total_ms = (ts_90k * 1000u) / 90000u;
    uint64_t hours = total_ms / 3600000u;
    uint64_t minutes = (total_ms % 3600000u) / 60000u;
    uint64_t seconds = (total_ms % 60000u) / 1000u;
    uint64_t millis = total_ms % 1000u;
    (void)snprintf(buf, buf_size, "%" G_GUINT64_FORMAT ":%02" G_GUINT64_FORMAT ":%02" G_GUINT64_FORMAT ".%03" G_GUINT64_FORMAT,
                   hours, minutes, seconds, millis);
}

/* Return 1 if path has extension .ts, .tp, or .m2ts (case-insensitive). */
static int path_is_ts_file(const char* path) {
    const char* dot = strrchr(path, '.');
    if (!dot || dot == path) return 0;
    dot++;
    if (g_ascii_strcasecmp(dot, "ts") == 0) return 1;
    if (g_ascii_strcasecmp(dot, "tp") == 0) return 1;
    if (g_ascii_strcasecmp(dot, "m2ts") == 0) return 1;
    return 0;
}

/* Result of background file load; passed to main thread to apply. */
typedef struct {
    ts_packets_result_t result_data;
    char** psi_summaries;
    size_t program_count;
    char* path;
    gui_file_ctx_t* ctx;
    int success;
} open_file_result_t;

/* Jitter result kept for the lifetime of the jitter dialog; cleared on dialog destroy. */
static ts_jitter_result_t* s_jitter_for_dialog = NULL;

static void jitter_dialog_destroyed(GtkWidget* dialog, gpointer user_data) {
    (void)dialog;
    (void)user_data;
    if (s_jitter_for_dialog) {
        free_jitter_result(s_jitter_for_dialog);
        free(s_jitter_for_dialog);
        s_jitter_for_dialog = NULL;
    }
}

static void jitter_draw_func(GtkDrawingArea* area, cairo_t* cr, int width, int height, gpointer data) {
    (void)area;
    const ts_jitter_result_t* j = (const ts_jitter_result_t*)data;
    if (!j || j->preview_row_count == 0) return;

    double min_off = j->preview_rows[0].offset_ms, max_off = min_off;
    for (size_t i = 1; i < j->preview_row_count; i++) {
        double o = j->preview_rows[i].offset_ms;
        if (o < min_off) min_off = o;
        if (o > max_off) max_off = o;
    }
    double range = max_off - min_off;
    if (range < 1e-9) range = 1.0;
    double pad = range * 0.05 + 1.0;
    /* Ensure Y axis always includes 0 ms so the reference line is visible */
    double y_min = min_off - pad;
    double y_max = max_off + pad;
    if (y_min > 0.0) y_min = 0.0;
    if (y_max < 0.0) y_max = 0.0;
    if (y_max - y_min < 1e-9) { y_min = -1.0; y_max = 1.0; }
    double y_range = y_max - y_min;
    int margin_l = 48, margin_r = 16, margin_t = 16, margin_b = 32;
    int plot_w = width - margin_l - margin_r, plot_h = height - margin_t - margin_b;
    if (plot_w < 10 || plot_h < 10) return;

    cairo_set_source_rgb(cr, 0.15, 0.15, 0.18);
    cairo_paint(cr);

    /* Horizontal reference line at 0 ms (dashed, prominent) */
    double y0 = margin_t + plot_h * (1.0 - (0.0 - y_min) / y_range);
    cairo_set_source_rgb(cr, 0.85, 0.85, 0.9);
    cairo_set_line_width(cr, 1.5);
    cairo_set_dash(cr, (const double[]){ 6.0, 4.0 }, 2, 0.0);
    cairo_move_to(cr, margin_l, y0);
    cairo_line_to(cr, width - margin_r, y0);
    cairo_stroke(cr);
    cairo_set_dash(cr, NULL, 0, 0.0);
    cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9);
    cairo_move_to(cr, margin_l + 4, y0 - 2);
    cairo_show_text(cr, "0 ms");

    /* Jitter curve */
    cairo_set_source_rgb(cr, 0.2, 0.6, 0.95);
    cairo_set_line_width(cr, 1.5);
    for (size_t i = 0; i < j->preview_row_count; i++) {
        double x = margin_l + (double)(unsigned long)i / (double)(unsigned long)(j->preview_row_count > 1u ? j->preview_row_count - 1u : 1u) * (double)plot_w;
        double y = margin_t + plot_h * (1.0 - (j->preview_rows[i].offset_ms - y_min) / y_range);
        if (i == 0) cairo_move_to(cr, x, y);
        else cairo_line_to(cr, x, y);
    }
    cairo_stroke(cr);

    /* Axis labels */
    cairo_set_source_rgb(cr, 0.7, 0.7, 0.75);
    cairo_set_font_size(cr, 10);
    char buf[64];
    snprintf(buf, sizeof buf, "%.1f ms", y_max);
    cairo_move_to(cr, 4, margin_t + 4);
    cairo_show_text(cr, buf);
    snprintf(buf, sizeof buf, "%.1f ms", y_min);
    cairo_move_to(cr, 4, height - margin_b);
    cairo_show_text(cr, buf);
    cairo_move_to(cr, margin_l, height - 8);
    cairo_show_text(cr, "sample index");
}

/* Append undefined-PID lines to buffer (same logic as report_undefined_pids but to string). */
static void append_undefined_pids(GString* out, const pat_table_t* pat, const pmt_t* pmt_table,
                                  size_t pmt_capacity, const pid_count_list_t* list) {
    uint8_t defined[MAX_PID];
    memset(defined, 0, sizeof defined);
    defined[TS_PID_PAT] = 1;
    defined[TS_PID_NULL] = 1;
    for (uint16_t pid = 0; pid < MAX_PID; pid++) {
        if (is_well_known_si_pid(pid)) defined[pid] = 1;
    }
    for (size_t i = 0; i < pat->program_count; i++) {
        if (pat->programs[i].pid < MAX_PID) defined[pat->programs[i].pid] = 1;
    }
    for (size_t i = 0; i < pmt_capacity && pmt_table; i++) {
        if (pmt_table[i].pcr_pid < MAX_PID) defined[pmt_table[i].pcr_pid] = 1;
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            if (pmt_table[i].es_list[j].elementary_pid < MAX_PID)
                defined[pmt_table[i].es_list[j].elementary_pid] = 1;
        }
    }
    for (size_t i = 0; i < list->count; i++) {
        uint16_t pid = list->pids[i].pid;
        if (pid < MAX_PID && !defined[pid])
            g_string_append_printf(out, "Undefined PID: 0x%04X (packets: %zu)\n", (unsigned)pid, list->pids[i].count);
    }
}

/* Build validation report string. Caller frees. */
static char* build_validation_message(const ts_validate_result_t* result, const char* path) {
    GString* str = g_string_new(NULL);
    char* buf = NULL;
    size_t size = 0;
    FILE* m = open_memstream(&buf, &size);
    if (m) {
        validation_summary_print(m);
        fflush(m);
        if (buf) g_string_append(str, buf);
        fclose(m);
        free(buf);
    }
    if (result->undefined_pid_count > 0u)
        append_undefined_pids(str, &result->psi.pat, result->psi.pmt_table,
                             result->psi.pmt_table_capacity, &result->psi.pid_list);
    if (!result->errors_found && path)
        g_string_append_printf(str, "\nNo errors in %s\n", path);
    return g_string_free(str, FALSE);
}

static GtkWidget* create_validation_metric_tile(const char* title, const char* value) {
    GtkWidget* tile = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_add_css_class(tile, "validation-metric-tile");
    GtkWidget* value_label = gtk_label_new(value);
    GtkWidget* title_label = gtk_label_new(title);
    gtk_widget_add_css_class(value_label, "validation-metric-value");
    gtk_widget_add_css_class(title_label, "validation-metric-title");
    gtk_label_set_xalign(GTK_LABEL(value_label), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0f);
    gtk_box_append(GTK_BOX(tile), value_label);
    gtk_box_append(GTK_BOX(tile), title_label);
    return tile;
}

static char* build_stats_detail_message(const ts_packets_result_t* packets, const ts_psi_result_t* psi) {
    GString* out = g_string_new(NULL);
    g_string_append(out, "PID ratios\n");
    g_string_append(out, "----------\n");
    const pid_count_list_t* list = psi ? &psi->pid_list : &packets->pid_list;
    if (packets->packet_count == 0u) {
        g_string_append(out, "(no packets)\n");
    } else {
        g_string_append(out, "PID       Type        Count        Ratio\n");
        g_string_append(out, "----------------------------------------------\n");
        for (size_t i = 0; i < list->count; i++) {
            double ratio = 100.0 * (double)list->pids[i].count / (double)packets->packet_count;
            g_string_append_printf(out, "0x%04X    %-10s  %-10zu  %6.2f%%\n",
                                   (unsigned)list->pids[i].pid,
                                   pid_type_to_string(list->pids[i].type),
                                   list->pids[i].count, ratio);
        }
        g_string_append_printf(out, "(total)   %-10s  %-10zu  100.00%%\n", "-", packets->packet_count);
    }

    g_string_append(out, "\nPacket summary (first 8)\n");
    g_string_append(out, "------------------------\n");
    size_t sample_count = packets->packet_count < 8u ? packets->packet_count : 8u;
    for (size_t i = 0; i < sample_count; i++) {
        char line[160];
        packet_summary_string(&packets->packets[i], i, line, sizeof line);
        g_string_append_printf(out, "  %s\n", line);
    }
    return g_string_free(out, FALSE);
}

static GtkWidget* create_popup_content_box(void) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_add_css_class(box, "popup-container");
    gtk_widget_set_margin_top(box, 14);
    gtk_widget_set_margin_bottom(box, 14);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);
    return box;
}

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

static GtkWidget* create_popup_header(const char* title_text, const char* subtitle_text) {
    GtkWidget* header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget* title = gtk_label_new(title_text);
    gtk_widget_add_css_class(title, "popup-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_box_append(GTK_BOX(header), title);
    if (subtitle_text && subtitle_text[0] != '\0') {
        GtkWidget* subtitle = gtk_label_new(subtitle_text);
        gtk_widget_add_css_class(subtitle, "popup-subtitle");
        gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
        gtk_box_append(GTK_BOX(header), subtitle);
    }
    return header;
}

static void update_stream_overview(gui_file_ctx_t* ctx, const char* path,
                                   size_t packet_count, size_t observed_pid_count,
                                   size_t program_count) {
    if (!ctx || !ctx->stream_overview_title || !ctx->stream_overview_meta) return;
    const char* base = path ? g_path_get_basename(path) : "(unknown)";
    char title_text[320];
    snprintf(title_text, sizeof title_text, "[%s]", base);
    gtk_label_set_text(GTK_LABEL(ctx->stream_overview_title), title_text);
    if (path) g_free((gpointer)base);

    guint64 bytes = (guint64)packet_count * (guint64)TS_PACKET_SIZE;
    char* pretty_size = g_format_size_full(bytes, G_FORMAT_SIZE_IEC_UNITS);
    char meta_text[512];
    snprintf(meta_text, sizeof meta_text,
             "Packets: %zu  •  Observed PIDs: %zu  •  Programs: %zu  •  Parsed size: %s",
             packet_count, observed_pid_count, program_count, pretty_size ? pretty_size : "n/a");
    if (pretty_size) g_free(pretty_size);
    gtk_label_set_text(GTK_LABEL(ctx->stream_overview_meta), meta_text);
}

static GtkWidget* create_validation_header(int errors_found, const char* path) {
    char subtitle_text[256];
    const char* base = path ? g_path_get_basename(path) : "(unknown file)";
    snprintf(subtitle_text, sizeof subtitle_text, "Target file: %s", base);
    if (path) g_free((gpointer)base);
    GtkWidget* header_box = create_popup_header("Validation report", subtitle_text);

    const char* status_text = errors_found ? "Issues found" : "No issues detected";
    GtkWidget* status = gtk_label_new(status_text);
    gtk_widget_add_css_class(status, errors_found ? "validation-status-bad" : "validation-status-good");
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_box_append(GTK_BOX(header_box), status);
    return header_box;
}

static void on_stats_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    if (!ctx->current_path) return;

    FILE* f = fopen(ctx->current_path, "rb");
    if (!f) return;

    ts_packets_result_t packets;
    if (analyze_packets(f, &packets) != 0) {
        fclose(f);
        return;
    }
    rewind(f);
    ts_psi_result_t psi;
    int psi_ok = (analyze_psi(f, &psi) == 0);
    fclose(f);

    size_t pusi_count = 0;
    size_t tei_count = 0;
    size_t pcr_count = 0;
    size_t null_pid_count = 0;
    for (size_t i = 0; i < packets.packet_count; i++) {
        const ts_packet_t* p = &packets.packets[i];
        if (p->pusi) pusi_count++;
        if (p->tei) tei_count++;
        if (p->pcr_valid) pcr_count++;
        if (p->pid == TS_PID_NULL) null_pid_count++;
    }

    char* details = build_stats_detail_message(&packets, psi_ok ? &psi : NULL);
    if (!details) {
        if (psi_ok) free_psi_result(&psi);
        free_packets_result(&packets);
        return;
    }

    GtkWidget* dialog = gtk_window_new();
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), ctx->window);
    gtk_window_set_title(GTK_WINDOW(dialog), "Stream stats");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 700, 500);

    GtkWidget* container = create_popup_content_box();
    {
        const char* base = g_path_get_basename(ctx->current_path);
        char subtitle[256];
        snprintf(subtitle, sizeof subtitle, "Ratios and packet summary for %s", base);
        GtkWidget* header = create_popup_header("Stream stats", subtitle);
        gtk_box_append(GTK_BOX(container), header);
        g_free((gpointer)base);
    }

    GtkWidget* summary_grid = gtk_grid_new();
    gtk_widget_add_css_class(summary_grid, "validation-summary-grid");
    gtk_widget_add_css_class(summary_grid, "popup-card");
    gtk_grid_set_row_spacing(GTK_GRID(summary_grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(summary_grid), 10);
    char s_packet_count[32], s_pid_count[32], s_program_count[32], s_null_count[32], s_pcr_count[32];
    snprintf(s_packet_count, sizeof s_packet_count, "%zu", packets.packet_count);
    snprintf(s_pid_count, sizeof s_pid_count, "%zu", psi_ok ? psi.pid_list.count : packets.pid_list.count);
    snprintf(s_program_count, sizeof s_program_count, "%zu", psi_ok ? psi.pat.program_count : 0u);
    snprintf(s_null_count, sizeof s_null_count, "%zu", null_pid_count);
    snprintf(s_pcr_count, sizeof s_pcr_count, "%zu", pcr_count);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Packets", s_packet_count), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Observed PIDs", s_pid_count), 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Programs", s_program_count), 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Null PID packets", s_null_count), 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("PCR packets", s_pcr_count), 2, 1, 1, 1);
    {
        char s_pusi[32];
        snprintf(s_pusi, sizeof s_pusi, "%zu", pusi_count);
        GtkWidget* pusi_tile = create_validation_metric_tile("PUSI packets", s_pusi);
        gtk_grid_attach(GTK_GRID(summary_grid), pusi_tile, 0, 1, 1, 1);
    }
    {
        char s_tei[32];
        snprintf(s_tei, sizeof s_tei, "%zu", tei_count);
        GtkWidget* tei_tile = create_validation_metric_tile("TEI packets", s_tei);
        gtk_grid_attach(GTK_GRID(summary_grid), tei_tile, 0, 2, 1, 1);
    }
    gtk_box_append(GTK_BOX(container), summary_grid);

    GtkWidget* details_title = gtk_label_new("PID ratios and packet sample");
    gtk_widget_add_css_class(details_title, "popup-section-title");
    gtk_label_set_xalign(GTK_LABEL(details_title), 0.0f);
    gtk_box_append(GTK_BOX(container), details_title);

    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_widget_add_css_class(scrolled, "popup-card");
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolled), 620);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled), 280);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    GtkWidget* text = gtk_text_view_new();
    gtk_widget_add_css_class(text, "validation-detail-view");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_NONE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(text), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(text), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(text), 8);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(text), 8);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(text)), details, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), text);
    gtk_box_append(GTK_BOX(container), scrolled);

    GtkWidget* close_btn = gtk_button_new_with_label("Close");
    gtk_widget_add_css_class(close_btn, "popup-close-btn");
    g_signal_connect_swapped(close_btn, "clicked", G_CALLBACK(gtk_window_destroy), dialog);
    gtk_box_append(GTK_BOX(container), close_btn);
    gtk_window_set_child(GTK_WINDOW(dialog), container);
    gtk_widget_set_focusable(close_btn, TRUE);
    gtk_window_set_focus(GTK_WINDOW(dialog), close_btn);
    gtk_window_present(GTK_WINDOW(dialog));

    g_free(details);
    if (psi_ok) free_psi_result(&psi);
    free_packets_result(&packets);
}

static void on_jitter_clicked(GtkWidget* button, gpointer user_data) {
    (void)button;
    gui_file_ctx_t* ctx = (gui_file_ctx_t*)user_data;
    if (!ctx->current_path) return;
    FILE* f = fopen(ctx->current_path, "rb");
    if (!f) return;
    ts_jitter_result_t* result = (ts_jitter_result_t*)calloc(1, sizeof(ts_jitter_result_t));
    if (!result) { fclose(f); return; }
    if (analyze_jitter(f, result, 1) != 0) {
        free(result);
        fclose(f);
        return;
    }
    fclose(f);
    if (s_jitter_for_dialog) {
        free_jitter_result(s_jitter_for_dialog);
        free(s_jitter_for_dialog);
    }
    s_jitter_for_dialog = result;

    GtkWidget* dialog = gtk_window_new();
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), ctx->window);
    gtk_window_set_title(GTK_WINDOW(dialog), "Jitter analysis");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 560, 420);
    g_signal_connect(dialog, "destroy", G_CALLBACK(jitter_dialog_destroyed), NULL);

    GtkWidget* vbox = create_popup_content_box();
    {
        char subtitle[160];
        snprintf(subtitle, sizeof subtitle, "PCR PID 0x%04X  •  %zu samples",
                 (unsigned)result->pcr_pid, result->pcr_sample_total);
        GtkWidget* header = create_popup_header("Jitter analysis", subtitle);
        gtk_box_append(GTK_BOX(vbox), header);
    }

    char buf[256];
    GtkWidget* grid = gtk_grid_new();
    gtk_widget_add_css_class(grid, "popup-card");
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    int r = 0;
#define JR(L, V) do { \
    GtkWidget* l = gtk_label_new(L); GtkWidget* v = gtk_label_new(V); \
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f); gtk_label_set_xalign(GTK_LABEL(v), 0.0f); \
    gtk_grid_attach(GTK_GRID(grid), l, 0, r, 1, 1); gtk_grid_attach(GTK_GRID(grid), v, 1, r, 1, 1); r++; } while(0)
    snprintf(buf, sizeof buf, "0x%04X", (unsigned)result->pcr_pid);
    JR("PCR PID", buf);
    snprintf(buf, sizeof buf, "%zu", result->pcr_sample_total);
    JR("PCR samples", buf);
    snprintf(buf, sizeof buf, "%.2f bps", result->bitrate);
    JR("Bitrate", buf);
    snprintf(buf, sizeof buf, "%zu", result->first_byte_offset);
    JR("First byte offset", buf);
    snprintf(buf, sizeof buf, "%zu", result->last_byte_offset);
    JR("Last byte offset", buf);
    snprintf(buf, sizeof buf, "%zu (omitted %zu)", result->preview_row_count, result->preview_rows_omitted);
    JR("Preview rows", buf);
#undef JR
    gtk_box_append(GTK_BOX(vbox), grid);

    GtkWidget* da = gtk_drawing_area_new();
    gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(da), 500);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(da), 220);
    gtk_widget_add_css_class(da, "popup-card");
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(da), jitter_draw_func, result, NULL);
    gtk_box_append(GTK_BOX(vbox), da);

    GtkWidget* close_btn = gtk_button_new_with_label("Close");
    gtk_widget_add_css_class(close_btn, "popup-close-btn");
    g_signal_connect_swapped(close_btn, "clicked", G_CALLBACK(gtk_window_destroy), dialog);
    gtk_box_append(GTK_BOX(vbox), close_btn);
    gtk_window_set_child(GTK_WINDOW(dialog), vbox);
    gtk_widget_set_focusable(close_btn, TRUE);
    gtk_window_set_focus(GTK_WINDOW(dialog), close_btn);
    gtk_window_present(GTK_WINDOW(dialog));
}

static GtkWidget* pes_packet_detail_grid(const pes_packet_t* p, size_t index) {
    GtkWidget* grid = gtk_grid_new();
    gtk_widget_add_css_class(grid, "detail-grid");
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 16);
    int row = 0;
#define PR(L, V) do { \
    GtkWidget* l = gtk_label_new(L); GtkWidget* v = gtk_label_new(V); \
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f); gtk_label_set_xalign(GTK_LABEL(v), 0.0f); \
    gtk_label_set_selectable(GTK_LABEL(v), TRUE); \
    gtk_widget_add_css_class(l, "detail-label"); gtk_widget_add_css_class(v, "detail-value"); \
    gtk_grid_attach(GTK_GRID(grid), l, 0, row, 1, 1); gtk_grid_attach(GTK_GRID(grid), v, 1, row, 1, 1); row++; } while(0)
    char tmp[80];
    snprintf(tmp, sizeof tmp, "%zu", index);
    PR("Index", tmp);
    snprintf(tmp, sizeof tmp, "0x%02X", (unsigned)p->stream_id);
    PR("Stream ID", tmp);
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->packet_length);
    PR("Packet length", tmp);
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->header_length);
    PR("Header length", tmp);
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->PTS_DTS_flags);
    PR("PTS_DTS flags", tmp);
    if (p->PTS_DTS_flags >= 2u) {
        format_pts_dts(p->pts, tmp, sizeof tmp);
        PR("PTS", tmp);
        if (p->PTS_DTS_flags == 3u) {
            format_pts_dts(p->dts, tmp, sizeof tmp);
            PR("DTS", tmp);
        }
    } else {
        PR("PTS", "(not present)");
    }
#undef PR
    return grid;
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

    GtkWidget* vbox = create_popup_content_box();
    {
        char subtitle[160];
        snprintf(subtitle, sizeof subtitle, "%zu PID group%s detected",
                 result->pes_packet_table.count, result->pes_packet_table.count == 1 ? "" : "s");
        GtkWidget* header = create_popup_header("PES Info", subtitle);
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
            GtkWidget* sub_label = gtk_expander_get_label_widget(GTK_EXPANDER(sub_exp));
            if (sub_label)
                gtk_widget_add_css_class(sub_label, "packet-summary");
            GtkWidget* pg = pes_packet_detail_grid(pp, j);
            gtk_widget_set_margin_top(pg, 8);
            expander_set_animated_child(GTK_EXPANDER(sub_exp), pg, EXPANDER_REVEAL_DURATION_MS);
            gtk_box_append(GTK_BOX(sub_row), sub_exp);
            gtk_box_append(GTK_BOX(inner), sub_row);
        }
        expander_set_animated_child(GTK_EXPANDER(exp), inner, EXPANDER_REVEAL_DURATION_MS);
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
    if (!ctx->current_path) return;
    FILE* f = fopen(ctx->current_path, "rb");
    if (!f) return;
    ts_validate_result_t result;
    if (analyze_validate(f, &result) != 0) {
        fclose(f);
        return;
    }
    fclose(f);
    char* message = build_validation_message(&result, ctx->current_path);
    if (!message) return;
    int errors_found = result.errors_found;
    size_t undefined_pid_count = result.undefined_pid_count;
    size_t observed_pid_count = result.psi.pid_list.count;
    size_t program_count = result.psi.pat.program_count;
    size_t cc_sync_issue_count = validation_summary_total_errors();
    size_t total_issues = cc_sync_issue_count + undefined_pid_count;
    free_validate_result(&result);

    GtkWidget* dialog = gtk_window_new();
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), ctx->window);
    gtk_window_set_title(GTK_WINDOW(dialog), "Validation");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 620, 460);

    GtkWidget* container = create_popup_content_box();

    GtkWidget* header = create_validation_header(errors_found, ctx->current_path);
    gtk_box_append(GTK_BOX(container), header);

    char total_issue_text[32];
    char cc_sync_text[32];
    char pid_observed_text[32];
    char program_count_text[32];
    char undefined_pid_text[32];
    snprintf(total_issue_text, sizeof total_issue_text, "%zu", total_issues);
    snprintf(cc_sync_text, sizeof cc_sync_text, "%zu", cc_sync_issue_count);
    snprintf(pid_observed_text, sizeof pid_observed_text, "%zu", observed_pid_count);
    snprintf(program_count_text, sizeof program_count_text, "%zu", program_count);
    snprintf(undefined_pid_text, sizeof undefined_pid_text, "%zu", undefined_pid_count);

    GtkWidget* summary_grid = gtk_grid_new();
    gtk_widget_add_css_class(summary_grid, "validation-summary-grid");
    gtk_widget_add_css_class(summary_grid, "popup-card");
    gtk_grid_set_row_spacing(GTK_GRID(summary_grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(summary_grid), 10);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Total issues", total_issue_text), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("CC + Sync issues", cc_sync_text), 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Undefined PIDs", undefined_pid_text), 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Observed PIDs", pid_observed_text), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(summary_grid), create_validation_metric_tile("Programs", program_count_text), 1, 1, 1, 1);
    gtk_box_append(GTK_BOX(container), summary_grid);

    GtkWidget* detail_title = gtk_label_new("Details");
    gtk_widget_add_css_class(detail_title, "validation-detail-title");
    gtk_widget_add_css_class(detail_title, "popup-section-title");
    gtk_label_set_xalign(GTK_LABEL(detail_title), 0.0f);
    gtk_box_append(GTK_BOX(container), detail_title);

    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_widget_add_css_class(scrolled, "popup-card");
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolled), 520);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled), 240);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    GtkWidget* detail_view = gtk_text_view_new();
    gtk_widget_add_css_class(detail_view, "validation-detail-view");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(detail_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(detail_view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(detail_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(detail_view), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(detail_view), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(detail_view), 8);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(detail_view), 8);
    GtkTextBuffer* detail_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(detail_view));
    gtk_text_buffer_set_text(detail_buffer, message, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), detail_view);
    gtk_box_append(GTK_BOX(container), scrolled);

    GtkWidget* close_btn = gtk_button_new_with_label("Close");
    gtk_widget_add_css_class(close_btn, "popup-close-btn");
    g_signal_connect_swapped(close_btn, "clicked", G_CALLBACK(gtk_window_destroy), dialog);
    gtk_box_append(GTK_BOX(container), close_btn);
    gtk_window_set_child(GTK_WINDOW(dialog), container);
    gtk_widget_set_focusable(close_btn, TRUE);
    gtk_window_set_focus(GTK_WINDOW(dialog), close_btn);
    g_free(message);
    gtk_window_present(GTK_WINDOW(dialog));
}

/* Build hex dump into buf; offset 8, 2 spaces, hex 49 chars, 2 spaces, ascii 16. Returns length. */
static size_t hexdump_format_line(char* buf, size_t buf_size, size_t offset, const uint8_t* data, int n) {
    size_t pos = 0;
    pos += (size_t)snprintf(buf + pos, buf_size - pos, "%08zx  ", offset);
    for (int j = 0; j < 16; j++) {
        if (j < n)
            pos += (size_t)snprintf(buf + pos, buf_size - pos, "%02x ", data[offset + (size_t)j]);
        else
            pos += (size_t)snprintf(buf + pos, buf_size - pos, "   ");
        if (j == 7 && pos < buf_size - 1) { buf[pos++] = ' '; buf[pos] = '\0'; }
    }
    if (pos < buf_size - 1) buf[pos++] = ' ';
    if (pos < buf_size - 1) buf[pos++] = ' ';
    for (int j = 0; j < 16 && pos < buf_size; j++) {
        char c = (j < n) ? (char)data[offset + (size_t)j] : ' ';
        buf[pos++] = (c >= 32 && c < 127) ? c : '.';
    }
    if (pos < buf_size) buf[pos++] = '\n';
    buf[pos] = '\0';
    return pos;
}

/* Show a popup window with hex dump of the packet at the given index in the file. */
static void show_hexdump_popup(const char* path, size_t packet_index, GtkWindow* parent) {
    FILE* f = fopen(path, "rb");
    if (!f) return;
    if (fseek(f, (long)(packet_index * (size_t)TS_PACKET_SIZE), SEEK_SET) != 0) {
        fclose(f);
        return;
    }
    uint8_t buf[TS_PACKET_SIZE];
    if (fread(buf, 1, sizeof buf, f) != sizeof buf) {
        fclose(f);
        return;
    }
    fclose(f);

    /* One line ~82 chars, 12 lines + header */
    char* text = (char*)malloc(1024);
    if (!text) return;
    size_t len = 0;
    /* Header exactly 77 chars: Offset(8) + 2 spaces + Hex(49) + 2 spaces + ASCII(16) */
    len += (size_t)snprintf(text + len, 1024 - len, "Offset  %*sHex%*s  ASCII%*s\n", 2, "", 46, "", 11, "");
    for (size_t i = 0; i < sizeof buf && len < 1000; i += 16) {
        int n = (int)((sizeof buf - i) > 16 ? 16 : (sizeof buf - i));
        len += hexdump_format_line(text + len, 1024 - len, i, buf, n);
    }

    GtkWidget* win = gtk_window_new();
    if (parent) {
        gtk_window_set_modal(GTK_WINDOW(win), TRUE);
        gtk_window_set_transient_for(GTK_WINDOW(win), parent);
    }
    gtk_window_set_title(GTK_WINDOW(win), "Packet hex dump");
    /* Just wide enough for 77 chars; height fits ~12 lines + header */
    gtk_window_set_default_size(GTK_WINDOW(win), 610, 300);

    GtkWidget* content = create_popup_content_box();
    {
        char subtitle[128];
        snprintf(subtitle, sizeof subtitle, "Packet #%zu  •  188 bytes", packet_index);
        GtkWidget* header = create_popup_header("Packet hex dump", subtitle);
        gtk_box_append(GTK_BOX(content), header);
    }

    GtkWidget* scrolled = gtk_scrolled_window_new();
    gtk_widget_add_css_class(scrolled, "popup-card");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scrolled), 570);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled), 220);

    GtkWidget* view = gtk_text_view_new();
    gtk_widget_add_css_class(view, "hexdump-view");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 6);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 6);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(view), 6);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(view), 6);
    gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text, (int)len);
    free(text);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
    gtk_box_append(GTK_BOX(content), scrolled);
    GtkWidget* close_btn = gtk_button_new_with_label("Close");
    gtk_widget_add_css_class(close_btn, "popup-close-btn");
    g_signal_connect_swapped(close_btn, "clicked", G_CALLBACK(gtk_window_destroy), win);
    gtk_box_append(GTK_BOX(content), close_btn);
    gtk_window_set_child(GTK_WINDOW(win), content);
    gtk_widget_set_focusable(close_btn, TRUE);
    gtk_window_set_focus(GTK_WINDOW(win), close_btn);
    gtk_window_present(GTK_WINDOW(win));
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
    show_hexdump_popup(ctx->current_path, packet_index, ctx->window);
}

static void packet_summary_string(const ts_packet_t* p, size_t index, char* buf, size_t buf_size) {
    const char* af = (p->adaptation_field_control == 3) ? "adapt + payload" :
                    (p->adaptation_field_control == 2) ? "adaptation only" :
                    (p->adaptation_field_control == 1) ? "payload only" : "none";
    (void)snprintf(buf, buf_size, "Packet %zu  ·  PID 0x%04X  ·  Continuity %u  ·  %s  ·  %u bytes",
                   index, (unsigned)p->pid, (unsigned)p->continuity_counter, af, (unsigned)p->payload_length);
}

/* Build a PSI summary string for this packet's payload, or NULL if not PAT/PMT. Caller frees. */
static char* packet_psi_summary(const uint8_t* raw, const ts_packet_t* p, size_t buffer_len,
                                 const pat_table_t* pat) {
    if (!p->pusi || p->payload_length < 2u) return NULL;
    int pointer_field = (int)raw[p->payload_offset];
    size_t section_len = (size_t)(p->payload_length - 1 - pointer_field);
    size_t section_start = (size_t)(p->payload_offset + 1 + pointer_field);
    if (section_start + section_len > buffer_len) return NULL;

    psi_header_t psi_header;
    if (!parse_psi_header(raw + section_start, section_len, p, &psi_header)) return NULL;

    if (p->pid == TS_PID_PAT && psi_header.table_id == 0x00) {
        pat_table_t temp_pat;
        pat_table_init(&temp_pat);
        if (!parse_pat_section(raw + section_start, section_len, &psi_header, &temp_pat)) {
            pat_table_cleanup(&temp_pat);
            return NULL;
        }
        char* out = (char*)malloc(512);
        if (!out) { pat_table_cleanup(&temp_pat); return NULL; }
        int n = snprintf(out, 512, "PAT: TS 0x%X v%u sec %u/%u - %zu program(s)",
            (unsigned)psi_header.transport_stream_id, (unsigned)psi_header.version_number,
            (unsigned)psi_header.section_number, (unsigned)psi_header.last_section_number,
            temp_pat.program_count);
        for (size_t k = 0; k < temp_pat.program_count && n < 480; k++)
            n += snprintf(out + n, 512 - (size_t)n, "; PNO %u -> PID 0x%X",
                (unsigned)temp_pat.programs[k].program_number, (unsigned)temp_pat.programs[k].pid);
        pat_table_cleanup(&temp_pat);
        return out;
    }

    for (size_t k = 0; k < pat->program_count; k++) {
        if (p->pid != pat->programs[k].pid) continue;
        pmt_t temp_pmt = { .pcr_pid = 0, .capacity = 2, .es_count = 0, .es_list = (pmt_es_t*)malloc(2 * sizeof(pmt_es_t)) };
        if (!temp_pmt.es_list) return NULL;
        if (!parse_pmt_section(raw + section_start, section_len, &psi_header, &temp_pmt)) {
            free(temp_pmt.es_list);
            return NULL;
        }
        char* out = (char*)malloc(512);
        if (!out) { free(temp_pmt.es_list); return NULL; }
        int n = snprintf(out, 512, "PMT: program %u, PCR PID 0x%X - %zu ES",
            (unsigned)pat->programs[k].program_number, (unsigned)temp_pmt.pcr_pid, temp_pmt.es_count);
        for (size_t j = 0; j < temp_pmt.es_count && n < 460; j++) {
            const char* codec = stream_type_to_codec_string(temp_pmt.es_list[j].stream_type);
            n += snprintf(out + n, 512 - (size_t)n, "; PID 0x%X %s",
                          (unsigned)temp_pmt.es_list[j].elementary_pid, codec);
        }
        free(temp_pmt.es_list);
        return out;
    }
    return NULL;
}

static gboolean expander_collapse_timeout_cb(gpointer user_data) {
    GtkExpander* exp = GTK_EXPANDER(user_data);
    g_object_set_data(G_OBJECT(exp), "packet-collapsing", GINT_TO_POINTER(1));
    g_object_set_data(G_OBJECT(exp), "packet-animating-collapse", NULL);
    gtk_expander_set_expanded(exp, FALSE);
    g_object_set_data(G_OBJECT(exp), "collapse-timeout-id", NULL);
    return G_SOURCE_REMOVE;
}

static void expander_expanded_notify_cb(GtkExpander* exp, GParamSpec* pspec, gpointer user_data) {
    (void)pspec;
    (void)user_data;
    GtkRevealer* rev = GTK_REVEALER(g_object_get_data(G_OBJECT(exp), "packet-revealer"));
    if (!rev) return;
    if (gtk_expander_get_expanded(exp)) {
        if (g_object_get_data(G_OBJECT(exp), "packet-animating-collapse"))
            return;
        guint tid = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(exp), "collapse-timeout-id"));
        if (tid) {
            g_source_remove(tid);
            g_object_set_data(G_OBJECT(exp), "collapse-timeout-id", NULL);
        }
        gtk_revealer_set_reveal_child(rev, TRUE);
    } else {
        if (g_object_get_data(G_OBJECT(exp), "packet-collapsing")) {
            g_object_set_data(G_OBJECT(exp), "packet-collapsing", NULL);
            return;
        }
        g_object_set_data(G_OBJECT(exp), "packet-animating-collapse", GINT_TO_POINTER(1));
        gtk_expander_set_expanded(exp, TRUE);
        gtk_revealer_set_reveal_child(rev, FALSE);
        guint id = g_timeout_add(EXPANDER_REVEAL_DURATION_MS, expander_collapse_timeout_cb, exp);
        g_object_set_data(G_OBJECT(exp), "collapse-timeout-id", GUINT_TO_POINTER(id));
    }
}

static void expander_set_animated_child(GtkExpander* exp, GtkWidget* child, unsigned int duration_ms) {
    GtkWidget* rev = gtk_revealer_new();
    gtk_revealer_set_child(GTK_REVEALER(rev), child);
    gtk_revealer_set_reveal_child(GTK_REVEALER(rev), FALSE);
    gtk_revealer_set_transition_duration(GTK_REVEALER(rev), (guint)duration_ms);
    gtk_revealer_set_transition_type(GTK_REVEALER(rev), GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    g_object_set_data(G_OBJECT(exp), "packet-revealer", rev);
    g_signal_connect(exp, "notify::expanded", G_CALLBACK(expander_expanded_notify_cb), NULL);
    gtk_expander_set_child(exp, rev);
}

static GtkWidget* create_psi_summary_widget(const char* psi_summary) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(box, "psi-summary-box");
    if (!psi_summary || psi_summary[0] == '\0')
        return box;

    const char* type_text = g_str_has_prefix(psi_summary, "PAT:") ? "PAT" :
                            g_str_has_prefix(psi_summary, "PMT:") ? "PMT" : "PSI";
    GtkWidget* chip = gtk_label_new(type_text);
    gtk_widget_add_css_class(chip, "psi-summary-chip");
    gtk_label_set_xalign(GTK_LABEL(chip), 0.0f);
    gtk_box_append(GTK_BOX(box), chip);

    GtkWidget* grid = gtk_grid_new();
    gtk_widget_add_css_class(grid, "psi-summary-grid");
    gtk_grid_set_row_spacing(GTK_GRID(grid), 2);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_append(GTK_BOX(box), grid);

    int row = 0;
#define PSI_ROW(K, V) do { \
    GtkWidget* k = gtk_label_new(K); GtkWidget* v = gtk_label_new(V); \
    gtk_widget_add_css_class(k, "psi-summary-key"); gtk_widget_add_css_class(v, "psi-summary-value"); \
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f); gtk_label_set_xalign(GTK_LABEL(v), 0.0f); \
    gtk_label_set_selectable(GTK_LABEL(v), TRUE); gtk_label_set_wrap(GTK_LABEL(v), TRUE); \
    gtk_grid_attach(GTK_GRID(grid), k, 0, row, 1, 1); gtk_grid_attach(GTK_GRID(grid), v, 1, row, 1, 1); row++; \
} while(0)

    if (g_str_has_prefix(psi_summary, "PAT:")) {
        char** parts = g_strsplit(psi_summary, "; ", -1);
        const char* head = parts && parts[0] ? parts[0] : psi_summary;
        const char* ts_mark = strstr(head, "TS ");
        const char* v_mark = strstr(head, " v");
        const char* sec_mark = strstr(head, " sec ");
        if (!sec_mark) sec_mark = strstr(head, " §");
        const char* prog_mark = strstr(head, " - ");
        if (!prog_mark) prog_mark = strstr(head, " — ");
        char tmp[128];
        if (ts_mark) {
            const char* start = ts_mark + 3;
            const char* end = v_mark ? v_mark : (sec_mark ? sec_mark : (prog_mark ? prog_mark : head + strlen(head)));
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("TS ID", tmp); }
        }
        if (v_mark) {
            const char* start = v_mark + 2;
            const char* end = sec_mark ? sec_mark : (prog_mark ? prog_mark : head + strlen(head));
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("Version", tmp); }
        }
        if (sec_mark) {
            const char* start = (strncmp(sec_mark, " sec ", 5) == 0) ? (sec_mark + 5) : (sec_mark + 2);
            const char* end = prog_mark ? prog_mark : head + strlen(head);
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("Section", tmp); }
        }
        if (prog_mark) {
            const char* start = prog_mark + 3;
            size_t n = strlen(start);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("Programs", tmp); }
        }

        int added_title = 0;
        if (parts) {
            for (int i = 1; parts[i] != NULL; i++) {
                unsigned pno = 0, pid = 0;
                if (sscanf(parts[i], "PNO %u -> PID 0x%X", &pno, &pid) == 2 ||
                    sscanf(parts[i], "PNO %u → PID 0x%X", &pno, &pid) == 2) {
                    if (!added_title) {
                        GtkWidget* title = gtk_label_new("Program map");
                        gtk_widget_add_css_class(title, "psi-summary-list-title");
                        gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
                        gtk_box_append(GTK_BOX(box), title);
                        added_title = 1;
                    }
                    char line[96];
                    (void)snprintf(line, sizeof line, "- Program %u -> PID 0x%04X", pno, pid);
                    GtkWidget* item = gtk_label_new(line);
                    gtk_widget_add_css_class(item, "psi-summary-item");
                    gtk_label_set_xalign(GTK_LABEL(item), 0.0f);
                    gtk_label_set_selectable(GTK_LABEL(item), TRUE);
                    gtk_box_append(GTK_BOX(box), item);
                }
            }
        }
        g_strfreev(parts);
    } else if (g_str_has_prefix(psi_summary, "PMT:")) {
        char** parts = g_strsplit(psi_summary, "; ", -1);
        const char* head = parts && parts[0] ? parts[0] : psi_summary;
        const char* p_mark = strstr(head, "program ");
        const char* pcr_mark = strstr(head, "PCR PID ");
        const char* es_mark = strstr(head, " - ");
        if (!es_mark) es_mark = strstr(head, " — ");
        char tmp[128];
        if (p_mark) {
            const char* start = p_mark + 8;
            const char* end = strchr(start, ',');
            if (!end) end = pcr_mark ? pcr_mark : (es_mark ? es_mark : head + strlen(head));
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("Program", tmp); }
        }
        if (pcr_mark) {
            const char* start = pcr_mark + 8;
            const char* end = es_mark ? es_mark : head + strlen(head);
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("PCR PID", tmp); }
        }
        if (es_mark) {
            const char* start = es_mark + 3;
            size_t es_stream_count = 0;
            if (sscanf(start, "%zu", &es_stream_count) == 1) {
                (void)snprintf(tmp, sizeof tmp, "%zu", es_stream_count);
                PSI_ROW("ES streams", tmp);
            }
        }

        int added_title = 0;
        if (parts) {
            for (int i = 1; parts[i] != NULL; i++) {
                unsigned pid = 0;
                int n = 0;
                if (sscanf(parts[i], "PID 0x%X %n", &pid, &n) == 1 && n > 0) {
                    const char* codec_start = parts[i] + n;
                    char* codec = g_strdup(codec_start);
                    if (codec) {
                        g_strstrip(codec);
                        if (!added_title) {
                            GtkWidget* title = gtk_label_new("ES list");
                            gtk_widget_add_css_class(title, "psi-summary-list-title");
                            gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
                            gtk_box_append(GTK_BOX(box), title);
                            added_title = 1;
                        }
                        char line[192];
                        (void)snprintf(line, sizeof line, "- PID 0x%04X - %s", pid, codec);
                        GtkWidget* item = gtk_label_new(line);
                        gtk_widget_add_css_class(item, "psi-summary-item");
                        gtk_label_set_xalign(GTK_LABEL(item), 0.0f);
                        gtk_label_set_wrap(GTK_LABEL(item), TRUE);
                        gtk_label_set_selectable(GTK_LABEL(item), TRUE);
                        gtk_box_append(GTK_BOX(box), item);
                        g_free(codec);
                    }
                }
            }
        }
        g_strfreev(parts);
    } else {
        PSI_ROW("Summary", psi_summary);
    }
#undef PSI_ROW
    return box;
}

static GtkWidget* packet_detail_grid(const ts_packet_t* p, size_t index, const char* psi_summary) {
    GtkWidget* grid = gtk_grid_new();
    gtk_widget_add_css_class(grid, "detail-grid");
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 16);
    int row = 0;
#define ROW(L, V) do { \
    GtkWidget* l = gtk_label_new(L); GtkWidget* v = gtk_label_new(V); \
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f); gtk_label_set_xalign(GTK_LABEL(v), 0.0f); \
    gtk_label_set_selectable(GTK_LABEL(v), TRUE); \
    gtk_widget_add_css_class(l, "detail-label"); gtk_widget_add_css_class(v, "detail-value"); \
    gtk_grid_attach(GTK_GRID(grid), l, 0, row, 1, 1); gtk_grid_attach(GTK_GRID(grid), v, 1, row, 1, 1); row++; } while(0)
    char tmp[64];
    snprintf(tmp, sizeof tmp, "%zu", index);
    ROW("Index", tmp);
    snprintf(tmp, sizeof tmp, "0x%04X", (unsigned)p->pid);
    ROW("PID", tmp);
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->continuity_counter);
    ROW("Continuity counter", tmp);
    ROW("PUSI", p->pusi ? "yes" : "no");
    ROW("TEI", p->tei ? "yes" : "no");
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->adaptation_field_control);
    ROW("Adaptation field ctrl", tmp);
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->payload_offset);
    ROW("Payload offset", tmp);
    snprintf(tmp, sizeof tmp, "%u", (unsigned)p->payload_length);
    ROW("Payload length", tmp);
    if ((p->adaptation_field_control & 0x02u) != 0u) {
        snprintf(tmp, sizeof tmp, "%u", (unsigned)p->adaptation_field_length);
        ROW("Adaptation length", tmp);
        ROW("Discontinuity", p->discontinuity_indicator ? "yes" : "no");
        ROW("Random access", p->random_access_indicator ? "yes" : "no");
        ROW("PCR present", p->pcr_valid ? "yes" : "no");
    }
    if (psi_summary && psi_summary[0]) {
        GtkWidget* l = gtk_label_new("PSI");
        GtkWidget* v = create_psi_summary_widget(psi_summary);
        gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
        gtk_widget_set_hexpand(v, TRUE);
        gtk_widget_set_halign(v, GTK_ALIGN_FILL);
        gtk_widget_add_css_class(l, "detail-label");
        gtk_grid_attach(GTK_GRID(grid), l, 0, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), v, 1, row, 1, 1);
        row++;
    }
#undef ROW
    return grid;
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

    /* Clear existing packet list */
    while (1) {
        GtkWidget* child = gtk_widget_get_first_child(GTK_WIDGET(ctx->packet_list_box));
        if (!child) break;
        gtk_box_remove(ctx->packet_list_box, child);
    }

    for (size_t i = 0; i < r->result_data.packet_count; i++) {
        const ts_packet_t* p = &r->result_data.packets[i];
        char summary[128];
        packet_summary_string(p, i, summary, sizeof summary);
        GtkWidget* row_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_add_css_class(row_box, "packet-row");
        GtkWidget* exp = gtk_expander_new(summary);
        gtk_widget_add_css_class(exp, "packet-row-expander");
        g_object_set_data(G_OBJECT(exp), "packet-index", GINT_TO_POINTER((int)i + 1));
        GtkGesture* right_click = GTK_GESTURE(gtk_gesture_click_new());
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(right_click), 3);
        g_signal_connect(right_click, "pressed", G_CALLBACK(on_packet_row_right_click), ctx);
        gtk_widget_add_controller(GTK_WIDGET(exp), GTK_EVENT_CONTROLLER(right_click));
        GtkWidget* summary_label = gtk_expander_get_label_widget(GTK_EXPANDER(exp));
        if (summary_label)
            gtk_widget_add_css_class(summary_label, "packet-summary");
        const char* psi_line = r->psi_summaries ? r->psi_summaries[i] : NULL;
        GtkWidget* detail_grid = packet_detail_grid(p, i, psi_line);
        gtk_widget_set_margin_top(detail_grid, 8);
        expander_set_animated_child(GTK_EXPANDER(exp), detail_grid, EXPANDER_REVEAL_DURATION_MS);
        gtk_box_append(GTK_BOX(row_box), exp);
        gtk_box_append(ctx->packet_list_box, row_box);
        if (r->psi_summaries && r->psi_summaries[i]) free(r->psi_summaries[i]);
    }
    update_stream_overview(ctx, r->path, r->result_data.packet_count,
                           r->result_data.pid_list.count, r->program_count);
    if (r->psi_summaries) free(r->psi_summaries);
    free_packets_result(&r->result_data);

    if (ctx->current_path) g_free(ctx->current_path);
    ctx->current_path = r->path;
    r->path = NULL;
    gtk_widget_set_visible(ctx->stats_btn, TRUE);
    gtk_widget_set_visible(ctx->validate_btn, TRUE);
    gtk_widget_set_visible(ctx->jitter_btn, TRUE);
    gtk_widget_set_visible(ctx->pes_info_btn, TRUE);
    gtk_stack_set_visible_child_name(GTK_STACK(ctx->content_stack), "list");
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
                r->psi_summaries[i] = packet_psi_summary(raw, p, sizeof raw, &psi_result.pat);
        }
    }
    r->program_count = psi_result.pat.program_count;
    free_psi_result(&psi_result);
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

    if (!path_is_ts_file(path)) {
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
        "label.psi-summary-list-title { font-size: 0.78em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: alpha(@theme_fg_color, 0.66); margin-top: 4px; }\n"
        "label.psi-summary-main { font-family: monospace; font-weight: 600; color: @theme_fg_color; }\n"
        "label.psi-summary-item { font-family: monospace; color: alpha(@theme_fg_color, 0.85); }\n"
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
    file_ctx.content_stack = content_stack;
    file_ctx.stream_overview_title = stream_overview_title;
    file_ctx.stream_overview_meta = stream_overview_meta;
    file_ctx.stats_btn = stats_btn;
    file_ctx.validate_btn = validate_btn;
    file_ctx.jitter_btn = jitter_btn;
    file_ctx.pes_info_btn = pes_info_btn;
    file_ctx.loading_label = loading_label;
    file_ctx.current_path = NULL;
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
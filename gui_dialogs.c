#include "gui_dialogs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "packet.h"
#include "ts_pipeline.h"
#include "utils.h"

#define TS_PACKET_SIZE 188

static GtkWidget* create_popup_content_box(void) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_add_css_class(box, "popup-container");
    gtk_widget_set_margin_top(box, 14);
    gtk_widget_set_margin_bottom(box, 14);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);
    return box;
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

/* Build hex dump into buf; offset 8, 2 spaces, hex 49 chars, 2 spaces, ascii 16. Returns length. */
static size_t hexdump_format_line(char* buf, size_t buf_size, size_t offset, const uint8_t* data, int n) {
    size_t pos = 0;
    pos += (size_t)snprintf(buf + pos, buf_size - pos, "%08zx  ", offset);
    for (int j = 0; j < 16; j++) {
        if (j < n) {
            pos += (size_t)snprintf(buf + pos, buf_size - pos, "%02x ", data[offset + (size_t)j]);
        } else {
            pos += (size_t)snprintf(buf + pos, buf_size - pos, "   ");
        }
        if (j == 7 && pos < buf_size - 1) {
            buf[pos++] = ' ';
            buf[pos] = '\0';
        }
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

void gui_show_hexdump_popup(const char* path, size_t packet_index, GtkWindow* parent) {
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

    char* text = (char*)malloc(1024);
    if (!text) return;
    size_t len = 0;
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

static void append_undefined_pids(GString* out, const pat_table_t* pat, const pmt_t* pmt_table,
                                  size_t pmt_capacity, const pid_count_list_t* list) {
    uint8_t defined[8192];
    memset(defined, 0, sizeof defined);
    defined[TS_PID_PAT] = 1;
    defined[TS_PID_NULL] = 1;
    for (uint16_t pid = 0; pid < 8192; pid++) {
        if (is_well_known_si_pid(pid)) defined[pid] = 1;
    }
    for (size_t i = 0; i < pat->program_count; i++) {
        if (pat->programs[i].pid < 8192) defined[pat->programs[i].pid] = 1;
    }
    for (size_t i = 0; i < pmt_capacity && pmt_table; i++) {
        if (pmt_table[i].pcr_pid < 8192) defined[pmt_table[i].pcr_pid] = 1;
        for (size_t j = 0; j < pmt_table[i].es_count; j++) {
            if (pmt_table[i].es_list[j].elementary_pid < 8192)
                defined[pmt_table[i].es_list[j].elementary_pid] = 1;
        }
    }
    for (size_t i = 0; i < list->count; i++) {
        uint16_t pid = list->pids[i].pid;
        if (pid < 8192 && !defined[pid])
            g_string_append_printf(out, "Undefined PID: 0x%04X (packets: %zu)\n", (unsigned)pid, list->pids[i].count);
    }
}

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

void gui_show_validation_popup(GtkWindow* parent, const char* path) {
    if (!path) return;
    FILE* f = fopen(path, "rb");
    if (!f) return;
    ts_validate_result_t result;
    if (analyze_validate(f, &result) != 0) {
        fclose(f);
        return;
    }
    fclose(f);
    char* message = build_validation_message(&result, path);
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
    gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);
    gtk_window_set_title(GTK_WINDOW(dialog), "Validation");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 620, 460);

    GtkWidget* container = create_popup_content_box();

    GtkWidget* header = create_validation_header(errors_found, path);
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

static void packet_summary_string(const ts_packet_t* p, size_t index, char* buf, size_t buf_size) {
    const char* af = (p->adaptation_field_control == 3u) ? "adapt + payload" :
                     (p->adaptation_field_control == 2u) ? "adaptation only" :
                     (p->adaptation_field_control == 1u) ? "payload only" : "none";
    (void)snprintf(buf, buf_size, "Packet %zu  ·  PID 0x%04X  ·  Continuity %u  ·  %s  ·  %u bytes",
                   index, (unsigned)p->pid, (unsigned)p->continuity_counter, af, (unsigned)p->payload_length);
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

void gui_show_stats_popup(GtkWindow* parent, const char* path) {
    if (!path) return;

    FILE* f = fopen(path, "rb");
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
    gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);
    gtk_window_set_title(GTK_WINDOW(dialog), "Stream stats");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 700, 500);

    GtkWidget* container = create_popup_content_box();
    {
        const char* base = g_path_get_basename(path);
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

    cairo_set_source_rgb(cr, 0.2, 0.6, 0.95);
    cairo_set_line_width(cr, 1.5);
    for (size_t i = 0; i < j->preview_row_count; i++) {
        double x = margin_l + (double)(unsigned long)i / (double)(unsigned long)(j->preview_row_count > 1u ? j->preview_row_count - 1u : 1u) * (double)plot_w;
        double y = margin_t + plot_h * (1.0 - (j->preview_rows[i].offset_ms - y_min) / y_range);
        if (i == 0) cairo_move_to(cr, x, y);
        else cairo_line_to(cr, x, y);
    }
    cairo_stroke(cr);

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

void gui_show_jitter_popup(GtkWindow* parent, const char* path) {
    if (!path) return;
    FILE* f = fopen(path, "rb");
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
    gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);
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

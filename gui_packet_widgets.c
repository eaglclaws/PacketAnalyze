#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glib.h>
#include "gui_packet_widgets.h"
#include "utils.h"

#define TS_PACKET_SIZE 188
#define EXPANDER_REVEAL_DURATION_MS 200

static void format_pts_dts(uint64_t ts_90k, char* buf, size_t buf_size) {
    uint64_t total_ms = (ts_90k * 1000u) / 90000u;
    uint64_t hours = total_ms / 3600000u;
    uint64_t minutes = (total_ms % 3600000u) / 60000u;
    uint64_t seconds = (total_ms % 60000u) / 1000u;
    uint64_t millis = total_ms % 1000u;
    (void)snprintf(buf, buf_size, "%" G_GUINT64_FORMAT ":%02" G_GUINT64_FORMAT ":%02" G_GUINT64_FORMAT ".%03" G_GUINT64_FORMAT,
                   hours, minutes, seconds, millis);
}

int gui_path_is_ts_file(const char* path) {
    const char* dot = strrchr(path, '.');
    if (!dot || dot == path) return 0;
    dot++;
    if (g_ascii_strcasecmp(dot, "ts") == 0) return 1;
    if (g_ascii_strcasecmp(dot, "tp") == 0) return 1;
    if (g_ascii_strcasecmp(dot, "m2ts") == 0) return 1;
    return 0;
}

GtkWidget* gui_create_popup_content_box(void) {
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_add_css_class(box, "popup-container");
    gtk_widget_set_margin_top(box, 14);
    gtk_widget_set_margin_bottom(box, 14);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);
    return box;
}

GtkWidget* gui_create_popup_header(const char* title_text, const char* subtitle_text) {
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

void gui_update_stream_overview(GtkWidget* title_widget, GtkWidget* meta_widget, const char* path,
                                size_t packet_count, size_t observed_pid_count, size_t program_count) {
    if (!title_widget || !meta_widget) return;
    const char* base = path ? g_path_get_basename(path) : "(unknown)";
    char title_text[320];
    snprintf(title_text, sizeof title_text, "[%s]", base);
    gtk_label_set_text(GTK_LABEL(title_widget), title_text);
    if (path) g_free((gpointer)base);

    guint64 bytes = (guint64)packet_count * (guint64)TS_PACKET_SIZE;
    char* pretty_size = g_format_size_full(bytes, G_FORMAT_SIZE_IEC_UNITS);
    char meta_text[512];
    snprintf(meta_text, sizeof meta_text,
             "Packets: %zu  •  Observed PIDs: %zu  •  Programs: %zu  •  Parsed size: %s",
             packet_count, observed_pid_count, program_count, pretty_size ? pretty_size : "n/a");
    if (pretty_size) g_free(pretty_size);
    gtk_label_set_text(GTK_LABEL(meta_widget), meta_text);
}

GtkWidget* gui_pes_packet_detail_grid(const pes_packet_t* p, size_t index) {
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

void gui_packet_summary_string(const ts_packet_t* p, size_t index, char* buf, size_t buf_size) {
    if (p->tei) {
        snprintf(buf, buf_size, "Pkt %zu | PID 0x%04X | TEI=1 (transport error)", index, (unsigned)p->pid);
        return;
    }
    snprintf(buf, buf_size, "Pkt %zu | PID 0x%04X | CC %u", index, (unsigned)p->pid, (unsigned)p->continuity_counter);
}

char* gui_packet_psi_summary(const uint8_t* raw, const ts_packet_t* p, size_t buffer_len, const pat_table_t* pat) {
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

static void collapse_descendant_expanders(GtkWidget* root) {
    if (!root) return;
    for (GtkWidget* child = gtk_widget_get_first_child(root);
         child != NULL;
         child = gtk_widget_get_next_sibling(child)) {
        if (GTK_IS_EXPANDER(child) && gtk_expander_get_expanded(GTK_EXPANDER(child))) {
            gtk_expander_set_expanded(GTK_EXPANDER(child), FALSE);
        }
        collapse_descendant_expanders(child);
    }
}

static GtkExpander* first_expander_child(GtkWidget* row) {
    for (GtkWidget* child = gtk_widget_get_first_child(row);
         child != NULL;
         child = gtk_widget_get_next_sibling(child)) {
        if (GTK_IS_EXPANDER(child)) return GTK_EXPANDER(child);
    }
    return NULL;
}

static void collapse_sibling_expanders(GtkExpander* exp) {
    GtkWidget* parent_box = GTK_WIDGET(g_object_get_data(G_OBJECT(exp), "accordion-parent"));
    if (!parent_box) return;
    for (GtkWidget* row = gtk_widget_get_first_child(parent_box);
         row != NULL;
         row = gtk_widget_get_next_sibling(row)) {
        GtkExpander* sibling = first_expander_child(row);
        if (!sibling || sibling == exp) continue;
        if (gtk_expander_get_expanded(sibling)) {
            gtk_expander_set_expanded(sibling, FALSE);
        }
    }
}

static void expander_expanded_notify_cb(GtkExpander* exp, GParamSpec* pspec, gpointer user_data) {
    (void)pspec;
    (void)user_data;
    GtkRevealer* rev = GTK_REVEALER(g_object_get_data(G_OBJECT(exp), "packet-revealer"));
    if (!rev) return;
    if (gtk_expander_get_expanded(exp)) {
        if (g_object_get_data(G_OBJECT(exp), "packet-animating-collapse"))
            return;
        collapse_sibling_expanders(exp);
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
        collapse_descendant_expanders(gtk_revealer_get_child(rev));
        g_object_set_data(G_OBJECT(exp), "packet-animating-collapse", GINT_TO_POINTER(1));
        gtk_expander_set_expanded(exp, TRUE);
        gtk_revealer_set_reveal_child(rev, FALSE);
        guint id = g_timeout_add(EXPANDER_REVEAL_DURATION_MS, expander_collapse_timeout_cb, exp);
        g_object_set_data(G_OBJECT(exp), "collapse-timeout-id", GUINT_TO_POINTER(id));
    }
}

void gui_expander_set_animated_child(GtkExpander* exp, GtkWidget* child, unsigned int duration_ms) {
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
            const char* start = sec_mark + ((strncmp(sec_mark, " sec ", 5) == 0) ? 5 : 2);
            const char* end = prog_mark ? prog_mark : head + strlen(head);
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("Section", tmp); }
        }
        if (prog_mark) {
            const char* start = prog_mark + 3;
            PSI_ROW("Programs", start);
        }
        for (int i = 1; parts && parts[i]; i++) {
            if (g_str_has_prefix(parts[i], "PNO ")) {
                const char* arrow = strstr(parts[i], " -> PID ");
                if (arrow) {
                    char pno_txt[64];
                    char pid_txt[128];
                    size_t kn = (size_t)(arrow - (parts[i] + 4));
                    if (kn > 0 && kn < 32) {
                        memcpy(pno_txt, parts[i] + 4, kn); pno_txt[kn] = '\0';
                        snprintf(pid_txt, sizeof pid_txt, "PID %s", arrow + 8);
                        char keybuf[80];
                        snprintf(keybuf, sizeof keybuf, "Program %s", pno_txt);
                        PSI_ROW(keybuf, pid_txt);
                    }
                }
            }
        }
        g_strfreev(parts);
    } else if (g_str_has_prefix(psi_summary, "PMT:")) {
        char** parts = g_strsplit(psi_summary, "; ", -1);
        const char* head = parts && parts[0] ? parts[0] : psi_summary;
        const char* prog_mark = strstr(head, "program ");
        const char* pcr_mark = strstr(head, ", PCR PID ");
        const char* es_mark = strstr(head, " - ");
        char tmp[128];
        if (prog_mark) {
            const char* start = prog_mark + 8;
            const char* end = pcr_mark ? pcr_mark : (es_mark ? es_mark : head + strlen(head));
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("Program", tmp); }
        }
        if (pcr_mark) {
            const char* start = pcr_mark + 10;
            const char* end = es_mark ? es_mark : head + strlen(head);
            size_t n = (size_t)(end > start ? (end - start) : 0);
            if (n > 0 && n < sizeof tmp) { memcpy(tmp, start, n); tmp[n] = '\0'; PSI_ROW("PCR PID", tmp); }
        }
        if (es_mark) {
            const char* start = es_mark + 3;
            PSI_ROW("Streams", start);
        }
        for (int i = 1; parts && parts[i]; i++) {
            if (g_str_has_prefix(parts[i], "PID ")) {
                const char* sp = strchr(parts[i] + 4, ' ');
                if (sp) {
                    char pid[32];
                    size_t pn = (size_t)(sp - (parts[i] + 4));
                    if (pn > 0 && pn < sizeof pid) {
                        memcpy(pid, parts[i] + 4, pn); pid[pn] = '\0';
                        char keybuf[80];
                        snprintf(keybuf, sizeof keybuf, "ES %d", i);
                        char valbuf[128];
                        snprintf(valbuf, sizeof valbuf, "PID %s  %s", pid, sp + 1);
                        PSI_ROW(keybuf, valbuf);
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

GtkWidget* gui_packet_detail_grid(const ts_packet_t* p, size_t index, const char* psi_summary) {
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

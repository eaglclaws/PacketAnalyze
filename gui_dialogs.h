#ifndef GUI_DIALOGS_H
#define GUI_DIALOGS_H

#include <stddef.h>
#include <gtk/gtk.h>

/* Show a popup window with hex dump of the packet at the given index in the file. */
void gui_show_hexdump_popup(const char* path, size_t packet_index, GtkWindow* parent);

/* Run validation and show the validation popup for the selected file. */
void gui_show_validation_popup(GtkWindow* parent, const char* path);

/* Show stream stats popup for the selected file. */
void gui_show_stats_popup(GtkWindow* parent, const char* path);

/* Show jitter analysis popup for the selected file. */
void gui_show_jitter_popup(GtkWindow* parent, const char* path);

#endif // GUI_DIALOGS_H

CC := gcc
PKG_CONFIG := pkg-config

OUT_DIR := build
DEBUG_DIR := $(OUT_DIR)/Debug
RELEASE_DIR := $(OUT_DIR)/Release
SAN_DIR := $(OUT_DIR)/Sanitized

APP := packet_analyze
APP_DEBUG := $(DEBUG_DIR)/outDebug
APP_RELEASE := $(RELEASE_DIR)/outRelease
APP_SAN := $(SAN_DIR)/outSanitized
PARSER_TEST_DEBUG := $(DEBUG_DIR)/parser_test
PARSER_TEST_SAN := $(SAN_DIR)/parser_test

COMMON_WARN := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wcast-align \
	-Wconversion -Wsign-conversion -Wnull-dereference
COMMON_CFLAGS := $(COMMON_WARN)
DEBUG_CFLAGS := $(COMMON_CFLAGS) -g3 -O0
RELEASE_CFLAGS := $(COMMON_CFLAGS) -O2 -DNDEBUG
SAN_CFLAGS := $(DEBUG_CFLAGS) -fno-omit-frame-pointer -fsanitize=address,undefined

GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk4)
GTK_LIBS := $(shell $(PKG_CONFIG) --libs gtk4)
LDLIBS := -lm

APP_SRCS := main.c ts_pipeline.c parser.c utils.c utils_store.c utils_print.c gui_entry.c gui_dialogs.c gui_packet_widgets.c gui_packet_list.c
PARSER_TEST_SRCS := parser_test.c parser.c utils.c utils_store.c utils_print.c
ALL_HDRS := $(wildcard *.h)

.PHONY: all debug release sanitize parser_test parser_test_sanitize clean \
	run run_release run_sanitize run_sanitize_gui regress regress_sanitize help

all: debug

debug: $(APP_DEBUG)

release: $(APP_RELEASE)

sanitize: $(APP_SAN)

parser_test: $(PARSER_TEST_DEBUG)

parser_test_sanitize: $(PARSER_TEST_SAN)

$(APP_DEBUG): $(APP_SRCS) $(ALL_HDRS)
	@mkdir -p "$(DEBUG_DIR)"
	$(CC) $(DEBUG_CFLAGS) $(GTK_CFLAGS) $(APP_SRCS) $(GTK_LIBS) $(LDLIBS) -o "$@"

$(APP_RELEASE): $(APP_SRCS) $(ALL_HDRS)
	@mkdir -p "$(RELEASE_DIR)"
	$(CC) $(RELEASE_CFLAGS) $(GTK_CFLAGS) $(APP_SRCS) $(GTK_LIBS) $(LDLIBS) -o "$@"

$(APP_SAN): $(APP_SRCS) $(ALL_HDRS)
	@mkdir -p "$(SAN_DIR)"
	$(CC) $(SAN_CFLAGS) $(GTK_CFLAGS) $(APP_SRCS) $(GTK_LIBS) $(LDLIBS) -o "$@"

$(PARSER_TEST_DEBUG): $(PARSER_TEST_SRCS) $(ALL_HDRS)
	@mkdir -p "$(DEBUG_DIR)"
	$(CC) $(DEBUG_CFLAGS) $(PARSER_TEST_SRCS) -o "$@"

$(PARSER_TEST_SAN): $(PARSER_TEST_SRCS) $(ALL_HDRS)
	@mkdir -p "$(SAN_DIR)"
	$(CC) $(SAN_CFLAGS) $(PARSER_TEST_SRCS) -o "$@"

run: debug
	"$(APP_DEBUG)" --gui

run_release: release
	"$(APP_RELEASE)" --gui

run_sanitize: sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	"$(APP_SAN)" --gui

run_sanitize_gui: sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	LSAN_OPTIONS=suppressions="$(CURDIR)/lsan.supp" \
	"$(APP_SAN)" --gui

regress: debug
	tests/run_regression.sh "$(APP_DEBUG)"

regress_sanitize: sanitize
	tests/run_sanitizer_regression.sh "$(APP_SAN)"

clean:
	rm -rf "$(OUT_DIR)"

help:
	@echo "Targets:"
	@echo "  make debug            Build debug binary ($(APP_DEBUG))"
	@echo "  make release          Build release binary ($(APP_RELEASE))"
	@echo "  make sanitize         Build ASan/UBSan binary ($(APP_SAN))"
	@echo "  make parser_test      Build parser tests ($(PARSER_TEST_DEBUG))"
	@echo "  make parser_test_sanitize Build sanitized parser tests ($(PARSER_TEST_SAN))"
	@echo "  make regress          Run regression suite with debug binary"
	@echo "  make regress_sanitize Run regression + sanitizer sweep"
	@echo "  make run              Build debug and launch GUI"
	@echo "  make run_sanitize_gui Build sanitized binary, run GUI with LSan suppressions"
	@echo "  make clean            Remove build directory"

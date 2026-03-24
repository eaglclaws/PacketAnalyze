# PacketAnalyze

CLI and GTK4 GUI for inspecting MPEG-2 Transport Stream (TS) files: packet headers, PSI (PAT/PMT), validation (continuity counter, sync, undefined PIDs), hexdumps, PCR jitter, and PES summaries.

**Input contract:** the tool assumes **188-byte aligned TS packets from byte 0** (sync byte `0x47`). It does **not** resynchronize if sync is lost; decoded fields may be unreliable when sync errors are present.

---

## Dependencies

### Build

| Requirement | Notes |
|-------------|--------|
| **C compiler** | GCC or Clang with C11 support |
| **pkg-config** | Used to locate GTK 4 |
| **GTK 4** | Development headers and libraries (`gtk4` in pkg-config) |
| **Math library** | `-lm` (standard on Unix) |

Typical distro packages:

- **Fedora / RHEL:** `gcc`, `pkg-config`, `gtk4-devel`
- **Debian / Ubuntu:** `build-essential`, `pkg-config`, `libgtk-4-dev`
- **Arch:** `base-devel`, `gtk4`

Optional:

- **AddressSanitizer / UndefinedBehaviorSanitizer** — usually provided with the same GCC package (`libasan` / `libubsan` may be separate on some distros; the Makefile uses `-fsanitize=address,undefined` for `sanitize` targets).

---

## Build

From the repository root:

```bash
make debug          # default: build/Debug/outDebug
make release        # build/Release/outRelease
make sanitize       # ASan + UBSan: build/Sanitized/outSanitized
make parser_test    # build/Debug/parser_test (no GUI)
make clean          # remove build/
make help           # list targets
```

Manual compile (equivalent to debug app):

```bash
mkdir -p build/Debug
gcc -Wall -Wextra -Wpedantic -Iinclude -g3 -O0 \
  src/main.c src/ts_pipeline.c src/parser.c src/utils.c src/utils_store.c src/utils_print.c \
  src/gui_entry.c src/gui_dialogs.c src/gui_packet_widgets.c src/gui_packet_list.c \
  $(pkg-config --cflags --libs gtk4) -lm -o build/Debug/outDebug
```

---

## Running

- **GUI:** run the binary with no arguments, or `--gui`:

  ```bash
  ./build/Debug/outDebug
  ./build/Debug/outDebug --gui
  ```

  Or: `make run` (builds debug and launches the GUI).

- **CLI:** requires a transport stream path with extension **`.ts`**, **`.tp`**, or **`.m2ts`** (case-insensitive).

---

## CLI usage

Replace `./build/Debug/outDebug` with your built binary path.

| Command | Description |
|---------|-------------|
| `./build/Debug/outDebug --packets <file>` | Print a header line per TS packet and PID ratio statistics |
| `./build/Debug/outDebug --psi-analyze <file>` | Print PAT, PMT, and descriptor-related information |
| `./build/Debug/outDebug --validate <file>` | Report CC errors, sync loss, undefined PIDs; or a “no errors” line |
| `./build/Debug/outDebug --hexdump <file> <n>` | Hexdump of packet **0-based** index `<n>` |
| `./build/Debug/outDebug --jitter-test <file>` | PCR jitter metrics and a text visualization |
| `./build/Debug/outDebug --pes <file>` | Print PES data for program elementary streams |

**Examples:**

```bash
# Long output — use a pager
./build/Debug/outDebug --packets recording.ts | less -S

./build/Debug/outDebug --validate sample.ts
./build/Debug/outDebug --hexdump sample.ts 0
```

If `--packets` reports sync loss, the program may print a warning that decoded fields may be unreliable (aligned-input contract).

---

## Tests and regression

```bash
make parser_test
./build/Debug/parser_test

make regress              # needs test corpus paths expected by tests/run_regression.sh
make regress_sanitize
```

---

## Documentation (Doxygen)

If [Doxygen](https://www.doxygen.nl/) is installed:

```bash
doxygen Doxyfile
```

HTML output is generated under `docs/html/` (see `Doxyfile`; `docs/` may be gitignored).

---

## Project layout

| Path | Purpose |
|------|---------|
| `src/` | C sources (`main.c`, pipeline, parser, GUI) |
| `include/` | Public headers |
| `tests/` | Regression scripts (`run_regression.sh`, etc.) |
| `build/` | Build outputs (created by `make`) |

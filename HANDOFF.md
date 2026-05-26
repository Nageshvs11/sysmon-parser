# Sysmon Parser — Handoff

## What We Built

A Python CLI that parses Sysmon **Event ID 1 (Process Creation)** XML and outputs structured JSON.

### Files

| File | Purpose |
|------|---------|
| `parser.py` | XML parsing, field extraction, CLI entry point, and filter logic |
| `samples/event1.xml` | Single whoami.exe event (CONDEF\Administrator) |
| `samples/event2.xml` | Single cmd.exe event |
| `samples/event3.xml` | Single mshta → powershell event (CONDEF\jsmith) |
| `samples/multi_events.xml` | Three events in one `<Events>` wrapper |

### What `parser.py` does

- Parses raw Sysmon XML files (single `<Event>` or a multi-event wrapper)
- Extracts 10 fields: `EventID`, `UtcTime`, `Image`, `CommandLine`, `User`, `IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`
- Outputs a single JSON object for one event, or a JSON array for multiple
- Supports four CLI filters: `--image`, `--cmdline`, `--user`, `--integrity`
- Accepts multiple input files in one invocation

## How to Use

```bash
# Single file
python parser.py samples/event1.xml

# Multiple files
python parser.py samples/event1.xml samples/event2.xml

# Filter by image (case-insensitive substring)
python parser.py samples/multi_events.xml --image powershell

# Filter by integrity level
python parser.py samples/multi_events.xml --integrity High

# Filter by exact user
python parser.py samples/multi_events.xml --user "CONDEF\\jsmith"

# Combine filters
python parser.py samples/multi_events.xml --image powershell --integrity Medium
```

Output is always to stdout. Pipe to `jq` for pretty-printing or field extraction.

## What's Left to Do

- **`.evtx` support** — CLAUDE.md describes reading binary `.evtx` files via `python-evtx`, but the current implementation only handles raw XML. The `reader.py` module described in the architecture doesn't exist yet.
- **Package structure** — CLAUDE.md specifies a `sysmon_parser/` package with `__main__.py`, `reader.py`, `output.py`, and `parser.py`. Currently everything is a single flat `parser.py` at the repo root.
- **`requirements.txt`** — No dependency file exists yet (`python-evtx`, `lxml` are listed in CLAUDE.md but not pinned).
- **Tests** — No `tests/` directory or pytest fixtures exist yet.
- **`output.py`** — JSON serialization is currently inlined in `parser.py`'s `__main__` block rather than in a dedicated module.
- **EventID filtering** — Parser assumes all input is Event ID 1. When `.evtx` support is added, it will need to filter out non-ID-1 records.

## Decisions Made and Why

**stdlib `xml.etree.ElementTree` instead of `lxml`**
CLAUDE.md lists `lxml` as a key dependency, but the current implementation uses the stdlib `xml.etree.ElementTree`. This avoids a native dependency for the XML-only stage and is sufficient for well-formed Sysmon XML. Switch to `lxml` when `.evtx` parsing is added, since `python-evtx` output may need it.

**Single file instead of package**
The full `sysmon_parser/` package layout described in CLAUDE.md was deferred. All logic lives in `parser.py` for now to get a working parser quickly. Refactor into the package structure when adding `.evtx` support, since that's the natural seam.

**Output format: object vs. array**
A single event with no filters prints as a plain JSON object (not a one-element array) for friendlier `jq` piping. As soon as filters are applied or multiple files are passed, output is always an array — this keeps the behavior predictable.

**Filter semantics**
`--image` and `--cmdline` are case-insensitive substring matches (analyst-friendly). `--user` is an exact match (usernames are structured). `--integrity` is constrained to the four valid Sysmon values via `choices=` in argparse.

**Sample data**
The `samples/` XMLs use real-looking Sysmon events from a `CONDEF` domain, including a suspicious mshta → PowerShell Base64-encoded reverse shell (event3 / third event in multi_events.xml). These cover the main filter dimensions: different users, integrity levels, and image paths.

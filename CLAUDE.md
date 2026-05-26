# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Python tool that parses Sysmon XML and extracts key fields from **Event ID 1 (Process Creation)** events, outputting structured JSON. Input is Sysmon XML (embedded in `.evtx` files); output is one JSON object per event or a JSON array for multiple events.

## Common Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the parser
python -m sysmon_parser <path/to/file.evtx>

# Run all tests
pytest

# Run a single test file
pytest tests/test_events.py

# Run a single test by name
pytest tests/test_events.py::test_process_create_parsing

# Lint
flake8 sysmon_parser/
```

## Fields Extracted (Event ID 1)

All fields come from `EventData/Data[@Name]` or `System` in the Sysmon XML:

| Field | XML source |
|-------|-----------|
| `EventID` | `System/EventID` |
| `UtcTime` | `EventData/Data[@Name="UtcTime"]` |
| `Image` | `EventData/Data[@Name="Image"]` |
| `CommandLine` | `EventData/Data[@Name="CommandLine"]` |
| `User` | `EventData/Data[@Name="User"]` |
| `IntegrityLevel` | `EventData/Data[@Name="IntegrityLevel"]` |
| `ParentImage` | `EventData/Data[@Name="ParentImage"]` |
| `ParentCommandLine` | `EventData/Data[@Name="ParentCommandLine"]` |
| `Computer` | `System/Computer` |
| `Hashes` | `EventData/Data[@Name="Hashes"]` |

## Architecture

```
sysmon_parser/
├── __main__.py   # CLI entry point
├── reader.py     # .evtx file reading via python-evtx (yields raw XML strings)
├── parser.py     # XML extraction and field normalization for Event ID 1
└── output.py     # JSON serialization (single object or array)
tests/
└── fixtures/     # Sample .evtx files and expected output JSON
```

**Data flow:** `.evtx` → `reader.py` (yields raw XML per record) → `parser.py` (lxml parse, filters EventID==1, extracts fields) → `output.py` → stdout or file.

## Key Dependencies

- [`python-evtx`](https://github.com/williballenthin/python-evtx) — reads binary `.evtx` files; yields raw XML per record
- `lxml` — XML parsing for event data extraction
- `dataclasses` / `pydantic` — typed event models

## Output Format

Single event:
```json
{
  "EventID": "1",
  "UtcTime": "2024-01-01 00:00:00.000",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "User": "DOMAIN\\user",
  "IntegrityLevel": "High",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "ParentCommandLine": "explorer.exe",
  "Computer": "HOSTNAME",
  "Hashes": "SHA256=abc123..."
}
```

Multiple events output as a JSON array.

## Sysmon XML Structure

Each event record has this shape inside the `.evtx` XML envelope:

```xml
<Event>
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2024-01-01T00:00:00.000000Z"/>
    <Computer>HOSTNAME</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">...</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    ...
  </EventData>
</Event>
```

Fields live under `EventData/Data[@Name]`. The `System` block contains metadata common to all event types.

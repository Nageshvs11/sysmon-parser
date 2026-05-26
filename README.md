# sysmon-parser

A Python CLI that parses Sysmon **Event ID 1 (Process Creation)** XML and outputs structured data for analysis and triage.

## Features

- Extracts 10 key fields from Sysmon Event ID 1 records
- Supports single events and multi-event XML files
- Filter events by image, command line, user, or integrity level
- Three output formats: JSON, JSONL, CSV
- Quick triage stats (`--stats`) before deep analysis

## Usage

```bash
python parser.py <FILE> [FILE ...] [options]
```

### Basic examples

```bash
# Parse a single event — outputs a JSON object
python parser.py samples/event1.xml

# Parse a multi-event file — outputs a JSON array
python parser.py samples/multi_events.xml
```

### Filtering

```bash
# Events where Image contains "powershell" (case-insensitive)
python parser.py samples/multi_events.xml --image powershell

# Events where CommandLine contains a string
python parser.py samples/multi_events.xml --cmdline "-Enc"

# Events for a specific user (exact match)
python parser.py samples/multi_events.xml --user "CONDEF\\jsmith"

# Events at a specific integrity level: High, Medium, Low, System
python parser.py samples/multi_events.xml --integrity Medium

# Combine filters
python parser.py samples/multi_events.xml --image powershell --integrity Medium
```

### Output formats

```bash
# JSON array (default)
python parser.py samples/multi_events.xml --format json

# JSONL — one object per line, good for streaming/piping
python parser.py samples/multi_events.xml --format jsonl

# CSV with headers
python parser.py samples/multi_events.xml --format csv
```

### Triage stats

```bash
# Summary statistics instead of raw events
python parser.py samples/multi_events.xml --stats
```

```json
{
  "total_events": 3,
  "unique_processes": 2,
  "unique_users": 2,
  "events_by_integrity_level": {
    "High": 2,
    "Medium": 1
  }
}
```

Stats also compose with filters — e.g. `--stats --user "CONDEF\\jsmith"` to triage a single user's activity.

### Multiple files

```bash
python parser.py samples/event1.xml samples/event2.xml samples/event3.xml --format csv
```

## Fields Extracted

| Field | Source |
|-------|--------|
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

## Output Example

Single event (no filters applied):

```json
{
  "EventID": "1",
  "UtcTime": "2024-12-01 16:05:11.850",
  "Image": "C:\\Windows\\System32\\whoami.exe",
  "CommandLine": "whoami  /groups",
  "User": "CONDEF\\Administrator",
  "IntegrityLevel": "High",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentCommandLine": "\"C:\\WINDOWS\\system32\\cmd.exe\"",
  "Computer": "win11v.condef.local",
  "Hashes": "SHA1=C23488BA47...,MD5=956692DA...,SHA256=23240EF9..."
}
```

## Project Structure

```
sysmon-parser/
├── parser.py          # XML parsing, filtering, output, and CLI
├── samples/
│   ├── event1.xml     # whoami.exe (CONDEF\Administrator)
│   ├── event2.xml     # cmd.exe
│   ├── event3.xml     # mshta → powershell reverse shell (CONDEF\jsmith)
│   └── multi_events.xml  # All three events in one file
└── HANDOFF.md         # Dev context: decisions, gaps, next steps
```

## What's Not Implemented Yet

- **`.evtx` support** — currently parses raw XML only; binary Event Log files require `python-evtx`
- **Tests** — no pytest suite yet
- **`requirements.txt`** — no pinned dependencies

## Dependencies

- Python 3.8+ (stdlib only — `xml.etree.ElementTree`, `csv`, `json`)
- No third-party packages required for current XML-based parsing

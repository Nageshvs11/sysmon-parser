import argparse
import csv
import io
import json
import xml.etree.ElementTree as ET

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def parse_event_element(event_el):
    system = event_el.find(f"{{{NS}}}System")
    event_data = event_el.find(f"{{{NS}}}EventData")

    def sys_text(tag):
        el = system.find(f"{{{NS}}}{tag}")
        return el.text if el is not None else None

    def data_field(name):
        for el in event_data.findall(f"{{{NS}}}Data"):
            if el.get("Name") == name:
                return el.text
        return None

    return {
        "EventID": sys_text("EventID"),
        "UtcTime": data_field("UtcTime"),
        "Image": data_field("Image"),
        "CommandLine": data_field("CommandLine"),
        "User": data_field("User"),
        "IntegrityLevel": data_field("IntegrityLevel"),
        "ParentImage": data_field("ParentImage"),
        "ParentCommandLine": data_field("ParentCommandLine"),
        "Computer": sys_text("Computer"),
        "Hashes": data_field("Hashes"),
    }


def parse_file(path):
    root = ET.parse(path).getroot()
    event_tag = f"{{{NS}}}Event"
    if root.tag == event_tag:
        return parse_event_element(root)
    events = [parse_event_element(el) for el in root.iter(event_tag)]
    return events[0] if len(events) == 1 else events


def apply_filters(events, image=None, cmdline=None, user=None, integrity=None):
    if image:
        events = [e for e in events if e.get("Image") and image.lower() in e["Image"].lower()]
    if cmdline:
        events = [e for e in events if e.get("CommandLine") and cmdline.lower() in e["CommandLine"].lower()]
    if user:
        events = [e for e in events if e.get("User") == user]
    if integrity:
        events = [e for e in events if e.get("IntegrityLevel") == integrity]
    return events


FIELDS = [
    "EventID", "UtcTime", "Image", "CommandLine", "User",
    "IntegrityLevel", "ParentImage", "ParentCommandLine", "Computer", "Hashes",
]


# This stats feature is for quick triage to understand what's in a file before deep analysis
def compute_stats(events):
    from collections import Counter
    integrity_counts = Counter(e.get("IntegrityLevel") or "Unknown" for e in events)
    return {
        "total_events": len(events),
        "unique_processes": len({e.get("Image") for e in events if e.get("Image")}),
        "unique_users": len({e.get("User") for e in events if e.get("User")}),
        "events_by_integrity_level": dict(integrity_counts),
    }


def output_events(events, fmt, any_filter):
    if fmt == "jsonl":
        for event in events:
            print(json.dumps(event))
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(events)
        print(buf.getvalue(), end="")
    else:  # json
        if not any_filter and len(events) == 1:
            print(json.dumps(events[0], indent=2))
        else:
            print(json.dumps(events, indent=2))


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Parse Sysmon Event ID 1 XML files")
    arg_parser.add_argument("files", nargs="+", metavar="FILE")
    arg_parser.add_argument("--image",     metavar="TEXT",  help="keep events where Image contains TEXT (case-insensitive)")
    arg_parser.add_argument("--cmdline",   metavar="TEXT",  help="keep events where CommandLine contains TEXT (case-insensitive)")
    arg_parser.add_argument("--user",      metavar="TEXT",  help="keep events where User matches exactly")
    arg_parser.add_argument("--integrity", metavar="LEVEL", choices=["High", "Medium", "Low", "System"],
                            help="keep events matching IntegrityLevel")
    arg_parser.add_argument("--format",    metavar="FMT",   choices=["json", "jsonl", "csv"], default="json",
                            help="output format: json (default), jsonl, or csv")
    arg_parser.add_argument("--stats",     action="store_true",
                            help="print summary statistics instead of events")
    args = arg_parser.parse_args()

    all_events = []
    for path in args.files:
        parsed = parse_file(path)
        if isinstance(parsed, list):
            all_events.extend(parsed)
        else:
            all_events.append(parsed)

    filtered = apply_filters(all_events, args.image, args.cmdline, args.user, args.integrity)
    any_filter = args.image or args.cmdline or args.user or args.integrity

    if args.stats:
        print(json.dumps(compute_stats(filtered), indent=2))
    else:
        output_events(filtered, args.format, any_filter)

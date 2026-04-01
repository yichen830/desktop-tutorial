#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


TIME_FIELDS = ("timestamp", "time", "@timestamp", "event_time")
IOC_FIELDS = ("ioc", "indicator", "ip", "domain", "hash", "file")


def load_events(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def pick_time(event: dict) -> str:
    for field in TIME_FIELDS:
        value = event.get(field)
        if value:
            return str(value)
    return "unknown"


def normalize_time(value: str) -> str:
    if value == "unknown":
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return value


def summarize_iocs(events: list[dict]) -> Counter:
    counter: Counter = Counter()
    for event in events:
        for field in IOC_FIELDS:
            value = event.get(field)
            if value:
                counter[f"{field}:{value}"] += 1
    return counter


def build_timeline(events: list[dict]) -> list[dict]:
    normalized = []
    for event in events:
        normalized.append(
            {
                "time": normalize_time(pick_time(event)),
                "source": event.get("source", "unknown"),
                "summary": event.get("summary", event.get("message", "")),
                "raw": event,
            }
        )
    return sorted(normalized, key=lambda item: item["time"])


def main() -> None:
    parser = argparse.ArgumentParser(description="简单 IOC 时间线整理工具")
    parser.add_argument("--input", required=True, help="输入 JSON 文件，内容为事件数组")
    args = parser.parse_args()

    events = load_events(Path(args.input))
    timeline = build_timeline(events)
    iocs = summarize_iocs(events)

    report = {
        "event_count": len(events),
        "top_iocs": iocs.most_common(10),
        "timeline": timeline,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

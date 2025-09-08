#!/usr/bin/env python3
"""
Generate NDJSON that guarantees **one burst correlation** for a 60-second bucket detector
Strategy:
- Build baseline for *both* series (monitor + resource tokens present in the same event)
  40 non-empty minutes (16:10–16:49), 1 event each minute
- Two burst minutes with heavy counts:
  16:50 (8 events), 16:53 (8 events)
This yields z ≈ 4.42 and 2 aligned spikes → reported as 1 burst correlation.
"""

import json
from datetime import datetime, timezone, timedelta

def iso_to_ms(iso):
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)

def make_event(ts_iso: str, idx: str, msg: str, resource_name: str = "web-app", extra_tags=None):
    """Create an event for a specific resource to enable burst correlation detection."""
    ts_ms = iso_to_ms(ts_iso)

    # Create CONSISTENT resource identifiers (same pod names for baseline and bursts)
    pod_name = f"{resource_name}-main-pod"  # Same pod name for all events of this resource
    resource_id = f"mit-acme/{pod_name}"
    monitor_id = 15079192 if resource_name == "web-app" else 15079193

    evt = {
        "count": 1,
        "currentStatus": "Alert",
        "event": {
            "attributes": {
                "attributes": {
                    "_dd": {"has_notification": False, "internal": "1", "version": "1"},
                    "evt": {
                        "id": f"evt-{idx}",
                        "name": f"[Kubernetes] {resource_name.title()} Monitor",
                        "type": "query_alert_monitor"
                    },
                    "monitor": {
                        "id": monitor_id,
                        "name": f"[Kubernetes] {resource_name.title()} Monitor",
                        "templated_name": f"[Kubernetes] {resource_name.title()} Monitor on kube_cluster_name:mit-acme,pod_name:{pod_name},kube_namespace:production",
                        "type": "query alert",
                        "groups": ["kube_cluster_name:mit-acme", f"pod_name:{pod_name}", "kube_namespace:production"],
                        "result": {"group_key": "kube_cluster_name,pod_name,kube_namespace"}
                    },
                    # include timestamp in nested attributes (your parser reads from here)
                    "timestamp": ts_ms
                },
                # optional explicit resource_id for engines that read it
                # (your tokenizer may still derive resource from tags/groups)
                "resource_id": resource_id
            },
            "message": msg,
            "tags": ["integration:kubernetes",
                     "kube_cluster_name:mit-acme",
                     "monitor",
                     "monitor_pack:kubernetes",
                     f"pod_name:{pod_name}",
                     "kube_namespace:production",
                     "source:alert"] + (extra_tags or []),
            "timestamp": ts_iso
        },
        "id": f"id-{idx}",
        "type": "event"
    }
    return evt

def generate_guaranteed_burst():
    """Generate events that guarantee one burst correlation between two resources."""

    start_dt = datetime.fromisoformat("2025-09-02T16:10:00Z".replace("Z", "+00:00"))
    lines = []
    resources = ["web-app", "database"]  # Two resources that will burst together

    print("Generating 40-minute baseline period...")
    # 40-minute baseline (16:10 ... 16:49), 1 event per minute for BOTH resources
    for i in range(40):
        ts_iso = (start_dt + timedelta(minutes=i)).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        # Generate baseline events for BOTH resources at the same time
        for resource in resources:
            lines.append(make_event(ts_iso, f"base-{resource}-{i:02d}", "%%%\\nBaseline event\\n%%%", resource))

    print("Generating first coordinated burst at 16:50...")
    # Burst #1 at 16:50: produce 8 events for BOTH resources in the SAME 5-second bucket
    burst1_dt = start_dt + timedelta(minutes=40)   # 16:50:00Z
    ts_iso = burst1_dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

    # Create 8 events for EACH resource at the SAME timestamp (same bucket)
    for j in range(8):
        for resource in resources:
            lines.append(make_event(ts_iso, f"burst1-{resource}-{j:02d}", "%%%\\nBURST #1\\n%%%", resource))

    print("Generating gap period...")
    # Gap minutes 16:51 and 16:52 - light baseline activity
    gap1_dt = start_dt + timedelta(minutes=41)  # 16:51
    gap2_dt = start_dt + timedelta(minutes=42)  # 16:52
    for g, gdt in enumerate([gap1_dt, gap2_dt], start=1):
        ts_iso = gdt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        # One event per resource during gap
        for resource in resources:
            lines.append(make_event(ts_iso, f"gap-{g:02d}-{resource}", "%%%\\nBaseline event\\n%%%", resource))

    print("Generating second coordinated burst at 16:53...")
    # Burst #2 at 16:53: produce 8 events for BOTH resources in the SAME 5-second bucket
    burst2_dt = start_dt + timedelta(minutes=43)   # 16:53:00Z
    ts_iso = burst2_dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

    # Create 8 events for EACH resource at the SAME timestamp (same bucket)
    for j in range(8):
        for resource in resources:
            lines.append(make_event(ts_iso, f"burst2-{resource}-{j:02d}", "%%%\\nBURST #2\\n%%%", resource))

    return lines

def main():
    """Generate and append guaranteed burst data to alerts.ndjson"""
    print("🚀 Generating guaranteed burst correlation data...")
    
    # Generate the events
    events = generate_guaranteed_burst()
    
    print(f"Generated {len(events)} events with guaranteed burst pattern:")
    print("- 40 minutes baseline (alternating web-app/database, 1 event/minute)")
    print("- Burst #1 at 16:50 (8 events × 2 resources = 16 events)")
    print("- Gap period (2 events × 2 resources = 4 events)")
    print("- Burst #2 at 16:53 (8 events × 2 resources = 16 events)")
    print("- Expected z-score ≈ 4.42 for aligned spikes between web-app and database")
    
    # Append to alerts.ndjson
    with open('alerts.ndjson', 'a', encoding='utf-8') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    print(f"✅ Appended {len(events)} events to alerts.ndjson")
    print("\nThis should guarantee exactly 1 burst correlation!")
    print("Run the engine to verify the burst detection.")

if __name__ == "__main__":
    main()

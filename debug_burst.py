#!/usr/bin/env python3
"""
Debug script to understand why burst correlations aren't being detected.
"""

import json
import numpy as np
from collections import defaultdict
from datetime import datetime

def load_and_debug():
    """Load events and debug the time series creation."""
    
    print("🔍 Debugging burst correlation detection...")
    
    # Load the last few events to see the synthetic data
    with open('alerts.ndjson', 'r') as f:
        lines = f.readlines()
    
    print(f"Total lines in alerts.ndjson: {len(lines)}")
    
    # Look at the last 10 events (our synthetic data)
    print("\n📊 Last 10 events (synthetic data):")
    for i, line in enumerate(lines[-10:], start=len(lines)-9):
        try:
            event = json.loads(line.strip())
            
            # Extract key fields using engine's tolerant normalization approach
            ev_event = event.get('event', {}) if isinstance(event.get('event', {}), dict) else {}
            ev_event_attrs = ev_event.get('attributes', {}) if isinstance(ev_event.get('attributes', {}), dict) else {}
            attrs = (ev_event_attrs.get('attributes', {}) or ev_event_attrs or event.get('attributes', {}) or {})
            monitor = attrs.get('monitor') or ev_event_attrs.get('monitor') or {}
            timestamp = (
                attrs.get('timestamp') or
                ev_event_attrs.get('timestamp') or
                ev_event.get('timestamp') or
                event.get('timestamp') or
                (monitor.get('result', {}) or {}).get('result_ts')
            )
            monitor_id = (monitor or {}).get('id', 'unknown')

            # Extract resource_id like the engine does
            groups = monitor.get('groups', []) or attrs.get('monitor_groups') or event.get('monitor_groups') or []
            kube_cluster = None
            pod_name = None
            kube_namespace = None

            for group in groups:
                if isinstance(group, str):
                    if group.startswith('kube_cluster_name:'):
                        kube_cluster = group.split(':', 1)[1]
                    elif group.startswith('pod_name:'):
                        pod_name = group.split(':', 1)[1]
                    elif group.startswith('kube_namespace:'):
                        kube_namespace = group.split(':', 1)[1]

            if kube_cluster and pod_name:
                resource_id = f"{kube_cluster}/{pod_name}"
            else:
                resource_id = attrs.get('resource_id') or ev_event_attrs.get('resource_id') or 'unknown'

            # Convert timestamp to readable format
            if isinstance(timestamp, (int, float)):
                dt = datetime.fromtimestamp((timestamp if timestamp > 1e12 else timestamp * 1000) / 1000)
                time_str = dt.strftime('%H:%M:%S')
            elif isinstance(timestamp, str):
                try:
                    from dateutil import parser as date_parser
                    dt = date_parser.parse(timestamp)
                    time_str = dt.strftime('%H:%M:%S')
                except Exception:
                    time_str = 'unknown'
            else:
                time_str = 'unknown'

            print(f"  {i:4d}: {time_str} | resource:{resource_id} | monitor:{monitor_id} | cluster:{kube_cluster} | pod:{pod_name} | ns:{kube_namespace}")
            
        except Exception as e:
            print(f"  {i:4d}: Error parsing: {e}")
    
    # Now simulate the time series building logic
    print("\n🔧 Simulating time series building...")
    
    # Parse events and build series like the engine does
    series_buckets = defaultdict(lambda: defaultdict(int))
    bucket_sec = 60  # 60-second buckets
    
    synthetic_events = []
    for line in lines[-76:]:  # Last 76 events are our synthetic data
        try:
            event = json.loads(line.strip())
            ev_event = event.get('event', {}) if isinstance(event.get('event', {}), dict) else {}
            ev_event_attrs = ev_event.get('attributes', {}) if isinstance(ev_event.get('attributes', {}), dict) else {}
            attrs = (ev_event_attrs.get('attributes', {}) or ev_event_attrs or event.get('attributes', {}) or {})

            monitor = attrs.get('monitor') or ev_event_attrs.get('monitor') or {}
            timestamp = (
                attrs.get('timestamp') or
                ev_event_attrs.get('timestamp') or
                ev_event.get('timestamp') or
                event.get('timestamp') or
                (monitor.get('result', {}) or {}).get('result_ts')
            )
            monitor_id = (monitor or {}).get('id', 'unknown')

            # Extract resource_id like the engine does
            groups = monitor.get('groups', []) or attrs.get('monitor_groups') or event.get('monitor_groups') or []
            kube_cluster = None
            pod_name = None
            kube_namespace = None

            for group in groups:
                if isinstance(group, str):
                    if group.startswith('kube_cluster_name:'):
                        kube_cluster = group.split(':', 1)[1]
                    elif group.startswith('pod_name:'):
                        pod_name = group.split(':', 1)[1]
                    elif group.startswith('kube_namespace:'):
                        kube_namespace = group.split(':', 1)[1]

            if kube_cluster and pod_name and timestamp:
                resource_id = f"{kube_cluster}/{pod_name}"
                synthetic_events.append({
                    'timestamp': (timestamp if isinstance(timestamp, (int, float)) else 0),
                    'resource_id': resource_id,
                    'monitor_id': monitor_id
                })
        except Exception:
            continue
    
    print(f"Found {len(synthetic_events)} synthetic events")
    
    # Group into buckets
    for event in synthetic_events:
        ts_ms = event['timestamp']
        bucket_ts = (ts_ms // (bucket_sec * 1000)) * (bucket_sec * 1000)
        
        # Create series keys like the engine
        resource_key = f"resource:{event['resource_id']}"
        monitor_key = f"monitor:{event['monitor_id']}"
        
        series_buckets[resource_key][bucket_ts] += 1
        series_buckets[monitor_key][bucket_ts] += 1
    
    print(f"\n📈 Time series created:")
    for series_key, buckets in series_buckets.items():
        print(f"  {series_key}: {len(buckets)} buckets, total events: {sum(buckets.values())}")
        
        # Show the time distribution
        sorted_buckets = sorted(buckets.items())
        if len(sorted_buckets) > 0:
            start_time = datetime.fromtimestamp(sorted_buckets[0][0] / 1000)
            end_time = datetime.fromtimestamp(sorted_buckets[-1][0] / 1000)
            print(f"    Time range: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')}")
            
            # Show bucket distribution
            counts = list(buckets.values())
            print(f"    Event counts: min={min(counts)}, max={max(counts)}, mean={np.mean(counts):.1f}")
            
            # Show high-activity buckets
            high_buckets = [(ts, count) for ts, count in sorted_buckets if count > 2]
            if high_buckets:
                print(f"    High-activity buckets ({len(high_buckets)}):")
                for ts, count in high_buckets:
                    time_str = datetime.fromtimestamp(ts / 1000).strftime('%H:%M:%S')
                    print(f"      {time_str}: {count} events")
    
    # Check if we have the expected pattern
    print(f"\n🎯 Checking for expected burst pattern...")
    
    # Look for the two main resource series
    web_app_series = None
    database_series = None
    
    for series_key, buckets in series_buckets.items():
        if 'web-app' in series_key:
            web_app_series = buckets
        elif 'database' in series_key:
            database_series = buckets
    
    if web_app_series and database_series:
        print("✅ Found both web-app and database series")
        
        # Check for aligned high-activity buckets
        web_app_high = {ts: count for ts, count in web_app_series.items() if count > 2}
        database_high = {ts: count for ts, count in database_series.items() if count > 2}
        
        print(f"Web-app high-activity buckets: {len(web_app_high)}")
        print(f"Database high-activity buckets: {len(database_high)}")
        
        # Check for alignment
        aligned_buckets = set(web_app_high.keys()) & set(database_high.keys())
        print(f"Aligned high-activity buckets: {len(aligned_buckets)}")
        
        if aligned_buckets:
            print("🎉 Found aligned bursts! These should trigger burst correlation.")
            for ts in sorted(aligned_buckets):
                time_str = datetime.fromtimestamp(ts / 1000).strftime('%H:%M:%S')
                print(f"  {time_str}: web-app={web_app_high[ts]}, database={database_high[ts]}")
        else:
            print("❌ No aligned bursts found")
    else:
        print("❌ Missing expected resource series")
        print(f"Available series: {list(series_buckets.keys())}")

if __name__ == "__main__":
    load_and_debug()

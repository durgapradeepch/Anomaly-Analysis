#!/usr/bin/env python3
"""
Debug the realistic burst data to understand why no correlations were detected.
"""

import json
import numpy as np
from collections import defaultdict
from datetime import datetime

def debug_realistic_data():
    """Debug the realistic burst data."""
    
    print("🔍 Debugging realistic burst correlation detection...")
    
    # Load events
    with open('alerts.ndjson', 'r') as f:
        lines = f.readlines()
    
    print(f"Total lines in alerts.ndjson: {len(lines)}")
    
    # Parse realistic events (last 257 events)
    realistic_events = []
    for line in lines[-300:]:  # Get more than 257 to be safe
        try:
            event = json.loads(line.strip())
            
            # Check if this is one of our realistic events
            ev_event = event.get('event', {}) if isinstance(event.get('event', {}), dict) else {}
            tags = ev_event.get('tags', []) if isinstance(ev_event.get('tags', []), list) else []
            if any(isinstance(tag, str) and 'service:' in tag for tag in tags):
                ev_event_attrs = ev_event.get('attributes', {}) if isinstance(ev_event.get('attributes', {}), dict) else {}
                attrs = (ev_event_attrs.get('attributes', {}) or ev_event_attrs or {})
                monitor = attrs.get('monitor') or ev_event_attrs.get('monitor') or {}
                timestamp = (
                    attrs.get('timestamp') or
                    ev_event_attrs.get('timestamp') or
                    ev_event.get('timestamp') or
                    (monitor.get('result', {}) or {}).get('result_ts')
                )

                # Extract service from tags
                service = None
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith('service:'):
                        service = tag.split(':', 1)[1]
                        break

                if service and timestamp:
                    # Extract resource_id like the engine does
                    groups = monitor.get('groups', []) or []
                    cluster = None
                    pod_name = None
                    namespace = None

                    for group in groups:
                        if isinstance(group, str):
                            if group.startswith('kube_cluster_name:') or group.startswith('cluster:'):
                                cluster = group.split(':', 1)[1]
                            elif group.startswith('pod_name:') or group.startswith('pod:'):
                                pod_name = group.split(':', 1)[1]
                            elif group.startswith('kube_namespace:') or group.startswith('namespace:'):
                                namespace = group.split(':', 1)[1]

                    if cluster and pod_name:
                        resource_id = f"{cluster}/{pod_name}"
                        realistic_events.append({
                            'timestamp': (timestamp if isinstance(timestamp, (int, float)) else 0),
                            'resource_id': resource_id,
                            'service': service,
                            'monitor_id': (monitor or {}).get('id', 'unknown')
                        })
        except:
            continue
    
    print(f"Found {len(realistic_events)} realistic events")
    
    # Group into time series by service
    bucket_sec = 60
    service_series = defaultdict(lambda: defaultdict(int))
    
    for event in realistic_events:
        ts_ms = event['timestamp']
        bucket_ts = (ts_ms // (bucket_sec * 1000)) * (bucket_sec * 1000)
        service = event['service']
        
        service_series[service][bucket_ts] += 1
    
    print(f"\n📈 Time series by service:")
    for service, buckets in service_series.items():
        if len(buckets) >= 3:  # Only show non-sparse series
            counts = list(buckets.values())
            sorted_buckets = sorted(buckets.items())
            
            start_time = datetime.fromtimestamp(sorted_buckets[0][0] / 1000)
            end_time = datetime.fromtimestamp(sorted_buckets[-1][0] / 1000)
            
            print(f"  {service}: {len(buckets)} buckets, total events: {sum(counts)}")
            print(f"    Time range: {start_time.strftime('%H:%M')} - {end_time.strftime('%H:%M')}")
            print(f"    Event counts: min={min(counts)}, max={max(counts)}, mean={np.mean(counts):.1f}")
            
            # Show high-activity buckets
            high_buckets = [(ts, count) for ts, count in sorted_buckets if count > np.mean(counts) + 1]
            if high_buckets:
                print(f"    High-activity buckets ({len(high_buckets)}):")
                for ts, count in high_buckets[:5]:  # Show first 5
                    time_str = datetime.fromtimestamp(ts / 1000).strftime('%H:%M:%S')
                    print(f"      {time_str}: {count} events")
            print()
    
    # Check for potential correlations manually
    print("🎯 Checking for potential correlations...")
    
    services = list(service_series.keys())
    for i in range(len(services)):
        for j in range(i + 1, len(services)):
            service1 = services[i]
            service2 = services[j]
            
            series1 = service_series[service1]
            series2 = service_series[service2]
            
            if len(series1) < 5 or len(series2) < 5:
                continue
            
            # Find common timestamps
            common_ts = set(series1.keys()) & set(series2.keys())
            if len(common_ts) < 5:
                continue
            
            # Calculate correlation
            values1 = [series1[ts] for ts in sorted(common_ts)]
            values2 = [series2[ts] for ts in sorted(common_ts)]
            
            if np.std(values1) > 0 and np.std(values2) > 0:
                correlation = np.corrcoef(values1, values2)[0, 1]
                
                # Check for aligned high-activity periods
                mean1, mean2 = np.mean(values1), np.mean(values2)
                aligned_bursts = sum(1 for v1, v2 in zip(values1, values2) 
                                   if v1 > mean1 + 1 and v2 > mean2 + 1)
                
                print(f"{service1} ↔ {service2}:")
                print(f"  Correlation: {correlation:.3f}")
                print(f"  Common buckets: {len(common_ts)}")
                print(f"  Aligned bursts: {aligned_bursts}")
                print(f"  Mean activity: {mean1:.1f}, {mean2:.1f}")
                print()

if __name__ == "__main__":
    debug_realistic_data()

#!/usr/bin/env python3
"""
Generate realistic NDJSON with varied correlation patterns for burst detection.
This creates more production-like data with:
- Different baseline patterns per service
- Timing jitter and variations
- Partial correlations (not all bursts align)
- Multiple services with different behaviors
- Realistic noise and missing events
"""

import json
import random
import numpy as np
from datetime import datetime, timezone, timedelta

def iso_to_ms(iso):
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)

def make_event(ts_iso: str, idx: str, msg: str, service_name: str, severity: str = "ERROR", extra_tags=None):
    """Create a realistic event for a specific service."""
    ts_ms = iso_to_ms(ts_iso)
    
    # Create consistent service-specific identifiers (same pod per service for correlation)
    pod_name = f"{service_name}-main-pod"  # Consistent pod name per service
    resource_id = f"prod-cluster/{pod_name}"
    monitor_id = {
        "web-frontend": 15001,
        "api-gateway": 15002, 
        "database": 15003,
        "cache-redis": 15004,
        "message-queue": 15005
    }.get(service_name, 15000)
    
    evt = {
        "count": 1,
        "currentStatus": "Alert",
        "event": {
            "attributes": {
                "attributes": {
                    "_dd": {"has_notification": False, "internal": "1", "version": "1"},
                    "evt": {
                        "id": f"evt-{idx}",
                        "name": f"[Production] {service_name.title()} Monitor",
                        "type": "query_alert_monitor"
                    },
                    "monitor": {
                        "id": monitor_id,
                        "name": f"[Production] {service_name.title()} Monitor",
                        "templated_name": f"[Production] {service_name.title()} Monitor on cluster:prod-cluster,pod:{pod_name},namespace:production",
                        "type": "query alert",
                        "groups": ["kube_cluster_name:prod-cluster", f"pod_name:{pod_name}", "kube_namespace:production"],
                        "result": {"group_key": "kube_cluster_name,pod_name,kube_namespace"}
                    },
                    "timestamp": ts_ms
                },
                "resource_id": resource_id
            },
            "message": msg,
            "tags": ["integration:kubernetes",
                     "kube_cluster_name:prod-cluster",
                     "monitor",
                     f"service:{service_name}",
                     f"pod_name:{pod_name}",
                     "kube_namespace:production",
                     f"severity:{severity.lower()}",
                     "source:alert"] + (extra_tags or []),
            "timestamp": ts_iso
        },
        "id": f"id-{idx}",
        "type": "event"
    }
    return evt

def add_jitter(base_time, max_jitter_minutes=5):
    """Add realistic timing jitter to events."""
    max_jitter_seconds = int(max_jitter_minutes * 60)
    jitter_seconds = random.randint(-max_jitter_seconds, max_jitter_seconds)
    return base_time + timedelta(seconds=jitter_seconds)

def generate_realistic_bursts():
    """Generate realistic burst correlation data with varied patterns."""
    
    start_dt = datetime.fromisoformat("2025-09-02T14:00:00Z".replace("Z", "+00:00"))
    lines = []
    
    # Define services with different characteristics (stronger correlations)
    services = {
        "web-frontend": {"baseline_rate": 0.7, "burst_probability": 1.0},   # Always bursts
        "api-gateway": {"baseline_rate": 0.6, "burst_probability": 0.9},    # Strong correlation
        "database": {"baseline_rate": 0.8, "burst_probability": 0.8},       # Good correlation
        "cache-redis": {"baseline_rate": 0.4, "burst_probability": 0.6},    # Moderate correlation
        "message-queue": {"baseline_rate": 0.3, "burst_probability": 0.2}   # Weak/independent
    }
    
    print("🏗️  Generating realistic baseline period (60 minutes)...")
    # 60-minute baseline with varied patterns
    for i in range(60):
        base_time = start_dt + timedelta(minutes=i)
        
        for service_name, config in services.items():
            # Each service has different baseline activity rates
            if random.random() < config["baseline_rate"]:
                # Add timing jitter to make it realistic
                event_time = add_jitter(base_time, max_jitter_minutes=2)
                ts_iso = event_time.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                
                severity = random.choices(["ERROR", "WARN", "CRITICAL"], weights=[0.7, 0.2, 0.1])[0]
                lines.append(make_event(ts_iso, f"baseline-{service_name}-{i:02d}", 
                                      "Normal operational event", service_name, severity))
    
    print("💥 Generating first incident burst at 15:00...")
    # Major incident at 15:00 - affects most services but with different timing
    incident1_base = start_dt + timedelta(hours=1)  # 15:00
    
    for service_name, config in services.items():
        if random.random() < config["burst_probability"]:
            # Different services fail at slightly different times (cascade effect)
            service_delay = {
                "web-frontend": 0,      # Fails first (user-facing)
                "api-gateway": 30,      # Fails 30s later
                "database": 45,         # Database overload 45s later
                "cache-redis": 60,      # Cache fails 1min later
                "message-queue": 90     # Queue backs up 1.5min later
            }.get(service_name, 0)
            
            burst_time = incident1_base + timedelta(seconds=service_delay)
            
            # Generate multiple events during burst (4-8 events for stronger signal)
            burst_count = random.randint(4, 8)
            for j in range(burst_count):
                # Reduce jitter for stronger correlation
                event_time = add_jitter(burst_time, max_jitter_minutes=0.5)
                ts_iso = event_time.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

                lines.append(make_event(ts_iso, f"incident1-{service_name}-{j:02d}",
                                      "🚨 INCIDENT: High error rate detected", service_name, "CRITICAL"))
    
    print("📈 Generating normal activity period...")
    # Normal activity for 30 minutes
    for i in range(30):
        base_time = start_dt + timedelta(hours=1, minutes=15 + i)  # 15:15 - 15:45
        
        for service_name, config in services.items():
            # Reduced activity after incident (recovery period)
            recovery_rate = config["baseline_rate"] * 0.6
            if random.random() < recovery_rate:
                event_time = add_jitter(base_time, max_jitter_minutes=3)
                ts_iso = event_time.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                
                lines.append(make_event(ts_iso, f"recovery-{service_name}-{i:02d}", 
                                      "Recovery period activity", service_name, "WARN"))
    
    print("⚡ Generating second partial burst at 15:50...")
    # Partial incident at 15:50 - only affects some services
    incident2_base = start_dt + timedelta(hours=1, minutes=50)  # 15:50
    
    # Only web-frontend, api-gateway, and database are affected this time
    affected_services = ["web-frontend", "api-gateway", "database"]
    
    for service_name in affected_services:
        # Smaller burst with minimal jitter (highly synchronized)
        burst_count = random.randint(4, 6)
        for j in range(burst_count):
            event_time = add_jitter(incident2_base, max_jitter_minutes=0.2)
            ts_iso = event_time.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

            lines.append(make_event(ts_iso, f"incident2-{service_name}-{j:02d}",
                                  "⚠️  PARTIAL INCIDENT: API timeout spike", service_name, "ERROR"))
    
    print("🔧 Adding realistic noise events...")
    # Add some random noise events throughout
    for _ in range(20):
        random_time = start_dt + timedelta(minutes=random.randint(0, 120))
        random_service = random.choice(list(services.keys()))
        event_time = add_jitter(random_time, max_jitter_minutes=10)
        ts_iso = event_time.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        
        lines.append(make_event(ts_iso, f"noise-{random.randint(1000, 9999)}", 
                              "Random operational event", random_service, 
                              random.choice(["ERROR", "WARN"])))
    
    return lines

def main():
    """Generate and append realistic burst data to alerts.ndjson"""
    print("🚀 Generating realistic burst correlation data...")
    
    # Set random seed for reproducible results
    random.seed(42)
    np.random.seed(42)
    
    # Generate the events
    events = generate_realistic_bursts()
    
    print(f"\n📊 Generated {len(events)} events with realistic patterns:")
    print("- 60 minutes varied baseline activity")
    print("- Major incident at 15:00 (cascade failure)")
    print("- 30 minutes recovery period") 
    print("- Partial incident at 15:50 (3 services)")
    print("- Random noise events throughout")
    print("- Timing jitter and realistic variations")
    
    # Append to alerts.ndjson
    with open('alerts.ndjson', 'a', encoding='utf-8') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    print(f"✅ Appended {len(events)} realistic events to alerts.ndjson")
    print("\nExpected correlations:")
    print("- Strong: web-frontend ↔ api-gateway")
    print("- Moderate: api-gateway ↔ database") 
    print("- Weak: database ↔ cache-redis")
    print("- Independent: message-queue")

if __name__ == "__main__":
    main()

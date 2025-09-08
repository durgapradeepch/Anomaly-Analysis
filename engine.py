#!/usr/bin/env python3
"""
Advanced Correlation & Anomaly Engine for alerts.ndjson

This module implements a comprehensive anomaly detection system that:
- Ingests Datadog/VictoriaLogs alerts from alerts.ndjson
- Normalizes events and builds time series
- Detects burst correlations, lead-lag relationships, PMI co-occurrence, and change attribution
- Performs statistical validation with adaptive thresholds
- Detects data drift and provides context-aware severity classification
- Outputs insights to public/vl_insights.jsonl for dashboard consumption

Usage:
    python engine.py --once    # Run single analysis pass
    python engine.py --watch   # Continuous monitoring (optional)

Dependencies: numpy, scipy, python-dateutil
"""

import json
import os
import sys
import argparse
import gc
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import re

import numpy as np
from scipy import stats
from scipy.stats import pearsonr
from dateutil import parser as date_parser

# Luminol is disabled due to numpy compatibility issues
# Using fallback correlation methods for change attribution
LUMINOL_AVAILABLE = False

# Configuration constants (can be overridden by environment variables)
BUCKET_SEC = int(os.getenv('BUCKET_SEC', '60'))
MAX_LAG_BUCKETS = int(os.getenv('MAX_LAG_BUCKETS', '10'))
PMI_MIN_SUPPORT = int(os.getenv('PMI_MIN_SUPPORT', '2'))
SIGNIFICANCE_P = float(os.getenv('SIGNIFICANCE_P', '0.01'))
CONF_LEVEL = float(os.getenv('CONF_LEVEL', '0.99'))
Z_THRESHOLD = float(os.getenv('Z_THRESHOLD', '3.0'))
CORR_THRESHOLD = float(os.getenv('CORR_THRESHOLD', '0.3'))
PMI_THRESHOLD = float(os.getenv('PMI_THRESHOLD', '2.0'))
DRIFT_THRESHOLD = float(os.getenv('DRIFT_THRESHOLD', '0.05'))
DRIFT_WINDOW_SIZE = int(os.getenv('DRIFT_WINDOW_SIZE', '500'))
JOIN_MODE = os.getenv('JOIN_MODE', 'resource')  # 'resource' or 'service'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def normalize_event(ev: dict) -> Optional[dict]:
    """
    Normalize a single event from alerts.ndjson into standardized format.
    
    Extracts and maps fields according to the specification:
    - resource_id, monitor_key, tags_map, tokens, severity, ts_ms
    - Handles missing fields gracefully
    
    Args:
        ev: Raw event dictionary from alerts.ndjson
        
    Returns:
        Normalized event dict or None if critical fields missing
    """
    import re
    try:
        # Extract nested attributes safely (be tolerant to schema variations)
        ev_event = ev.get('event', {}) if isinstance(ev.get('event', {}), dict) else {}
        ev_event_attrs = ev_event.get('attributes', {}) if isinstance(ev_event.get('attributes', {}), dict) else {}

        attrs_candidates = [
            ev_event_attrs.get('attributes', {}) or {},
            ev_event_attrs or {},
            ev.get('attributes', {}) or {},
            ev or {}
        ]
        # Merge candidates giving precedence to earlier ones
        attrs: dict = {}
        for d in reversed(attrs_candidates):
            if isinstance(d, dict):
                attrs.update(d)

        # Monitor object can live in multiple places
        monitor_candidates = [
            attrs.get('monitor'),
            ev_event_attrs.get('monitor'),
            ev.get('monitor')
        ]
        monitor = next((m for m in monitor_candidates if isinstance(m, dict)), {})
        evt_info = attrs.get('evt', {}) if isinstance(attrs.get('evt', {}), dict) else {}

        # Extract timestamps (try multiple sources, convert to milliseconds)
        ts_candidates = [
            attrs.get('timestamp'),
            ev_event_attrs.get('timestamp'),
            ev_event.get('timestamp'),
            ev.get('timestamp'),
            monitor.get('result', {}).get('result_ts') if isinstance(monitor.get('result', {}), dict) else None,
            ev.get('firstOccurrence'),
            ev.get('lastOccurrence'),
            ev.get('_time'),
            ev.get('time')
        ]

        ts_ms = None
        for ts_candidate in ts_candidates:
            if ts_candidate is None or ts_candidate == '':
                continue
            try:
                if isinstance(ts_candidate, str):
                    # Parse ISO format or other string formats
                    dt = date_parser.parse(ts_candidate)
                    ts_ms = int(dt.timestamp() * 1000)
                elif isinstance(ts_candidate, (int, float)):
                    # Assume already in milliseconds if > 1e12, else seconds
                    ts_ms = int(ts_candidate * 1000 if ts_candidate < 1e12 else ts_candidate)
                if ts_ms:
                    break
            except (ValueError, TypeError, OverflowError):
                continue

        if not ts_ms:
            logger.warning(f"No valid timestamp found for event: {ev.get('id', 'unknown')}")
            return None

        # Extract resource identifiers
        groups = []
        groups_candidates = [
            monitor.get('groups') if isinstance(monitor, dict) else None,
            attrs.get('monitor_groups'),
            ev.get('monitor_groups')
        ]
        for gc in groups_candidates:
            if isinstance(gc, list):
                groups = gc
                break
        group_key = ''
        if isinstance(monitor.get('result', {}), dict):
            group_key = monitor.get('result', {}).get('group_key', '')

        # Parse kube_cluster_name, pod_name, and kube_namespace from groups
        kube_cluster = None
        pod_name = None
        kube_namespace = None

        for group in groups or []:
            if isinstance(group, str):
                if group.startswith('kube_cluster_name:'):
                    kube_cluster = group.split(':', 1)[1]
                elif group.startswith('pod_name:'):
                    pod_name = group.split(':', 1)[1]
                elif group.startswith('kube_namespace:'):
                    kube_namespace = group.split(':', 1)[1]

        # Fallback: try tags if not found in groups
        if not kube_cluster or not pod_name or not kube_namespace:
            all_tags = []
            for source in [attrs, monitor, ev, ev_event, ev_event_attrs]:
                tags = source.get('tags') if isinstance(source, dict) else []
                if isinstance(tags, list):
                    all_tags.extend(tags)
            # Also treat group strings as tags
            if isinstance(groups, list):
                all_tags.extend(groups)

            for tag in all_tags:
                if isinstance(tag, str):
                    if tag.startswith('kube_cluster_name:') and not kube_cluster:
                        kube_cluster = tag.split(':', 1)[1]
                    elif tag.startswith('pod_name:') and not pod_name:
                        pod_name = tag.split(':', 1)[1]
                    elif tag.startswith('kube_namespace:') and not kube_namespace:
                        kube_namespace = tag.split(':', 1)[1]

        # Create resource_id; prefer explicit field if present
        explicit_resource = (
            ev_event_attrs.get('resource_id') or
            attrs.get('resource_id') or
            ev.get('resource_id')
        )
        resource_id = None
        if isinstance(explicit_resource, str) and explicit_resource:
            resource_id = explicit_resource
        elif kube_cluster and pod_name and pod_name != 'pod' and kube_cluster != 'cluster':
            resource_id = f"{kube_cluster}/{pod_name}"
        else:
            # Skip events with insufficient identifiers
            return None

        # Create monitor_key - use actual group values when available for better uniqueness
        monitor_id = str((monitor.get('id') if isinstance(monitor, dict) else '') or attrs.get('monitor_id', ''))
        group_vals = []
        for g in groups or []:
            # g looks like "kube_namespace:default"
            if isinstance(g, str) and ':' in g:
                group_vals.append(g.split(':', 1)[1])
        monitor_key = f"{monitor_id}|{','.join(group_vals) or group_key}"

        # Build tags_map from all tag sources
        tags_map = {}
        all_tags = []
        for source in [attrs, monitor, ev, ev_event, ev_event_attrs]:
            tags = source.get('tags') if isinstance(source, dict) else []
            if isinstance(tags, list):
                all_tags.extend(tags)
        if isinstance(groups, list):
            all_tags.extend(groups)

        for tag in all_tags:
            if isinstance(tag, str) and ':' in tag:
                key, value = tag.split(':', 1)
                tags_map[key] = value

        # Extract severity/status
        status_candidates = [
            attrs.get('status'),
            ev.get('currentStatus'),
            ev.get('status'),
            ev_event.get('status'),
            (attrs.get('monitor', {}) or {}).get('group_status'),
            (monitor or {}).get('group_status')
        ]

        severity = 'INFO'  # default
        for status in status_candidates:
            if status is None:
                continue
            status_str = str(status).lower()
            if any(s in status_str for s in ['critical', 'alert']):
                severity = 'CRITICAL'
                break
            if 'error' in status_str:
                severity = 'ERROR'
                break
            if 'warn' in status_str:
                severity = 'WARN'
                break

        # Extract transition information
        transition = attrs.get('transition', {}) if isinstance(attrs.get('transition', {}), dict) else {}
        transition_info = {
            'source': transition.get('source_state'),
            'dest': transition.get('destination_state'),
            'type': transition.get('transition_type')
        }

        # Extract thresholds
        thresholds = {}
        options = monitor.get('options', {}) if isinstance(monitor.get('options', {}), dict) else {}
        if isinstance(options, dict):
            thresholds = options.get('thresholds', {}) if isinstance(options.get('thresholds', {}), dict) else {}

        # Extract priority
        priority = monitor.get('priority', 0) if isinstance(monitor, dict) else 0

        # Build tokens for PMI analysis
        tokens = set()

        # Add resource_id as primary token for granular correlation
        tokens.add(f"resource_id:{resource_id}")

        # Add individual resource components for flexible matching
        if kube_cluster:
            tokens.add(f"kube_cluster_name:{kube_cluster}")
        if pod_name:
            tokens.add(f"pod_name:{pod_name}")

        # Add monitor information - prefer templated_name over generic name
        monitor_name = monitor.get('name', '') if isinstance(monitor, dict) else ''
        templated_name = monitor.get('templated_name', '') if isinstance(monitor, dict) else ''
        monitor_type = monitor.get('type', '') if isinstance(monitor, dict) else ''

        # Use templated name if available (contains actual resolved values)
        if templated_name and templated_name != monitor_name:
            tokens.add(f"monitor_name:{templated_name}")
            # Note: Removed monitor_template to avoid confusion in correlations
            # The resolved monitor_name already contains the actual pod names
        elif monitor_name:
            tokens.add(f"monitor_name:{monitor_name}")

        if monitor_type:
            tokens.add(f"monitor_type:{monitor_type}")

        # Add event information - prefer templated_name for resolved values
        evt_name = evt_info.get('name', '')
        evt_type = evt_info.get('type', '')

        # Use templated name if available for event name as well
        if templated_name and evt_name:
            # Extract the resolved event name from templated_name if it contains more specific info
            if '{{' not in templated_name and templated_name != evt_name:
                tokens.add(f"evt_name:{templated_name}")
            else:
                tokens.add(f"evt_name:{evt_name}")
        elif evt_name:
            tokens.add(f"evt_name:{evt_name}")

        if evt_type:
            tokens.add(f"evt_type:{evt_type}")

        # Extract actual resolved values from message and tags
        message = (
            ev_event_attrs.get('message') or
            ev_event.get('message') or
            ev.get('message') or
            ''
        )

        # Extract actual pod name from message if templated name contains {{pod_name.name}}
        if evt_name and '{{pod_name.name}}' in evt_name and message:
            # Look for actual pod name in message - try multiple patterns
            pod_match = (re.search(r'Pod (\S+) ', message) or
                        re.search(r'pod (\S+) is', message) or
                        re.search(r'pod_name:(\S+)', message))
            if pod_match:
                actual_pod_name = pod_match.group(1)
                tokens.add(f"actual_pod_name:{actual_pod_name}")

                # Create resolved event name
                resolved_evt_name = evt_name.replace('{{pod_name.name}}', actual_pod_name)
                if '{{kube_namespace.name}}' in resolved_evt_name and kube_namespace:
                    resolved_evt_name = resolved_evt_name.replace('{{kube_namespace.name}}', kube_namespace)
                tokens.add(f"resolved_evt_name:{resolved_evt_name}")

        # Extract actual namespace from message if templated
        actual_namespace_found = False
        if evt_name and '{{kube_namespace.name}}' in evt_name and message:
            namespace_match = (re.search(r'namespace (\S+)', message) or
                              re.search(r'on (\S+)\s*$', message) or
                              re.search(r'on (\S+)\s+', message))
            if namespace_match:
                actual_namespace = namespace_match.group(1)
                tokens.add(f"actual_namespace:{actual_namespace}")
                actual_namespace_found = True

        # Add service and category with enrichment (check multiple locations)
        service = attrs.get('service', '') or ev_event.get('service', '')
        sourcecategory = attrs.get('sourcecategory', '') or ev_event.get('sourcecategory', '')

        # Enrich service if undefined by deriving from integration or monitor_pack
        if not service or service == 'undefined':
            # Check for integration or monitor_pack in tags
            for tag in all_tags:
                if isinstance(tag, str):
                    if tag.startswith('integration:'):
                        service = tag.split(':', 1)[1]
                        break
                    if tag.startswith('monitor_pack:'):
                        service = tag.split(':', 1)[1]
                        break

        if service and service != 'undefined':
            tokens.add(f"service:{service}")
        if sourcecategory:
            tokens.add(f"sourcecategory:{sourcecategory}")

        # Add all tags as tokens, but skip kube_namespace if actual_namespace was found
        for key, value in tags_map.items():
            if key == 'kube_namespace' and actual_namespace_found:
                continue  # Skip redundant kube_namespace when we have actual_namespace
            tokens.add(f"{key}:{value}")

        # Add query signature if available
        query = monitor.get('query', '') if isinstance(monitor, dict) else ''
        if query:
            # Extract metric name from query - more permissive pattern
            metric_match = re.search(r'(\w+[\w\._-]+)', query)
            if metric_match:
                tokens.add(f"metric:{metric_match.group(1)}")

        # Add message keyword tokens for PMI analysis
        message_for_errors = ev_event.get('message') or ev.get('event', {}).get('message', '')
        if message_for_errors:
            # Extract common Kubernetes error patterns
            k8s_error_patterns = [
                ('ImagePullBackOff', r'ImagePullBackOff'),
                ('CrashLoopBackOff', r'CrashLoopBackOff'),
                ('Evicted', r'Evicted'),
                ('OOMKilled', r'OOMKilled'),
                ('timeout', r'timeout|timed out'),
                ('failed', r'failed|failure'),
                ('error', r'error'),
                ('critical', r'critical'),
                ('warning', r'warning')
            ]

            for keyword, pattern in k8s_error_patterns:
                if re.search(pattern, message_for_errors, re.IGNORECASE):
                    tokens.add(f"error_type:{keyword.lower()}")
                    break  # Only add one error type to avoid noise

        # Create normalized event
        normalized = {
            'ts_ms': ts_ms,
            'resource_id': resource_id,
            'monitor_key': monitor_key,
            'severity': severity,
            'priority': priority,
            'transition': transition_info,
            'thresholds': thresholds,
            'monitor': {
                'id': monitor_id,
                'name': monitor_name,
                'aggregation_key': attrs.get('aggregation_key', ''),
                'event_object': attrs.get('event_object', ''),
                'group_key': group_key
            },
            'tags_map': tags_map,
            'tokens': list(tokens),
            'raw': ev  # Keep original for debugging
        }
        
        return normalized

    except Exception as e:
        logger.error(f"Error normalizing event {ev.get('id', 'unknown')}: {e}")
        return None


def load_logs(file_path: str = 'alerts.ndjson') -> List[dict]:
    """
    Load and normalize events from alerts.ndjson file.

    Args:
        file_path: Path to the NDJSON file

    Returns:
        List of normalized events
    """
    normalized_events = []
    validation_errors = 0

    logger.info(f"Loading logs from {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    raw_event = json.loads(line)
                    normalized = normalize_event(raw_event)

                    if normalized:
                        normalized_events.append(normalized)
                    else:
                        validation_errors += 1

                except json.JSONDecodeError as e:
                    logger.warning(f"JSON decode error on line {line_num}: {e}")
                    validation_errors += 1
                except Exception as e:
                    logger.warning(f"Error processing line {line_num}: {e}")
                    validation_errors += 1

    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return []

    logger.info(f"Loaded {len(normalized_events)} valid events, {validation_errors} validation errors")
    return normalized_events


def build_series_map(normalized_events: List[dict], bucket_sec: int = BUCKET_SEC) -> Dict[str, Dict[int, float]]:
    """
    Build time series from normalized events with bucketing and smoothing.

    Creates series keyed by service|level combinations and resource_id|monitor_key.
    Applies 3-point moving average smoothing and filters sparse series.

    Args:
        normalized_events: List of normalized events
        bucket_sec: Bucket size in seconds

    Returns:
        Dictionary mapping series keys to {bucket_timestamp: count} dictionaries
    """
    if not normalized_events:
        return {}

    logger.info(f"Building time series with {bucket_sec}s buckets")

    # Group events into buckets
    series_buckets = defaultdict(lambda: defaultdict(int))

    for event in normalized_events:
        ts_ms = event['ts_ms']
        bucket_ts = (ts_ms // (bucket_sec * 1000)) * (bucket_sec * 1000)

        # Create series keys based on JOIN_MODE configuration
        severity = event['severity']
        resource_id = event['resource_id']
        monitor_key = event['monitor_key']

        if JOIN_MODE == 'resource':
            # PRIMARY: Resource-based series for granular correlation
            primary_key = f"resource:{resource_id}"
            series_buckets[primary_key][bucket_ts] += 1

            # SECONDARY: Monitor-based series for detailed analysis
            monitor_series_key = f"monitor:{monitor_key}"
            series_buckets[monitor_series_key][bucket_ts] += 1

            # ROLLUP: Service-level series for dashboard aggregation
            service = 'kubernetes'  # Default service from the data
            if event['tags_map'].get('service'):
                service = event['tags_map']['service']
            elif 'service:' in ' '.join(event['tokens']):
                for token in event['tokens']:
                    if token.startswith('service:'):
                        service = token.split(':', 1)[1]
                        break

            service_level_key = f"service_rollup:{service}|{severity}"
            series_buckets[service_level_key][bucket_ts] += 1

        else:  # JOIN_MODE == 'service'
            # PRIMARY: Service|level series for high-level correlation
            service = 'kubernetes'  # Default service from the data
            if event['tags_map'].get('service'):
                service = event['tags_map']['service']
            elif 'service:' in ' '.join(event['tokens']):
                for token in event['tokens']:
                    if token.startswith('service:'):
                        service = token.split(':', 1)[1]
                        break

            primary_key = f"{service}|{severity}"
            series_buckets[primary_key][bucket_ts] += 1

            # SECONDARY: Resource and monitor series for detailed analysis
            resource_key = f"resource:{resource_id}"
            series_buckets[resource_key][bucket_ts] += 1

            monitor_series_key = f"monitor:{monitor_key}"
            series_buckets[monitor_series_key][bucket_ts] += 1

    # Convert to regular dicts and apply smoothing
    series_map = {}

    # Adjust threshold based on JOIN_MODE
    if JOIN_MODE == 'resource':
        min_points_threshold = 3  # Lower threshold for granular resource analysis
    else:
        min_points_threshold = 8  # Higher threshold for service-level analysis

    for series_key, buckets in series_buckets.items():
        if len(buckets) < min_points_threshold:
            continue  # Skip sparse series

        # Sort by timestamp and apply 3-point moving average
        sorted_buckets = sorted(buckets.items())
        smoothed_buckets = {}

        for i, (ts, count) in enumerate(sorted_buckets):
            if i == 0 or i == len(sorted_buckets) - 1:
                # Keep first and last points as-is
                smoothed_buckets[ts] = count
            else:
                # 3-point moving average
                prev_count = sorted_buckets[i-1][1]
                next_count = sorted_buckets[i+1][1]
                smoothed_count = (prev_count + count + next_count) / 3.0
                smoothed_buckets[ts] = smoothed_count

        series_map[series_key] = smoothed_buckets

    logger.info(f"Built {len(series_map)} time series (filtered {len(series_buckets) - len(series_map)} sparse series)")
    return series_map


def calculate_rolling_z_scores(series_data: Dict[int, float], window_size: int = 10) -> Dict[int, float]:
    """
    Calculate z-scores using rolling baseline for proper burst detection.

    For each timestamp, uses a rolling window of past W buckets to compute
    baseline mean and stddev, then calculates z-score for current value.

    Args:
        series_data: Dictionary mapping timestamps to values
        window_size: Number of past buckets to use for rolling baseline (default: 10 = 10 minutes at 60s buckets)

    Returns:
        Dictionary mapping timestamps to z-scores
    """
    if len(series_data) < window_size:
        return {}

    # Sort timestamps to ensure proper chronological order
    sorted_timestamps = sorted(series_data.keys())
    z_scores = {}

    for i, ts in enumerate(sorted_timestamps):
        # Need at least window_size previous points for rolling baseline
        if i < window_size:
            z_scores[ts] = 0.0  # Not enough history
            continue

        # Get rolling window of past values (excluding current)
        window_values = [series_data[sorted_timestamps[j]] for j in range(i - window_size, i)]

        if len(window_values) < window_size:
            z_scores[ts] = 0.0
            continue

        # Calculate rolling baseline and variance
        baseline_mean = np.mean(window_values)
        baseline_std = np.std(window_values, ddof=1)

        if baseline_std == 0:
            z_scores[ts] = 0.0
        else:
            current_value = series_data[ts]
            z_scores[ts] = (current_value - baseline_mean) / baseline_std

    return z_scores


def detect_bursts_in_series(series_data: Dict[int, float], z_threshold: float = 3.0, window_size: int = 10) -> List[int]:
    """
    Detect burst timestamps in a single time series using rolling baseline.

    Args:
        series_data: Dictionary mapping timestamps to values
        z_threshold: Z-score threshold for burst detection
        window_size: Rolling window size for baseline calculation

    Returns:
        List of timestamps where bursts occurred
    """
    z_scores = calculate_rolling_z_scores(series_data, window_size)
    burst_timestamps = []

    for ts, z_score in z_scores.items():
        if abs(z_score) >= z_threshold:
            burst_timestamps.append(ts)

    return burst_timestamps


def count_aligned_bursts(bursts1: List[int], bursts2: List[int], alignment_window_ms: int = 120000) -> int:
    """
    Count bursts that occur within alignment window of each other.

    Args:
        bursts1: List of burst timestamps for series 1
        bursts2: List of burst timestamps for series 2
        alignment_window_ms: Alignment window in milliseconds (default: 2 minutes)

    Returns:
        Number of aligned bursts
    """
    if not bursts1 or not bursts2:
        return 0

    aligned_count = 0
    used_bursts2 = set()  # Avoid double-counting

    for burst1_ts in bursts1:
        for burst2_ts in bursts2:
            if burst2_ts in used_bursts2:
                continue

            # Check if bursts are within alignment window
            if abs(burst1_ts - burst2_ts) <= alignment_window_ms:
                aligned_count += 1
                used_bursts2.add(burst2_ts)
                break  # Move to next burst1, avoid multiple matches

    return aligned_count


def detect_bursts(series_map: Dict[str, Dict[int, float]], z_threshold: float = Z_THRESHOLD) -> List[dict]:
    """
    Detect burst correlations between time series pairs using proper rolling baseline.

    For each pair of series:
    1. Detect bursts in each series using rolling baseline z-scores
    2. Count aligned bursts within time window
    3. Calculate correlation and statistical significance
    4. Apply robust thresholds for support and confidence

    Args:
        series_map: Dictionary mapping series keys to time series data
        z_threshold: Z-score threshold for burst detection

    Returns:
        List of burst correlation anomalies
    """
    burst_pairs = []
    window_size = 10  # 10 buckets = 10 minutes at 60s intervals
    alignment_window_ms = 120000  # 2 minutes alignment window

    # Filter series based on JOIN_MODE
    if JOIN_MODE == 'resource':
        primary_keys = [k for k in series_map.keys() if k.startswith(('resource:', 'monitor:'))]
        logger.info(f"Resource mode: Analyzing {len(primary_keys)} resource/monitor series for burst correlations")
    else:  # service mode
        primary_keys = list(series_map.keys())
        logger.info(f"Service mode: Analyzing {len(primary_keys)} series for burst correlations")

    for i in range(len(primary_keys)):
        for j in range(i + 1, len(primary_keys)):
            series1_key = primary_keys[i]
            series2_key = primary_keys[j]

            series1_data = series_map[series1_key]
            series2_data = series_map[series2_key]

            # Need sufficient data for rolling baseline
            if len(series1_data) < window_size + 2 or len(series2_data) < window_size + 2:
                continue

            # Find overlapping timestamps
            common_timestamps = set(series1_data.keys()) & set(series2_data.keys())
            if len(common_timestamps) < window_size + 2:
                continue

            try:
                # Detect bursts in each series using rolling baseline
                bursts1 = detect_bursts_in_series(series1_data, z_threshold, window_size)
                bursts2 = detect_bursts_in_series(series2_data, z_threshold, window_size)

                if not bursts1 or not bursts2:
                    continue  # No bursts in one or both series

                # Count aligned bursts within time window
                aligned_bursts = count_aligned_bursts(bursts1, bursts2, alignment_window_ms)

                # Apply robust thresholds
                total_bursts = len(bursts1) + len(bursts2)
                confidence = aligned_bursts / min(len(bursts1), len(bursts2)) if bursts1 and bursts2 else 0

                # Minimum support: at least 2 aligned bursts and 50% confidence
                if aligned_bursts < 2 or confidence < 0.5:
                    continue

                # Calculate correlation on overlapping data for additional validation
                values1 = [series1_data[ts] for ts in sorted(common_timestamps)]
                values2 = [series2_data[ts] for ts in sorted(common_timestamps)]

                if len(values1) < 3:
                    continue

                # Calculate Pearson correlation
                # Check for constant arrays before correlation calculation
                if np.std(values1) == 0 or np.std(values2) == 0:
                    # One or both arrays are constant, skip correlation
                    continue

                # Calculate correlation with proper error handling
                try:
                    corr_result = pearsonr(values1, values2)
                    # Extract values regardless of scipy version
                    correlation = corr_result[0] if isinstance(corr_result, tuple) else corr_result.correlation
                    p_value = corr_result[1] if isinstance(corr_result, tuple) else corr_result.pvalue
                    # Ensure they are numeric
                    correlation = float(correlation)  # type: ignore
                    p_value = float(p_value)  # type: ignore
                except (ValueError, TypeError) as e:
                    logger.warning(f"Correlation calculation failed for {series1_key} vs {series2_key}: {e}")
                    continue

                # Calculate confidence interval using Fisher's Z transformation
                n = len(values1)
                if n > 3 and abs(correlation) < 0.999:  # Avoid edge cases
                    z_fisher = 0.5 * np.log((1 + correlation) / (1 - correlation))
                    se = 1 / np.sqrt(n - 3)
                    z_critical = stats.norm.ppf((1 + CONF_LEVEL) / 2)

                    ci_lower_z = z_fisher - z_critical * se
                    ci_upper_z = z_fisher + z_critical * se

                    ci_lower = (np.exp(2 * ci_lower_z) - 1) / (np.exp(2 * ci_lower_z) + 1)
                    ci_upper = (np.exp(2 * ci_upper_z) - 1) / (np.exp(2 * ci_upper_z) + 1)
                else:
                    ci_lower, ci_upper = correlation, correlation

                # Determine significance and priority
                is_significant = p_value < SIGNIFICANCE_P and abs(correlation) >= CORR_THRESHOLD

                # Check for severity bias (prioritize ERROR/CRITICAL series)
                has_error_series = ('ERROR' in series1_key or 'CRITICAL' in series1_key or
                                  'ERROR' in series2_key or 'CRITICAL' in series2_key)

                # Calculate alignment strength based on total buckets
                alignment_strength = aligned_bursts / len(common_timestamps) if common_timestamps else 0

                # Create burst correlation result with enhanced context
                burst_result = {
                    'series1': series1_key,
                    'series2': series2_key,
                    'aligned_bursts': aligned_bursts,
                    'total_buckets': len(common_timestamps),
                    'alignment_strength': alignment_strength,
                    'correlation': correlation,
                    'p_value': p_value,
                    'confidence_interval': [ci_lower, ci_upper],
                    'sample_size': n,
                    'is_significant': is_significant,
                    'has_error_series': has_error_series,
                    'strategy': 'rolling_z_score',
                    'means': [np.mean(values1), np.mean(values2)],
                    'stds': [np.std(values1, ddof=1), np.std(values2, ddof=1)],
                    'correlation_basis': {
                        'burst_pattern': 'rolling_baseline',
                        'burst_count': aligned_bursts,
                        'total_bursts_series1': len(bursts1),
                        'total_bursts_series2': len(bursts2),
                        'confidence': confidence,
                        'alignment_window_minutes': alignment_window_ms / 60000,
                        'rolling_window_buckets': window_size,
                        'correlation_trigger': 'burst_alignment',
                        'burst_intensity': alignment_strength,
                        'series1_type': series1_key.split(':')[0],
                        'series2_type': series2_key.split(':')[0]
                    }
                }

                # Robust filtering: already passed minimum support and confidence checks
                burst_pairs.append(burst_result)

            except Exception as e:
                logger.warning(f"Error calculating correlation for {series1_key} vs {series2_key}: {e}")
                continue

    # Sort by significance and strength
    burst_pairs.sort(key=lambda x: (
        x['is_significant'],
        x['has_error_series'],
        x['alignment_strength'],
        abs(x['correlation'])
    ), reverse=True)

    logger.info(f"Found {len(burst_pairs)} burst correlation pairs")
    return burst_pairs


def cross_corr_lead_lag(series_map: Dict[str, Dict[int, float]], max_lag: int = MAX_LAG_BUCKETS, adaptive_thresholds: dict = None) -> List[dict]:
    """
    Detect lead-lag relationships between time series pairs.

    For each pair:
    1. Search lags in [-max_lag, +max_lag] range
    2. Find best correlation and its lag
    3. Calculate simplified Granger causality and precedence scores
    4. Combine scores for confidence measure

    Args:
        series_map: Dictionary mapping series keys to time series data
        max_lag: Maximum lag to search in buckets

    Returns:
        List of lead-lag relationship anomalies
    """
    lead_lag_pairs = []

    # Filter series based on JOIN_MODE (same as burst detection)
    if JOIN_MODE == 'resource':
        # Prioritize resource: and monitor: series
        primary_keys = [k for k in series_map.keys() if k.startswith(('resource:', 'monitor:'))]
        logger.info(f"Resource mode: Analyzing {len(primary_keys)} resource/monitor series for lead-lag relationships")
    else:  # service mode
        # Include all series
        primary_keys = list(series_map.keys())
        logger.info(f"Service mode: Analyzing {len(primary_keys)} series for lead-lag relationships")

    for i in range(len(primary_keys)):
        for j in range(i + 1, len(primary_keys)):
            series1_key = primary_keys[i]
            series2_key = primary_keys[j]

            series1_data = series_map[series1_key]
            series2_data = series_map[series2_key]

            # Find overlapping time range
            all_ts1 = set(series1_data.keys())
            all_ts2 = set(series2_data.keys())

            if len(all_ts1) < 8 or len(all_ts2) < 8:
                continue

            min_ts = max(min(all_ts1), min(all_ts2))
            max_ts = min(max(all_ts1), max(all_ts2))

            # Create aligned time series for lag analysis
            bucket_size_ms = BUCKET_SEC * 1000
            time_range = list(range(int(min_ts), int(max_ts) + bucket_size_ms, bucket_size_ms))

            if len(time_range) < max_lag * 2 + 8:  # Need enough data for lag analysis
                continue

            # Fill missing values with 0
            values1 = [series1_data.get(ts, 0) for ts in time_range]
            values2 = [series2_data.get(ts, 0) for ts in time_range]

            best_correlation = 0
            best_lag = 0
            best_lag_seconds = 0

            # Search for best lag
            for lag in range(-max_lag, max_lag + 1):
                if lag == 0:
                    # No lag case
                    try:
                        # Check for constant arrays
                        if np.std(values1) == 0 or np.std(values2) == 0:
                            continue
                        corr_result = pearsonr(values1, values2)
                        corr = float(corr_result[0])  # type: ignore
                        if abs(corr) > abs(best_correlation):
                            best_correlation = corr
                            best_lag = lag
                            best_lag_seconds = lag * BUCKET_SEC
                    except:
                        continue
                elif lag > 0:
                    # series1 leads series2 by lag buckets
                    if len(values1) > lag and len(values2) > lag:
                        try:
                            # Check for constant arrays
                            vals1_lag = values1[:-lag]
                            vals2_lag = values2[lag:]
                            if np.std(vals1_lag) == 0 or np.std(vals2_lag) == 0:
                                continue
                            corr_result = pearsonr(vals1_lag, vals2_lag)
                            corr = float(corr_result[0])  # type: ignore
                            if abs(corr) > abs(best_correlation):
                                best_correlation = corr
                                best_lag = lag
                                best_lag_seconds = lag * BUCKET_SEC
                        except:
                            continue
                else:
                    # series2 leads series1 by |lag| buckets
                    abs_lag = abs(lag)
                    if len(values1) > abs_lag and len(values2) > abs_lag:
                        try:
                            # Check for constant arrays
                            vals1_lag = values1[abs_lag:]
                            vals2_lag = values2[:-abs_lag]
                            if np.std(vals1_lag) == 0 or np.std(vals2_lag) == 0:
                                continue
                            corr_result = pearsonr(vals1_lag, vals2_lag)
                            corr = float(corr_result[0])  # type: ignore
                            if abs(corr) > abs(best_correlation):
                                best_correlation = corr
                                best_lag = lag
                                best_lag_seconds = lag * BUCKET_SEC
                        except:
                            continue

            # Calculate simplified Granger causality score
            granger_score = 0
            try:
                # Simple AR model comparison (baseline vs with exogenous variable)
                if best_lag != 0:
                    # This is a simplified version - in practice would use proper AR modeling
                    # For now, use correlation strength as proxy
                    granger_score = min(abs(best_correlation) * 0.8, 1.0)
            except:
                granger_score = 0

            # Calculate precedence score using actual peak timing
            precedence_score = 0
            try:
                # Find peaks in both series
                peaks1_ts = []
                peaks2_ts = []

                for k, ts in enumerate(time_range):
                    if k > 0 and k < len(time_range) - 1:
                        if values1[k] > values1[k-1] and values1[k] > values1[k+1] and values1[k] > np.mean(values1):
                            peaks1_ts.append(ts)
                        if values2[k] > values2[k-1] and values2[k] > values2[k+1] and values2[k] > np.mean(values2):
                            peaks2_ts.append(ts)

                # Calculate average time difference between peaks
                if peaks1_ts and peaks2_ts:
                    time_diffs = []
                    for p1 in peaks1_ts:
                        closest_p2 = min(peaks2_ts, key=lambda x: abs(x - p1))
                        time_diffs.append((closest_p2 - p1) / 1000)  # Convert to seconds

                    if time_diffs:
                        avg_diff = np.mean(time_diffs)
                        # Score based on consistency of direction and magnitude
                        consistency = 1 - (np.std(time_diffs) / (abs(avg_diff) + 1))
                        precedence_score = min(float(consistency * (abs(avg_diff) / 60)), 1.0)  # Normalize by minute
            except:
                precedence_score = 0

            # Calculate overall confidence
            confidence = (abs(best_correlation) * 0.5 + granger_score * 0.3 + precedence_score * 0.2)

            # Keep if any score is above adaptive threshold
            min_correlation = adaptive_thresholds.get('correlation_threshold', 0.25) if adaptive_thresholds else 0.25
            if abs(best_correlation) > min_correlation or granger_score > 0.1 or precedence_score > 0.15:
                sample_size = min(len(values1), len(values2))

                # Analyze lead-lag correlation basis
                leadlag_context = analyze_leadlag_correlation_basis(
                    series1_key, series2_key, best_lag, best_correlation,
                    granger_score, precedence_score, series1_data, series2_data
                )

                lead_lag_result = {
                    'series1': series1_key,
                    'series2': series2_key,
                    'lag_buckets': best_lag,
                    'lag_seconds': best_lag_seconds,
                    'correlation': best_correlation,
                    'granger_score': granger_score,
                    'precedence_score': precedence_score,
                    'confidence': confidence,
                    'sample_size': sample_size,
                    'direction': 'series1_leads' if best_lag > 0 else 'series2_leads' if best_lag < 0 else 'simultaneous',
                    'correlation_basis': leadlag_context
                }

                lead_lag_pairs.append(lead_lag_result)

    # Sort by confidence
    lead_lag_pairs.sort(key=lambda x: x['confidence'], reverse=True)

    logger.info(f"Found {len(lead_lag_pairs)} lead-lag relationships")
    return lead_lag_pairs


def pmi_cooccurrence(normalized_events: List[dict],
                    min_support: int = PMI_MIN_SUPPORT,
                    pmi_threshold: float = PMI_THRESHOLD) -> List[dict]:
    """
    Analyze token co-occurrence patterns using Pointwise Mutual Information.

    Treats each time bucket as a transaction of tokens aggregated across events.
    Computes PMI = log2(p(a,b) / (p(a) * p(b))) for token pairs.

    Args:
        normalized_events: List of normalized events
        min_support: Minimum support count for token pairs
        pmi_threshold: Minimum PMI score threshold

    Returns:
        List of PMI co-occurrence anomalies
    """
    if not normalized_events:
        return []

    logger.info("Analyzing PMI co-occurrence patterns")

    # Group events by time buckets and collect tokens
    bucket_tokens = defaultdict(set)
    token_counts = defaultdict(int)
    pair_counts = defaultdict(int)
    pair_buckets = defaultdict(list)  # Track which buckets each pair occurred in
    total_buckets = 0

    for event in normalized_events:
        ts_ms = event['ts_ms']
        bucket_ts = (ts_ms // (BUCKET_SEC * 1000)) * (BUCKET_SEC * 1000)

        event_tokens = set(event['tokens'])
        bucket_tokens[bucket_ts].update(event_tokens)

    # Count token occurrences and co-occurrences
    total_buckets = len(bucket_tokens)

    for bucket_ts, tokens in bucket_tokens.items():
        token_list = list(tokens)

        # Count individual tokens
        for token in token_list:
            token_counts[token] += 1

        # Count token pairs
        for i in range(len(token_list)):
            for j in range(i + 1, len(token_list)):
                token_a = token_list[i]
                token_b = token_list[j]
                # Ensure consistent ordering
                if token_a > token_b:
                    token_a, token_b = token_b, token_a
                pair_counts[(token_a, token_b)] += 1
                pair_buckets[(token_a, token_b)].append(bucket_ts)

    # Calculate PMI scores
    pmi_results = []

    for (token_a, token_b), pair_count in pair_counts.items():
        if pair_count < min_support:
            continue

        count_a = token_counts[token_a]
        count_b = token_counts[token_b]

        if count_a == 0 or count_b == 0 or total_buckets == 0:
            continue

        # Calculate probabilities
        p_a = count_a / total_buckets
        p_b = count_b / total_buckets
        p_ab = pair_count / total_buckets

        # Calculate PMI
        if p_a * p_b > 0:
            pmi_score = np.log2(p_ab / (p_a * p_b))
        else:
            continue

        if pmi_score >= pmi_threshold:
            # Calculate confidence score (weighted combination)
            normalized_support = min(pair_count / 10.0, 1.0)  # Normalize support
            pmi_strength = min(pmi_score / 5.0, 1.0)  # Normalize PMI
            sample_size_score = min(total_buckets / 100.0, 1.0)  # Normalize sample size

            confidence = (normalized_support * 0.4 + pmi_strength * 0.4 + sample_size_score * 0.2)

            # Check if any token comes from ERROR/CRITICAL series
            has_error_token = any('ERROR' in token or 'CRITICAL' in token
                                for token in [token_a, token_b])

            # Analyze correlation basis and context
            co_occurrence_buckets = pair_buckets[(token_a, token_b)]
            correlation_context = analyze_pmi_correlation_basis(
                token_a, token_b, bucket_tokens, normalized_events,
                co_occurrence_buckets, total_buckets
            )

            pmi_result = {
                'token_a': token_a,
                'token_b': token_b,
                'pmi_score': pmi_score,
                'support': pair_count,
                'count_a': count_a,
                'count_b': count_b,
                'total_buckets': total_buckets,
                'confidence': confidence,
                'has_error_token': has_error_token,
                'p_a': p_a,
                'p_b': p_b,
                'p_ab': p_ab,
                'correlation_basis': correlation_context
            }

            pmi_results.append(pmi_result)

    # Sort by confidence and error priority
    pmi_results.sort(key=lambda x: (x['has_error_token'], x['confidence'], x['pmi_score']), reverse=True)

    logger.info(f"Found {len(pmi_results)} significant PMI co-occurrences")
    return pmi_results


def analyze_pmi_correlation_basis(token_a: str, token_b: str, bucket_tokens: dict,
                                 normalized_events: List[dict], co_occurrence_buckets: List[int],
                                 total_buckets: int) -> dict:
    """
    Analyze the basis and context of PMI correlation to explain how/why it happened.

    Args:
        token_a, token_b: The correlated tokens
        bucket_tokens: Token occurrences by time bucket
        normalized_events: Original events for context
        co_occurrence_buckets: Time buckets where both tokens appeared
        total_buckets: Total time buckets analyzed

    Returns:
        Dictionary with correlation basis analysis
    """
    try:
        # Find events that contain both tokens
        related_events = []
        for event in normalized_events:
            event_tokens = set(event.get('tokens', []))
            if token_a in event_tokens and token_b in event_tokens:
                related_events.append(event)

        # Analyze temporal patterns
        co_occurrence_times = []
        for bucket_ts in co_occurrence_buckets:
            co_occurrence_times.append(bucket_ts)

        # Calculate time clustering
        if len(co_occurrence_times) > 1:
            time_gaps = []
            sorted_times = sorted(co_occurrence_times)
            for i in range(1, len(sorted_times)):
                gap_seconds = (sorted_times[i] - sorted_times[i-1]) / 1000
                time_gaps.append(gap_seconds)

            avg_gap = np.mean(time_gaps) if time_gaps else 0
            gap_std = np.std(time_gaps) if len(time_gaps) > 1 else 0

            # Determine clustering pattern
            if gap_std < avg_gap * 0.3:  # Low variance = regular pattern
                temporal_pattern = "regular_intervals"
            elif any(gap < 300 for gap in time_gaps):  # Some gaps < 5 minutes
                temporal_pattern = "burst_clusters"
            else:
                temporal_pattern = "scattered_events"
        else:
            temporal_pattern = "single_occurrence"
            avg_gap = 0
            gap_std = 0

        # Analyze event context
        severities = [event.get('severity', 'unknown') for event in related_events]
        severity_distribution = {sev: severities.count(sev) for sev in set(severities)}

        # Extract resource context
        resources = set()
        namespaces = set()
        for event in related_events:
            resource_id = event.get('resource_id', '')
            if resource_id:
                resources.add(resource_id)

            tags_map = event.get('tags_map', {})
            if 'kube_namespace' in tags_map:
                namespaces.add(tags_map['kube_namespace'])

        # Determine correlation trigger
        correlation_trigger = "unknown"
        if "deployment" in token_a.lower() or "deployment" in token_b.lower():
            correlation_trigger = "deployment_scaling"
        elif "crashloop" in token_a.lower() or "crashloop" in token_b.lower():
            correlation_trigger = "pod_failures"
        elif "imagepull" in token_a.lower() or "imagepull" in token_b.lower():
            correlation_trigger = "image_issues"
        elif "monitor_name" in token_a and "evt_name" in token_b:
            correlation_trigger = "alert_event_pairing"
        elif "resource_id" in token_a or "resource_id" in token_b:
            correlation_trigger = "resource_lifecycle"

        # Calculate co-occurrence density
        total_time_span = (max(co_occurrence_times) - min(co_occurrence_times)) / 1000 if len(co_occurrence_times) > 1 else 0
        co_occurrence_density = len(co_occurrence_times) / max(total_time_span / 3600, 1)  # per hour

        return {
            'temporal_pattern': temporal_pattern,
            'co_occurrence_count': len(co_occurrence_times),
            'avg_time_gap_minutes': avg_gap / 60 if avg_gap else 0,
            'time_gap_consistency': 1 - (gap_std / max(avg_gap, 1)) if avg_gap > 0 else 1,
            'correlation_trigger': correlation_trigger,
            'severity_distribution': severity_distribution,
            'affected_resources': list(resources)[:5],  # Limit to 5 for display
            'affected_namespaces': list(namespaces),
            'co_occurrence_density_per_hour': co_occurrence_density,
            'total_time_span_hours': total_time_span / 3600 if total_time_span > 0 else 0,
            'related_events_count': len(related_events)
        }

    except Exception as e:
        logger.warning(f"Failed to analyze PMI correlation basis for {token_a} <-> {token_b}: {e}")
        return {
            'temporal_pattern': 'analysis_failed',
            'correlation_trigger': 'unknown',
            'error': str(e)
        }


def analyze_burst_correlation_basis(series1_key: str, series2_key: str,
                                   series1_data: dict, series2_data: dict,
                                   common_timestamps: list, aligned_bursts: int,
                                   z_scores1: dict, z_scores2: dict, z_threshold: float) -> dict:
    """
    Analyze the basis and context of burst correlation to explain how/why it happened.
    """
    try:
        # Find burst timestamps
        burst_timestamps = []
        for ts in common_timestamps:
            z1 = z_scores1.get(ts, 0)
            z2 = z_scores2.get(ts, 0)
            if abs(z1) >= z_threshold and abs(z2) >= z_threshold:
                burst_timestamps.append(ts)

        # Analyze burst clustering
        if len(burst_timestamps) > 1:
            time_gaps = []
            sorted_bursts = sorted(burst_timestamps)
            for i in range(1, len(sorted_bursts)):
                gap_seconds = (sorted_bursts[i] - sorted_bursts[i-1]) / 1000
                time_gaps.append(gap_seconds)

            avg_gap = np.mean(time_gaps) if time_gaps else 0
            if avg_gap < 300:  # < 5 minutes
                burst_pattern = "rapid_succession"
            elif avg_gap < 3600:  # < 1 hour
                burst_pattern = "periodic_bursts"
            else:
                burst_pattern = "scattered_bursts"
        else:
            burst_pattern = "single_burst" if aligned_bursts > 0 else "no_bursts"
            avg_gap = 0

        # Determine correlation trigger based on series names
        correlation_trigger = "unknown"
        if "resource:" in series1_key or "resource:" in series2_key:
            correlation_trigger = "resource_scaling"
        elif "monitor:" in series1_key and "monitor:" in series2_key:
            correlation_trigger = "cascading_alerts"
        elif "kubernetes" in series1_key.lower() or "kubernetes" in series2_key.lower():
            correlation_trigger = "k8s_infrastructure"
        elif "ERROR" in series1_key or "ERROR" in series2_key:
            correlation_trigger = "error_propagation"

        # Calculate burst intensity
        max_z1 = max([abs(z_scores1.get(ts, 0)) for ts in burst_timestamps]) if burst_timestamps else 0
        max_z2 = max([abs(z_scores2.get(ts, 0)) for ts in burst_timestamps]) if burst_timestamps else 0
        burst_intensity = (max_z1 + max_z2) / 2

        # Calculate time span
        total_time_span = (max(burst_timestamps) - min(burst_timestamps)) / 1000 if len(burst_timestamps) > 1 else 0

        return {
            'burst_pattern': burst_pattern,
            'burst_count': aligned_bursts,
            'avg_burst_gap_minutes': avg_gap / 60 if avg_gap else 0,
            'correlation_trigger': correlation_trigger,
            'burst_intensity': burst_intensity,
            'total_time_span_hours': total_time_span / 3600 if total_time_span > 0 else 0,
            'series1_type': series1_key.split(':')[0] if ':' in series1_key else 'unknown',
            'series2_type': series2_key.split(':')[0] if ':' in series2_key else 'unknown',
            'simultaneous_events': len(burst_timestamps)
        }

    except Exception as e:
        logger.warning(f"Failed to analyze burst correlation basis for {series1_key} <-> {series2_key}: {e}")
        return {
            'burst_pattern': 'analysis_failed',
            'correlation_trigger': 'unknown',
            'error': str(e)
        }


def analyze_leadlag_correlation_basis(series1_key: str, series2_key: str,
                                     best_lag: int, best_correlation: float,
                                     granger_score: float, precedence_score: float,
                                     series1_data: dict, series2_data: dict) -> dict:
    """
    Analyze the basis and context of lead-lag correlation to explain how/why it happened.
    """
    try:
        # Determine relationship type
        if best_lag > 0:
            relationship_type = "causal_chain"
            leader = series1_key
            follower = series2_key
        elif best_lag < 0:
            relationship_type = "reverse_causal"
            leader = series2_key
            follower = series1_key
        else:
            relationship_type = "simultaneous"
            leader = follower = "both"

        # Analyze lag characteristics
        lag_minutes = abs(best_lag) * 5 / 60  # Convert buckets to minutes (assuming 5-second buckets)

        if lag_minutes < 1:
            lag_category = "immediate"
        elif lag_minutes < 15:
            lag_category = "short_delay"
        elif lag_minutes < 60:
            lag_category = "medium_delay"
        else:
            lag_category = "long_delay"

        # Determine correlation trigger based on series names
        correlation_trigger = "unknown"
        if "resource:" in series1_key and "monitor:" in series2_key:
            correlation_trigger = "resource_to_alert"
        elif "monitor:" in series1_key and "resource:" in series2_key:
            correlation_trigger = "alert_to_resource"
        elif "kubernetes" in series1_key.lower() or "kubernetes" in series2_key.lower():
            correlation_trigger = "k8s_cascade"
        elif "ERROR" in series1_key or "ERROR" in series2_key:
            correlation_trigger = "error_cascade"

        # Calculate relationship strength
        relationship_strength = (abs(best_correlation) + granger_score + precedence_score) / 3

        # Analyze data patterns
        series1_values = list(series1_data.values())
        series2_values = list(series2_data.values())

        series1_activity = sum(1 for v in series1_values if v > 0)
        series2_activity = sum(1 for v in series2_values if v > 0)

        activity_ratio = series1_activity / max(series2_activity, 1)

        return {
            'relationship_type': relationship_type,
            'lag_category': lag_category,
            'lag_minutes': lag_minutes,
            'correlation_trigger': correlation_trigger,
            'relationship_strength': relationship_strength,
            'leader_series': leader,
            'follower_series': follower,
            'activity_ratio': activity_ratio,
            'granger_strength': granger_score,
            'precedence_strength': precedence_score,
            'correlation_strength': abs(best_correlation)
        }

    except Exception as e:
        logger.warning(f"Failed to analyze lead-lag correlation basis for {series1_key} <-> {series2_key}: {e}")
        return {
            'relationship_type': 'analysis_failed',
            'correlation_trigger': 'unknown',
            'error': str(e)
        }


def analyze_change_attribution_basis(change_series: str, effect_series: str,
                                    correlation_coefficient: float, lag_minutes: float,
                                    change_count: int, effect_count: int,
                                    change_data: dict, effect_data: dict,
                                    change_events: List[dict], effect_events: List[dict]) -> dict:
    """
    Analyze the basis and context of change attribution to explain how/why it happened.
    """
    try:
        # Find events related to this change series
        related_change_events = [e for e in change_events if e['resource_id'] == change_series]
        related_effect_events = [e for e in effect_events if e['resource_id'] == effect_series]

        # Analyze change type from actual event content
        change_type = "unknown"
        change_keywords = []

        for event in related_change_events:
            tokens = event.get('tokens', [])
            monitor_name = event.get('monitor', {}).get('name', '').lower()

            # Check tokens for change indicators
            for token in tokens:
                token_lower = token.lower()
                if 'deployment' in token_lower or 'deploy' in token_lower:
                    change_type = "deployment_change"
                    change_keywords.append('deployment')
                elif 'config' in token_lower:
                    change_type = "configuration_change"
                    change_keywords.append('config')
                elif 'scale' in token_lower or 'replica' in token_lower:
                    change_type = "scaling_change"
                    change_keywords.append('scaling')
                elif 'update' in token_lower or 'rollout' in token_lower:
                    change_type = "update_change"
                    change_keywords.append('update')

            # Check monitor name
            if 'deployment' in monitor_name:
                change_type = "deployment_change"
                change_keywords.append('deployment')
            elif 'config' in monitor_name:
                change_type = "configuration_change"
                change_keywords.append('config')

        # If still unknown, infer from resource type
        if change_type == "unknown":
            if 'pod' in change_series.lower():
                change_type = "pod_lifecycle"
            elif 'service' in change_series.lower():
                change_type = "service_change"
            else:
                change_type = "resource_change"

        # Analyze effect type from actual event content
        effect_type = "unknown"
        effect_keywords = []

        for event in related_effect_events:
            tokens = event.get('tokens', [])
            severity = event.get('severity', '')
            monitor_name = event.get('monitor', {}).get('name', '').lower()

            # Check severity and tokens
            if severity in ['ERROR', 'CRITICAL']:
                effect_type = "error_increase"
                effect_keywords.append('error')

            for token in tokens:
                token_lower = token.lower()
                if 'crashloop' in token_lower or 'crash' in token_lower:
                    effect_type = "pod_failures"
                    effect_keywords.append('crash')
                elif 'imagepull' in token_lower:
                    effect_type = "image_issues"
                    effect_keywords.append('image')
                elif 'restart' in token_lower:
                    effect_type = "restart_events"
                    effect_keywords.append('restart')
                elif 'performance' in token_lower or 'latency' in token_lower:
                    effect_type = "performance_impact"
                    effect_keywords.append('performance')

            # Check monitor name
            if 'error' in monitor_name or 'fail' in monitor_name:
                effect_type = "error_increase"
                effect_keywords.append('error')
            elif 'performance' in monitor_name or 'latency' in monitor_name:
                effect_type = "performance_impact"
                effect_keywords.append('performance')

        # If still unknown, infer from resource type
        if effect_type == "unknown":
            if 'pod' in effect_series.lower():
                effect_type = "pod_impact"
            elif 'service' in effect_series.lower():
                effect_type = "service_impact"
            else:
                effect_type = "resource_impact"

        # Analyze lag characteristics
        if lag_minutes < 1:
            lag_category = "immediate"
        elif lag_minutes < 5:
            lag_category = "very_fast"
        elif lag_minutes < 15:
            lag_category = "fast"
        elif lag_minutes < 60:
            lag_category = "moderate"
        else:
            lag_category = "slow"

        # Calculate impact ratio
        impact_ratio = effect_count / max(change_count, 1)

        # Determine attribution confidence
        if correlation_coefficient > 0.8:
            attribution_confidence = "very_high"
        elif correlation_coefficient > 0.6:
            attribution_confidence = "high"
        elif correlation_coefficient > 0.4:
            attribution_confidence = "moderate"
        else:
            attribution_confidence = "low"

        # Analyze change frequency
        change_values = list(change_data.values())
        effect_values = list(effect_data.values())

        change_frequency = sum(1 for v in change_values if v > 0) / len(change_values) if change_values else 0
        effect_frequency = sum(1 for v in effect_values if v > 0) / len(effect_values) if effect_values else 0

        return {
            'change_type': change_type,
            'effect_type': effect_type,
            'lag_category': lag_category,
            'lag_minutes': lag_minutes,
            'impact_ratio': impact_ratio,
            'attribution_confidence': attribution_confidence,
            'change_frequency': change_frequency,
            'effect_frequency': effect_frequency,
            'correlation_strength': correlation_coefficient,
            'total_changes': change_count,
            'total_effects': effect_count
        }

    except Exception as e:
        logger.warning(f"Failed to analyze change attribution basis for {change_series} -> {effect_series}: {e}")
        return {
            'change_type': 'analysis_failed',
            'effect_type': 'unknown',
            'error': str(e)
        }


def classify_change_events(normalized_events: List[dict]) -> Tuple[List[dict], List[dict]]:
    """
    Classify events into change events and effect events.

    Change events: deployments, config changes, etc.
    Effect events: errors, latency issues, restarts, etc.

    Args:
        normalized_events: List of normalized events

    Returns:
        Tuple of (change_events, effect_events)
    """
    change_events = []
    effect_events = []

    for event in normalized_events:
        tokens = set(event['tokens'])
        severity = event['severity']
        monitor_name = event['monitor'].get('name', '').lower()

        # First, check if this is clearly an effect event (errors, failures, restarts)
        is_effect = False
        effect_keywords = ['restart', 'crash', 'fail', 'error', 'down', 'unavailable', 'timeout', 'imagepull', 'crashloop']

        # Check severity
        if severity in ['ERROR', 'CRITICAL']:
            is_effect = True

        # Check monitor name for effect indicators
        if any(keyword in monitor_name for keyword in effect_keywords):
            is_effect = True

        # Check tokens for effect indicators
        for token in tokens:
            token_lower = token.lower()
            if any(keyword in token_lower for keyword in effect_keywords):
                is_effect = True
                break

        # Check status/severity field robustly
        status = ''
        sev_lower = event.get('severity', '').lower()
        if sev_lower in ['error', 'critical']:
            status = sev_lower
        if status in ['error', 'critical', 'alert']:
            is_effect = True

        # If it's an effect event, classify it as such
        if is_effect:
            effect_events.append(event)
        else:
            # Only classify as change event if it has clear change indicators
            is_change = False
            change_keywords = ['deployment', 'deploy', 'config', 'update', 'release', 'rollout', 'migration']

            # More specific change detection - avoid false positives
            for token in tokens:
                token_lower = token.lower()
                if any(keyword in token_lower for keyword in change_keywords):
                    is_change = True
                    break

            # Check monitor name for specific change indicators (not just kubernetes + pod)
            if any(keyword in monitor_name for keyword in change_keywords):
                is_change = True

            # Check for deployment/scaling specific patterns
            if 'deployment' in monitor_name and ('replica' in monitor_name or 'desired' in monitor_name):
                is_change = True

            # Check for specific transition types that indicate changes
            transition_type = event['transition'].get('type', '')
            if transition_type in ['deployment', 'config_change', 'update']:
                is_change = True

            # DEMO: For demonstration purposes, treat some pod events as "changes"
            # to show change attribution analysis (normally you'd have separate change events)
            if not is_change and 'pod_name' in str(event.get('tags', [])):
                # Treat 10% of pod events as "changes" for demo purposes
                import hashlib
                pod_name = event.get('resource_id', '')
                if pod_name and int(hashlib.md5(pod_name.encode()).hexdigest()[:2], 16) < 25:  # ~10%
                    is_change = True

            if is_change:
                change_events.append(event)

    return change_events, effect_events


def change_attribution(normalized_events: List[dict]) -> List[dict]:
    """
    Detect cause-effect relationships between change and effect events.

    Uses temporal correlation analysis to identify causal relationships
    between change events and their potential effects.

    Args:
        normalized_events: List of normalized events

    Returns:
        List of change attribution anomalies
    """
    if not normalized_events:
        return []

    logger.info("Analyzing change attribution patterns")

    # Classify events
    change_events, effect_events = classify_change_events(normalized_events)

    if not change_events or not effect_events:
        logger.info(f"Insufficient events for change attribution: {len(change_events)} changes, {len(effect_events)} effects")
        return []

    logger.info(f"Analyzing {len(change_events)} change events vs {len(effect_events)} effect events")

    # Build minute-bucketed time series for changes and effects
    bucket_size_ms = 60 * 1000  # 1 minute buckets for change attribution

    # Group by service/resource for more targeted analysis
    change_series = defaultdict(lambda: defaultdict(int))
    effect_series = defaultdict(lambda: defaultdict(int))

    for event in change_events:
        bucket_ts = (event['ts_ms'] // bucket_size_ms) * bucket_size_ms
        resource_key = event['resource_id']
        change_series[resource_key][bucket_ts] += 1

    for event in effect_events:
        bucket_ts = (event['ts_ms'] // bucket_size_ms) * bucket_size_ms
        resource_key = event['resource_id']
        effect_series[resource_key][bucket_ts] += 1

    attribution_results = []
    max_lag_minutes = 30  # 30 minute window for change attribution
    max_lag_buckets = max_lag_minutes

    # Analyze each change-effect series pair
    for change_key, change_buckets in change_series.items():
        for effect_key, effect_buckets in effect_series.items():

            if len(change_buckets) < 2 or len(effect_buckets) < 2:
                continue

            # Create aligned time series
            all_timestamps = sorted(set(change_buckets.keys()) | set(effect_buckets.keys()))
            if len(all_timestamps) < 5:
                continue

            change_values = [change_buckets.get(ts, 0) for ts in all_timestamps]
            effect_values = [effect_buckets.get(ts, 0) for ts in all_timestamps]

            best_correlation = 0
            best_lag_minutes = 0

            # Luminol is disabled due to compatibility issues, using fallback method

            # Fallback method: simple lag correlation
            if best_correlation == 0:
                try:
                    for lag in range(0, min(max_lag_buckets, len(all_timestamps) // 2)):
                        if lag == 0:
                            # Check for constant arrays
                            if np.std(change_values) == 0 or np.std(effect_values) == 0:
                                continue
                            corr_result = pearsonr(change_values, effect_values)
                            corr = float(corr_result[0])  # type: ignore
                        else:
                            if len(change_values) > lag and len(effect_values) > lag:
                                # Check for constant arrays
                                change_lag = change_values[:-lag]
                                effect_lag = effect_values[lag:]
                                if np.std(change_lag) == 0 or np.std(effect_lag) == 0:
                                    continue
                                corr_result = pearsonr(change_lag, effect_lag)
                                corr = float(corr_result[0])  # type: ignore
                            else:
                                continue

                        # Check temporal direction (change should precede effect)
                        if corr > best_correlation and corr > 0.3:
                            best_correlation = corr
                            best_lag_minutes = lag

                except Exception as e:
                    logger.warning(f"Fallback correlation failed for {change_key} -> {effect_key}: {e}")
                    continue

            # Create attribution result if significant
            if best_correlation > 0.3 and best_lag_minutes >= 0:
                # Analyze change attribution basis
                attribution_context = analyze_change_attribution_basis(
                    change_key, effect_key, best_correlation, best_lag_minutes,
                    sum(change_values), sum(effect_values), change_buckets, effect_buckets,
                    change_events, effect_events
                )

                attribution_result = {
                    'change_series': change_key,
                    'effect_series': effect_key,
                    'correlation_coefficient': best_correlation,
                    'lag_minutes': best_lag_minutes,
                    'lag_ms': int(best_lag_minutes * 60 * 1000),
                    'change_count': sum(change_values),
                    'effect_count': sum(effect_values),
                    'confidence': best_correlation,  # Use correlation as confidence
                    'method': 'fallback',
                    'correlation_basis': attribution_context
                }

                attribution_results.append(attribution_result)

    # Sort by confidence
    attribution_results.sort(key=lambda x: x['confidence'], reverse=True)

    logger.info(f"Found {len(attribution_results)} change attribution relationships")
    return attribution_results


def calculate_adaptive_thresholds(normalized_events: List[dict]) -> dict:
    """
    Calculate adaptive thresholds based on data characteristics.

    Adjusts detection thresholds based on:
    - Log volume and error rates
    - Pattern strength and service diversity
    - Sparsity and distribution characteristics

    Args:
        normalized_events: List of normalized events

    Returns:
        Dictionary containing adaptive threshold values
    """
    if not normalized_events:
        return {
            'z_score_threshold': Z_THRESHOLD,
            'correlation_threshold': CORR_THRESHOLD,
            'pmi_threshold': PMI_THRESHOLD,
            'min_points': 8
        }

    logger.info("Calculating adaptive thresholds")

    # Calculate data characteristics
    total_logs = len(normalized_events)

    # Error rate calculation
    error_logs = sum(1 for event in normalized_events if event['severity'] in ['ERROR', 'CRITICAL'])
    error_rate = error_logs / total_logs if total_logs > 0 else 0

    # Service diversity
    services = set()
    for event in normalized_events:
        for token in event['tokens']:
            if token.startswith('service:'):
                services.add(token.split(':', 1)[1])
    service_count = len(services)

    # Time span and sparsity
    timestamps = [event['ts_ms'] for event in normalized_events]
    time_span_hours = (max(timestamps) - min(timestamps)) / (1000 * 3600) if timestamps else 0
    logs_per_minute = total_logs / (time_span_hours * 60) if time_span_hours > 0 else 0

    # Pattern strength (concentration in top service)
    service_counts = defaultdict(int)
    for event in normalized_events:
        for token in event['tokens']:
            if token.startswith('service:'):
                service_counts[token.split(':', 1)[1]] += 1
                break

    if service_counts:
        max_service_share = max(service_counts.values()) / total_logs
    else:
        max_service_share = 1.0

    avg_logs_per_service = total_logs / service_count if service_count > 0 else total_logs

    # Adaptive threshold calculation
    base_z = Z_THRESHOLD
    base_corr = CORR_THRESHOLD
    base_pmi = PMI_THRESHOLD

    # Adjust z-score threshold based on volume and error rate
    if total_logs > 1000 and error_rate < 0.1:
        # High volume, low error rate -> more sensitive
        z_threshold = max(base_z * 0.8, 2.0)
    elif total_logs < 100:
        # Low volume -> less sensitive to avoid noise
        z_threshold = min(base_z * 1.2, 4.0)
    else:
        z_threshold = base_z

    # Adjust correlation threshold based on pattern strength
    if max_service_share > 0.8:
        # Strong patterns -> increase precision
        corr_threshold = min(base_corr * 1.2, 0.5)
    elif max_service_share < 0.3:
        # Weak patterns -> increase sensitivity
        corr_threshold = max(base_corr * 0.8, 0.2)
    else:
        corr_threshold = base_corr

    # Adjust PMI threshold based on sparsity
    if logs_per_minute < 1:
        # Very sparse data -> lower PMI threshold
        pmi_threshold = max(base_pmi * 0.7, 1.5)
    elif logs_per_minute > 10:
        # Dense data -> higher PMI threshold
        pmi_threshold = min(base_pmi * 1.3, 3.0)
    else:
        pmi_threshold = base_pmi

    # Minimum points threshold
    if total_logs > 5000:
        min_points = 12
    elif total_logs > 1000:
        min_points = 10
    else:
        min_points = 8

    adaptive_thresholds = {
        'z_score_threshold': z_threshold,
        'correlation_threshold': corr_threshold,
        'pmi_threshold': pmi_threshold,
        'min_points': min_points,
        'data_characteristics': {
            'total_logs': total_logs,
            'error_rate': error_rate,
            'sparsity': logs_per_minute,
            'pattern_strength': max_service_share,
            'service_count': service_count,
            'avg_logs_per_service': avg_logs_per_service
        }
    }

    logger.info(f"Adaptive thresholds: z={z_threshold:.2f}, corr={corr_threshold:.2f}, pmi={pmi_threshold:.2f}")
    return adaptive_thresholds


# Global drift history storage (in production, this would be persistent)
_drift_history = deque(maxlen=DRIFT_WINDOW_SIZE)


def detect_data_drift(normalized_events: List[dict],
                     drift_threshold: float = DRIFT_THRESHOLD) -> dict:
    """
    Detect data drift by monitoring pattern changes over time.

    Maintains a history of pattern snapshots and computes variance
    to detect significant changes in data characteristics.

    Args:
        normalized_events: List of normalized events
        drift_threshold: Threshold for drift detection

    Returns:
        Dictionary containing drift detection results
    """
    if not normalized_events:
        return {
            'drift_detected': False,
            'drift_score': 0.0,
            'drift_type': 'no_drift',
            'confidence': 0.0,
            'indicators': [],
            'historical_patterns_count': len(_drift_history)
        }

    logger.info("Detecting data drift patterns")

    # Calculate current pattern snapshot
    total_logs = len(normalized_events)

    # Error rate
    error_logs = sum(1 for event in normalized_events if event['severity'] in ['ERROR', 'CRITICAL'])
    current_error_rate = error_logs / total_logs if total_logs > 0 else 0

    # Service distribution
    service_counts = defaultdict(int)
    for event in normalized_events:
        for token in event['tokens']:
            if token.startswith('service:'):
                service_counts[token.split(':', 1)[1]] += 1
                break

    current_service_count = len(service_counts)
    current_pattern_strength = max(service_counts.values()) / total_logs if service_counts else 1.0

    # Create current snapshot
    current_snapshot = {
        'error_rate': current_error_rate,
        'service_count': current_service_count,
        'pattern_strength': current_pattern_strength,
        'timestamp': datetime.now().isoformat()
    }

    # Add to history
    _drift_history.append(current_snapshot)

    # Need at least 10 snapshots for meaningful drift detection
    if len(_drift_history) < 10:
        return {
            'drift_detected': False,
            'drift_score': 0.0,
            'drift_type': 'insufficient_history',
            'confidence': 0.0,
            'indicators': ['Insufficient historical data for drift detection'],
            'historical_patterns_count': len(_drift_history)
        }

    # Calculate drift metrics
    historical_snapshots = list(_drift_history)[:-1]  # Exclude current snapshot

    # Error rate drift
    historical_error_rates = [s['error_rate'] for s in historical_snapshots]
    error_rate_variance = np.var(historical_error_rates) if len(historical_error_rates) > 1 else 0
    error_rate_drift = abs(current_error_rate - np.mean(historical_error_rates))

    # Service count drift
    historical_service_counts = [s['service_count'] for s in historical_snapshots]
    service_count_variance = np.var(historical_service_counts) if len(historical_service_counts) > 1 else 0
    service_count_drift = abs(current_service_count - np.mean(historical_service_counts))

    # Pattern strength drift
    historical_pattern_strengths = [s['pattern_strength'] for s in historical_snapshots]
    pattern_strength_variance = np.var(historical_pattern_strengths) if len(historical_pattern_strengths) > 1 else 0
    pattern_strength_drift = abs(current_pattern_strength - np.mean(historical_pattern_strengths))

    # Calculate overall drift score
    drift_components = []
    indicators = []

    # Normalize drift scores by historical variance (with minimum threshold)
    if error_rate_variance > 0.001:
        error_drift_score = error_rate_drift / np.sqrt(error_rate_variance)
        drift_components.append(error_drift_score)
        if error_drift_score > 2.0:
            indicators.append(f"Significant error rate change: {current_error_rate:.3f} vs historical avg {np.mean(historical_error_rates):.3f}")

    if service_count_variance > 0.1:
        service_drift_score = service_count_drift / np.sqrt(service_count_variance)
        drift_components.append(service_drift_score)
        if service_drift_score > 2.0:
            indicators.append(f"Service count change: {current_service_count} vs historical avg {np.mean(historical_service_counts):.1f}")

    if pattern_strength_variance > 0.001:
        pattern_drift_score = pattern_strength_drift / np.sqrt(pattern_strength_variance)
        drift_components.append(pattern_drift_score)
        if pattern_drift_score > 2.0:
            indicators.append(f"Pattern strength change: {current_pattern_strength:.3f} vs historical avg {np.mean(historical_pattern_strengths):.3f}")

    # Overall drift score (average of normalized components)
    if drift_components:
        drift_score = np.mean(drift_components)
    else:
        drift_score = 0.0

    # Classify drift type and confidence
    if drift_score > 3.0:
        drift_type = 'significant_drift'
        confidence = min(float(drift_score / 5.0), 1.0)
        drift_detected = True
    elif drift_score > 2.0:
        drift_type = 'moderate_drift'
        confidence = min(float(drift_score / 4.0), 1.0)
        drift_detected = True
    elif drift_score > 1.0:
        drift_type = 'minor_drift'
        confidence = min(float(drift_score / 3.0), 1.0)
        drift_detected = drift_score > drift_threshold * 20  # Scale threshold
    else:
        drift_type = 'no_drift'
        confidence = 0.0
        drift_detected = False

    if not indicators:
        indicators = ['No significant pattern changes detected']

    drift_result = {
        'drift_detected': drift_detected,
        'drift_score': drift_score,
        'drift_type': drift_type,
        'confidence': confidence,
        'indicators': indicators,
        'historical_patterns_count': len(_drift_history)
    }

    logger.info(f"Drift detection: {drift_type} (score: {drift_score:.2f}, confidence: {confidence:.2f})")
    return drift_result


def classify_severity_context(normalized_events: List[dict]) -> dict:
    """
    Classify the severity context of the environment.

    Determines if this is a high/medium/low error environment and
    provides recommended thresholds for anomaly severity classification.

    Args:
        normalized_events: List of normalized events

    Returns:
        Dictionary containing severity context information
    """
    if not normalized_events:
        return {
            'overall_metrics': {},
            'error_rates': {},
            'context_level': 'low_error_environment',
            'context_description': 'No events to analyze',
            'recommended_thresholds': {'critical': 0.8, 'high': 0.6},
            'severity_rationale': {}
        }

    logger.info("Classifying severity context")

    # Calculate overall metrics
    total_events = len(normalized_events)
    error_events = sum(1 for event in normalized_events if event['severity'] in ['ERROR', 'CRITICAL'])
    critical_events = sum(1 for event in normalized_events if event['severity'] == 'CRITICAL')

    overall_error_rate = error_events / total_events if total_events > 0 else 0
    critical_rate = critical_events / total_events if total_events > 0 else 0

    # Calculate service-level error rates
    service_events = defaultdict(int)
    service_errors = defaultdict(int)

    for event in normalized_events:
        service = 'unknown'
        for token in event['tokens']:
            if token.startswith('service:'):
                service = token.split(':', 1)[1]
                break

        service_events[service] += 1
        if event['severity'] in ['ERROR', 'CRITICAL']:
            service_errors[service] += 1

    # Calculate service error rates
    service_error_rates = {}
    services_with_errors = 0

    for service, total in service_events.items():
        error_count = service_errors.get(service, 0)
        error_rate = error_count / total if total > 0 else 0
        service_error_rates[service] = error_rate

        if error_rate > 0.1:  # 10% error threshold
            services_with_errors += 1

    service_error_rate = services_with_errors / len(service_events) if service_events else 0

    # Determine context level
    if service_error_rate > 0.7:
        context_level = 'high_error_environment'
        context_description = f'High error environment: {service_error_rate:.1%} of services have significant errors'
        # Aggressive thresholds to focus on most critical issues
        recommended_thresholds = {'critical': 0.9, 'high': 0.7}
    elif service_error_rate > 0.5:
        context_level = 'medium_error_environment'
        context_description = f'Medium error environment: {service_error_rate:.1%} of services have significant errors'
        # Moderate thresholds
        recommended_thresholds = {'critical': 0.8, 'high': 0.6}
    elif service_error_rate > 0.3:
        context_level = 'low_medium_error_environment'
        context_description = f'Low-medium error environment: {service_error_rate:.1%} of services have significant errors'
        # Strong thresholds
        recommended_thresholds = {'critical': 0.7, 'high': 0.5}
    else:
        context_level = 'low_error_environment'
        context_description = f'Low error environment: {service_error_rate:.1%} of services have significant errors'
        # Sensitive to ERROR correlations
        recommended_thresholds = {'critical': 0.6, 'high': 0.4}

    # Calculate additional metrics
    time_span_hours = 0
    if normalized_events:
        timestamps = [event['ts_ms'] for event in normalized_events]
        time_span_hours = (max(timestamps) - min(timestamps)) / (1000 * 3600)

    overall_metrics = {
        'total_events': total_events,
        'error_events': error_events,
        'critical_events': critical_events,
        'overall_error_rate': overall_error_rate,
        'critical_rate': critical_rate,
        'time_span_hours': time_span_hours,
        'events_per_hour': total_events / time_span_hours if time_span_hours > 0 else 0
    }

    error_rates = {
        'service_error_rate': service_error_rate,
        'services_with_errors': services_with_errors,
        'total_services': len(service_events),
        'service_error_rates': dict(sorted(service_error_rates.items(),
                                         key=lambda x: x[1], reverse=True)[:10])  # Top 10
    }

    # Severity rationale
    severity_rationale = {
        'context_factors': [
            f'Overall error rate: {overall_error_rate:.1%}',
            f'Service error distribution: {services_with_errors}/{len(service_events)} services affected',
            f'Critical event rate: {critical_rate:.1%}',
            f'Event volume: {total_events} events over {time_span_hours:.1f} hours'
        ],
        'threshold_reasoning': {
            'high_error_environment': 'Aggressive thresholds to focus on most critical correlations',
            'medium_error_environment': 'Balanced thresholds for moderate error rates',
            'low_medium_error_environment': 'Strong thresholds for selective detection',
            'low_error_environment': 'Sensitive thresholds to catch error correlations'
        }.get(context_level, 'Standard thresholds')
    }

    severity_context = {
        'overall_metrics': overall_metrics,
        'error_rates': error_rates,
        'context_level': context_level,
        'context_description': context_description,
        'recommended_thresholds': recommended_thresholds,
        'severity_rationale': severity_rationale
    }

    logger.info(f"Severity context: {context_level} ({service_error_rate:.1%} service error rate)")
    return severity_context


def deduplicate_pmi_cooccurrences(pmi_results: List[dict]) -> List[dict]:
    """
    Deduplicate PMI co-occurrences that represent the same underlying system component.

    Groups related tokens by extracting system components (monitor names, metrics, etc.)
    and keeps only the most significant co-occurrence from each group.

    Args:
        pmi_results: List of PMI co-occurrence results

    Returns:
        Deduplicated list of PMI results
    """
    if not pmi_results:
        return pmi_results

    def extract_system_component(token: str) -> str:
        """Extract the core system component from a token."""
        # Remove prefixes to get the core component
        if token.startswith('evt_name:'):
            component = token.replace('evt_name:', '').strip('[]')
        elif token.startswith('monitor_name:'):
            component = token.replace('monitor_name:', '').strip('[]')
        elif token.startswith('metric:'):
            component = token.replace('metric:', '')
        elif token.startswith('kube_namespace:'):
            return f"namespace:{token.replace('kube_namespace:', '')}"
        elif token.startswith('pod_name:'):
            return f"pod:{token.replace('pod_name:', '')}"
        elif token.startswith('resource:'):
            return token.replace('resource:', '')
        else:
            return token

        # Further normalize the component name
        return component

    def get_component_signature(pmi: dict) -> str:
        """Create a signature for grouping related PMI results."""
        token_a = pmi.get('token_a', '')
        token_b = pmi.get('token_b', '')

        comp_a = extract_system_component(token_a)
        comp_b = extract_system_component(token_b)

        # More aggressive grouping: if both components refer to the same monitor/system
        # treat them as the same regardless of whether it's evt_name, monitor_name, or metric
        def normalize_component(comp: str) -> str:
            # Extract the core system name, ignoring prefixes
            comp_lower = comp.lower()

            # For Kubernetes monitors, extract the core monitor type
            if 'kubernetes' in comp_lower and 'deployment' in comp_lower and 'replica' in comp_lower:
                return 'k8s_deployment_replicas'
            elif 'kubernetes_state.deployment.replicas_desired' in comp_lower:
                return 'k8s_deployment_replicas'  # Same as above - metric version
            elif 'kubernetes' in comp_lower and 'pod' in comp_lower and 'crashloop' in comp_lower:
                return 'k8s_pod_crashloop'
            elif 'kubernetes' in comp_lower and 'pod' in comp_lower and 'imagepull' in comp_lower:
                return 'k8s_pod_imagepull'
            elif 'kubernetes' in comp_lower and 'statefulset' in comp_lower:
                return 'k8s_statefulset'
            elif 'kubernetes_state.statefulset.replicas_desired' in comp_lower:
                return 'k8s_statefulset'  # Metric version
            elif 'kubernetes' in comp_lower and 'failed' in comp_lower and 'pod' in comp_lower:
                return 'k8s_failed_pods'
            elif 'kubernetes_state.pod.status_phase' in comp_lower:
                return 'k8s_failed_pods'  # Metric version
            elif 'kubernetes_state.container.status_report' in comp_lower:
                return 'k8s_container_status'
            elif comp_lower.startswith('namespace:'):
                return comp  # Keep namespace distinctions
            elif comp_lower.startswith('pod:'):
                return comp  # Keep pod distinctions
            else:
                return comp

        norm_a = normalize_component(comp_a)
        norm_b = normalize_component(comp_b)

        # Special case: if both are the same normalized component, they're definitely duplicates
        if norm_a == norm_b and norm_a != comp_a and norm_a != comp_b:
            return f"duplicate_{norm_a}"

        # Special case: evt_name and monitor_name for the same thing are duplicates
        if (comp_a == comp_b and
            ((token_a.startswith('evt_name:') and token_b.startswith('monitor_name:')) or
             (token_a.startswith('monitor_name:') and token_b.startswith('evt_name:')))):
            return f"duplicate_evt_monitor_{norm_a}"

        # Sort components to ensure consistent signatures
        components = sorted([norm_a, norm_b])
        return f"{components[0]}|{components[1]}"

    # Group PMI results by their component signatures
    component_groups = defaultdict(list)
    for pmi in pmi_results:
        signature = get_component_signature(pmi)
        component_groups[signature].append(pmi)

    # Keep the best result from each group
    deduplicated = []
    duplicates_removed = 0

    for signature, group in component_groups.items():
        if len(group) == 1:
            # No duplicates, keep as is
            deduplicated.extend(group)
        else:
            # Multiple results for same component - keep the best one
            # Sort by PMI score (descending), then by support (descending)
            best = max(group, key=lambda x: (x.get('pmi_score', 0), x.get('support', 0)))

            # Add metadata about deduplication
            best['_deduplication'] = {
                'duplicates_removed': len(group) - 1,
                'original_group_size': len(group),
                'component_signature': signature
            }

            deduplicated.append(best)
            duplicates_removed += len(group) - 1

    logger.info(f"PMI deduplication: {duplicates_removed} duplicates removed, {len(deduplicated)} unique patterns kept")
    return deduplicated


def deduplicate_burst_correlations(burst_pairs: List[dict]) -> List[dict]:
    """
    Deduplicate burst correlations that involve the same system components.

    Args:
        burst_pairs: List of burst correlation results

    Returns:
        Deduplicated list of burst correlations
    """
    if not burst_pairs:
        return burst_pairs

    def get_burst_signature(burst: dict) -> str:
        """Create a signature for grouping related burst correlations."""
        series1 = burst.get('series1', '')
        series2 = burst.get('series2', '')

        # Extract core components
        def extract_core(series: str) -> str:
            if '|' in series:
                parts = series.split('|')
                if len(parts) >= 2:
                    return f"{parts[0]}_{parts[1]}"
            return series

        core1 = extract_core(series1)
        core2 = extract_core(series2)

        # Sort to ensure consistent signatures
        cores = sorted([core1, core2])
        return f"{cores[0]}|{cores[1]}"

    # Group by signature
    groups = defaultdict(list)
    for burst in burst_pairs:
        signature = get_burst_signature(burst)
        groups[signature].append(burst)

    # Keep best from each group
    deduplicated = []
    duplicates_removed = 0

    for signature, group in groups.items():
        if len(group) == 1:
            deduplicated.extend(group)
        else:
            # Keep the one with highest correlation
            best = max(group, key=lambda x: x.get('correlation', 0))
            best['_deduplication'] = {
                'duplicates_removed': len(group) - 1,
                'original_group_size': len(group),
                'component_signature': signature
            }
            deduplicated.append(best)
            duplicates_removed += len(group) - 1

    logger.info(f"Burst correlation deduplication: {duplicates_removed} duplicates removed, {len(deduplicated)} unique patterns kept")
    return deduplicated


def filter_semantic_redundant_correlations(pmi_results: List[dict]) -> List[dict]:
    """
    Filter out semantically redundant PMI correlations.

    Removes correlations between tokens that represent the same semantic information
    extracted from different parts of the alert data, such as:
    - actual_namespace:X ↔ kube_namespace:X
    - actual_pod_name:Y ↔ pod_name:Y
    - resolved_evt_name:Z ↔ monitor_name:Z (when they contain identical content)

    Args:
        pmi_results: List of PMI correlation results

    Returns:
        Filtered list with redundant correlations removed
    """
    if not pmi_results:
        return pmi_results

    def extract_semantic_value(token: str) -> tuple:
        """Extract the semantic type and value from a token."""
        if ':' not in token:
            return ('unknown', token)

        prefix, value = token.split(':', 1)

        # Map semantically equivalent prefixes to the same type
        semantic_mappings = {
            'actual_namespace': 'namespace',
            'kube_namespace': 'namespace',
            'actual_pod_name': 'pod',
            'pod_name': 'pod',
            'resolved_evt_name': 'event_name',
            'monitor_name': 'event_name',
            'evt_name': 'event_name',
            'actual_cluster': 'cluster',
            'kube_cluster_name': 'cluster'
        }

        semantic_type = semantic_mappings.get(prefix, prefix)
        return (semantic_type, value)

    def is_semantically_redundant(token_a: str, token_b: str) -> bool:
        """Check if two tokens represent the same semantic information."""
        type_a, value_a = extract_semantic_value(token_a)
        type_b, value_b = extract_semantic_value(token_b)

        # Same semantic type and same value = redundant
        if type_a == type_b and value_a == value_b:
            return True

        # Special case: resolved event names that are identical to monitor names
        if (type_a == 'event_name' and type_b == 'event_name' and
            value_a == value_b and value_a != ''):
            return True

        return False

    # Filter out redundant correlations
    filtered_results = []
    redundant_count = 0

    for pmi_result in pmi_results:
        token_a = pmi_result.get('token_a', '')
        token_b = pmi_result.get('token_b', '')

        if is_semantically_redundant(token_a, token_b):
            redundant_count += 1
            # Log the redundant correlation for debugging
            logger.debug(f"Filtered redundant correlation: {token_a} ↔ {token_b}")
        else:
            filtered_results.append(pmi_result)

    if redundant_count > 0:
        logger.info(f"Semantic filtering: {redundant_count} redundant correlations removed (e.g., actual_namespace:X ↔ kube_namespace:X)")

    return filtered_results


def extract_anomaly_timestamp(anomaly: dict, anomaly_type: str, normalized_events: List[dict]) -> str:
    """
    Extract a meaningful timestamp for an anomaly based on its type and underlying data.

    Args:
        anomaly: Anomaly dictionary containing analysis results
        anomaly_type: Type of anomaly ('burst', 'lead_lag', 'pmi', 'change_attribution')
        normalized_events: Original events for timestamp extraction

    Returns:
        ISO timestamp string representing when the anomaly pattern was most active
    """
    try:
        if anomaly_type == 'burst':
            # For burst correlations, find the timestamp of the strongest burst
            series1 = anomaly.get('series1', '')
            series2 = anomaly.get('series2', '')

            # Find events related to these series and get the most recent significant timestamp
            related_events = []
            for event in normalized_events:
                event_keys = [
                    f"kubernetes|{event['severity']}",
                    f"resource:{event['resource_id']}",
                    f"monitor:{event['monitor_key']}"
                ]
                if series1 in event_keys or series2 in event_keys:
                    related_events.append(event)

            if related_events:
                # Return timestamp of the most recent related event
                latest_event = max(related_events, key=lambda x: x['ts_ms'])
                return datetime.fromtimestamp(latest_event['ts_ms'] / 1000, timezone.utc).isoformat()

        elif anomaly_type == 'lead_lag':
            # For lead-lag, use the timestamp adjusted by the lag
            series1 = anomaly.get('series1', '')
            lag_seconds = anomaly.get('lag_seconds', 0)

            # Find the most recent event for the leading series
            related_events = []
            for event in normalized_events:
                event_keys = [
                    f"kubernetes|{event['severity']}",
                    f"resource:{event['resource_id']}",
                    f"monitor:{event['monitor_key']}"
                ]
                if series1 in event_keys:
                    related_events.append(event)

            if related_events:
                latest_event = max(related_events, key=lambda x: x['ts_ms'])
                # Adjust by lag to show when the effect would occur
                adjusted_ts = latest_event['ts_ms'] + (lag_seconds * 1000)
                return datetime.fromtimestamp(adjusted_ts / 1000, timezone.utc).isoformat()

        elif anomaly_type == 'pmi':
            # For PMI co-occurrences, find events containing the tokens
            token_a = anomaly.get('token_a', '')
            token_b = anomaly.get('token_b', '')

            related_events = []
            for event in normalized_events:
                if any(token_a in token or token_b in token for token in event['tokens']):
                    related_events.append(event)

            if related_events:
                # Use the median timestamp to represent the pattern timeframe
                related_events.sort(key=lambda x: x['ts_ms'])
                median_idx = len(related_events) // 2
                median_event = related_events[median_idx]
                return datetime.fromtimestamp(median_event['ts_ms'] / 1000, timezone.utc).isoformat()

        elif anomaly_type == 'change_attribution':
            # For change attribution, use the change timestamp plus lag
            lag_ms = anomaly.get('lag_ms', 0)
            change_series = anomaly.get('change_series', '')

            # Find the most recent change event
            related_events = []
            for event in normalized_events:
                if change_series in event['resource_id'] or change_series in event['monitor_key']:
                    related_events.append(event)

            if related_events:
                latest_change = max(related_events, key=lambda x: x['ts_ms'])
                # Add lag to show when the effect occurs
                effect_ts = latest_change['ts_ms'] + lag_ms
                return datetime.fromtimestamp(effect_ts / 1000, timezone.utc).isoformat()

    except Exception as e:
        logger.warning(f"Failed to extract timestamp for {anomaly_type} anomaly: {e}")

    # Fallback to current time if extraction fails
    return datetime.now(timezone.utc).isoformat()


def assign_anomaly_severity(anomaly: dict, anomaly_type: str, severity_context: dict) -> str:
    """
    Assign severity level to an anomaly based on its characteristics and context.

    Args:
        anomaly: Anomaly dictionary
        anomaly_type: Type of anomaly ('burst', 'lead_lag', 'pmi', 'change_attribution')
        severity_context: Severity context information

    Returns:
        Severity level string ('critical', 'high', 'medium', 'low')
    """
    recommended_thresholds = severity_context['recommended_thresholds']
    critical_threshold = recommended_thresholds['critical']
    high_threshold = recommended_thresholds['high']

    # Calculate base score based on anomaly type
    if anomaly_type == 'burst':
        base_score = anomaly.get('alignment_strength', 0) * 0.6 + abs(anomaly.get('correlation', 0)) * 0.4
        has_error = anomaly.get('has_error_series', False)
    elif anomaly_type == 'lead_lag':
        base_score = anomaly.get('confidence', 0)
        has_error = any('ERROR' in key or 'CRITICAL' in key
                       for key in [anomaly.get('series1', ''), anomaly.get('series2', '')])
    elif anomaly_type == 'pmi':
        base_score = anomaly.get('confidence', 0)
        has_error = anomaly.get('has_error_token', False)
    elif anomaly_type == 'change_attribution':
        base_score = anomaly.get('confidence', 0)
        has_error = True  # Change attribution inherently involves errors
    else:
        base_score = 0.5
        has_error = False

    # Apply error bias
    if has_error:
        base_score = min(base_score * 1.2, 1.0)

    # Assign severity
    if base_score >= critical_threshold:
        return 'critical'
    elif base_score >= high_threshold:
        return 'high'
    elif base_score >= 0.3:
        return 'medium'
    else:
        return 'low'


def create_anomaly_message(anomaly: dict, anomaly_type: str) -> str:
    """
    Create human-readable message for an anomaly.

    Args:
        anomaly: Anomaly dictionary
        anomaly_type: Type of anomaly

    Returns:
        Human-readable message string
    """
    if anomaly_type == 'burst':
        series1 = anomaly.get('series1', 'Unknown')
        series2 = anomaly.get('series2', 'Unknown')
        correlation = anomaly.get('correlation', 0)
        aligned_bursts = anomaly.get('aligned_bursts', 0)
        return f"Burst correlation between {series1} and {series2}: {aligned_bursts} aligned bursts, correlation {correlation:.3f}"

    elif anomaly_type == 'lead_lag':
        series1 = anomaly.get('series1', 'Unknown')
        series2 = anomaly.get('series2', 'Unknown')
        lag_seconds = anomaly.get('lag_seconds', 0)
        correlation = anomaly.get('correlation', 0)
        direction = anomaly.get('direction', 'unknown')

        if direction == 'series1_leads':
            return f"Lead-lag relationship: {series1} leads {series2} by {lag_seconds}s (correlation {correlation:.3f})"
        elif direction == 'series2_leads':
            return f"Lead-lag relationship: {series2} leads {series1} by {abs(lag_seconds)}s (correlation {correlation:.3f})"
        else:
            return f"Simultaneous correlation between {series1} and {series2} (correlation {correlation:.3f})"

    elif anomaly_type == 'pmi':
        token_a = anomaly.get('token_a', 'Unknown')
        token_b = anomaly.get('token_b', 'Unknown')
        pmi_score = anomaly.get('pmi_score', 0)
        support = anomaly.get('support', 0)
        return f"Strong co-occurrence: {token_a} and {token_b} (PMI {pmi_score:.2f}, support {support})"

    elif anomaly_type == 'change_attribution':
        change_series = anomaly.get('change_series', 'Unknown')
        effect_series = anomaly.get('effect_series', 'Unknown')
        lag_minutes = anomaly.get('lag_minutes', 0)
        correlation = anomaly.get('correlation_coefficient', 0)
        return f"Change attribution: {change_series} → {effect_series} after {lag_minutes:.1f}min (correlation {correlation:.3f})"

    else:
        return f"Unknown anomaly type: {anomaly_type}"


def generate_insights(normalized_events: List[dict],
                     burst_pairs: List[dict],
                     lead_lag_pairs: List[dict],
                     pmi_results: List[dict],
                     attribution_results: List[dict],
                     adaptive_thresholds: dict,
                     drift_result: dict,
                     severity_context: dict,
                     deduplication_stats: dict = None) -> dict:
    """
    Generate comprehensive insights from all analysis results.

    Compiles all analysis results into the required JSON schema format.

    Args:
        normalized_events: List of normalized events
        burst_pairs: Burst correlation results
        lead_lag_pairs: Lead-lag analysis results
        pmi_results: PMI co-occurrence results
        attribution_results: Change attribution results
        adaptive_thresholds: Adaptive threshold settings
        drift_result: Data drift detection results
        severity_context: Severity context information

    Returns:
        Complete insights dictionary matching the required schema
    """
    logger.info("Generating comprehensive insights")

    # Calculate data quality metrics
    total_logs = len(normalized_events)
    validation_errors = 0  # This would be tracked during loading

    # Calculate quality metrics
    series_count = len(set(event['resource_id'] for event in normalized_events))
    events_count = total_logs

    # Statistical significance counts
    significant_burst = sum(1 for bp in burst_pairs if bp.get('is_significant', False))
    significant_lead_lag = sum(1 for ll in lead_lag_pairs if ll.get('confidence', 0) > 0.5)
    significant_pmi = sum(1 for pmi in pmi_results if pmi.get('confidence', 0) > 0.5)
    significant_attribution = sum(1 for attr in attribution_results if attr.get('confidence', 0) > 0.5)

    total_significant = significant_burst + significant_lead_lag + significant_pmi + significant_attribution

    # Create anomalies with severity assignment
    all_anomalies = []
    anomaly_id = 1

    # Process burst correlations
    for burst in burst_pairs:
        severity = assign_anomaly_severity(burst, 'burst', severity_context)
        message = create_anomaly_message(burst, 'burst')
        timestamp = extract_anomaly_timestamp(burst, 'burst', normalized_events)

        anomaly = {
            'id': f'burst_{anomaly_id}',
            'type': 'burst_correlation',
            'severity': severity,
            'message': message,
            'details': burst,
            'timestamp': timestamp
        }
        all_anomalies.append(anomaly)
        anomaly_id += 1

    # Process lead-lag relationships
    for lead_lag in lead_lag_pairs:
        severity = assign_anomaly_severity(lead_lag, 'lead_lag', severity_context)
        message = create_anomaly_message(lead_lag, 'lead_lag')
        timestamp = extract_anomaly_timestamp(lead_lag, 'lead_lag', normalized_events)

        anomaly = {
            'id': f'leadlag_{anomaly_id}',
            'type': 'lead_lag',
            'severity': severity,
            'message': message,
            'details': lead_lag,
            'timestamp': timestamp
        }
        all_anomalies.append(anomaly)
        anomaly_id += 1

    # Process PMI co-occurrences
    for pmi in pmi_results:
        severity = assign_anomaly_severity(pmi, 'pmi', severity_context)
        message = create_anomaly_message(pmi, 'pmi')
        timestamp = extract_anomaly_timestamp(pmi, 'pmi', normalized_events)

        anomaly = {
            'id': f'pmi_{anomaly_id}',
            'type': 'pmi_correlation',
            'severity': severity,
            'message': message,
            'details': pmi,
            'timestamp': timestamp
        }
        all_anomalies.append(anomaly)
        anomaly_id += 1

    # Process change attributions
    for attribution in attribution_results:
        severity = assign_anomaly_severity(attribution, 'change_attribution', severity_context)
        message = create_anomaly_message(attribution, 'change_attribution')
        timestamp = extract_anomaly_timestamp(attribution, 'change_attribution', normalized_events)

        anomaly = {
            'id': f'change_{anomaly_id}',
            'type': 'change_attribution',
            'severity': severity,
            'message': message,
            'details': attribution,
            'timestamp': timestamp
        }
        all_anomalies.append(anomaly)
        anomaly_id += 1

    # Sort anomalies by severity and confidence
    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    all_anomalies.sort(key=lambda x: (
        severity_order.get(x['severity'], 0),
        x['details'].get('confidence', 0) if 'confidence' in x['details'] else
        x['details'].get('alignment_strength', 0) if 'alignment_strength' in x['details'] else 0
    ), reverse=True)

    # Calculate time coverage
    if normalized_events:
        timestamps = [event['ts_ms'] for event in normalized_events]
        time_coverage_hours = (max(timestamps) - min(timestamps)) / (1000 * 3600)
    else:
        time_coverage_hours = 0

    # Build the complete insights object
    insights = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'data_quality': {
            'total_logs': total_logs,
            'valid_logs': total_logs,  # All normalized events are valid
            'validation_errors': validation_errors,
            'data_characteristics': adaptive_thresholds.get('data_characteristics', {}),
            'drift_detection': drift_result,
            'quality_metrics': {
                'overall_score': min(100, max(0, int(100 * (total_logs / 1000) * (1 - validation_errors / max(total_logs, 1))))),
                'data_coverage': {
                    'total_logs': total_logs,
                    'total_services': len(set(event.get('tags_map', {}).get('service', 'unknown') for event in normalized_events)),
                    'service_diversity': len(set(event['resource_id'] for event in normalized_events)),
                    'time_coverage_hours': time_coverage_hours
                },
                'correlation_quality': {
                    'total_correlations': len(burst_pairs) + len(lead_lag_pairs),
                    'significant_correlations': significant_burst + significant_lead_lag,
                    'significance_rate': (significant_burst + significant_lead_lag) / max(len(burst_pairs) + len(lead_lag_pairs), 1),
                    'avg_correlation_strength': np.mean([abs(bp.get('correlation', 0)) for bp in burst_pairs] +
                                                      [ll.get('confidence', 0) for ll in lead_lag_pairs]) if burst_pairs or lead_lag_pairs else 0,
                    'avg_pmi_score': np.mean([pmi.get('pmi_score', 0) for pmi in pmi_results]) if pmi_results else 0,
                    'avg_lag_confidence': np.mean([ll.get('confidence', 0) for ll in lead_lag_pairs]) if lead_lag_pairs else 0
                },
                'statistical_robustness': {
                    'min_sample_size': min([bp.get('sample_size', 0) for bp in burst_pairs] +
                                         [ll.get('sample_size', 0) for ll in lead_lag_pairs] + [total_logs]) if burst_pairs or lead_lag_pairs else total_logs,
                    'avg_sample_size': np.mean([bp.get('sample_size', 0) for bp in burst_pairs] +
                                             [ll.get('sample_size', 0) for ll in lead_lag_pairs]) if burst_pairs or lead_lag_pairs else total_logs,
                    'max_sample_size': max([bp.get('sample_size', 0) for bp in burst_pairs] +
                                         [ll.get('sample_size', 0) for ll in lead_lag_pairs] + [total_logs]) if burst_pairs or lead_lag_pairs else total_logs
                },
                'component_scores': {
                    'data_quality': min(100, max(0, int(100 * (1 - validation_errors / max(total_logs, 1))))),
                    'service_diversity': min(100, int(len(set(event['resource_id'] for event in normalized_events)) * 10)),
                    'correlation_significance': min(100, int(total_significant * 20)),
                    'statistical_robustness': min(100, int(total_logs / 10))
                }
            }
        },
        'adaptive_thresholds': adaptive_thresholds,
        'severity_context': severity_context,
        'stats': {
            'series': series_count,
            'events': events_count,
            'burst_pairs_count': len(burst_pairs),
            'lead_lag_count': len(lead_lag_pairs),
            'pmi_count': len(pmi_results),
            'change_attribution_count': len(attribution_results),
            'statistically_significant': total_significant,
            'deduplication': deduplication_stats or {}
        },
        'burst_pairs': burst_pairs,
        'lead_lag': lead_lag_pairs,
        'pmi': pmi_results,
        'change_attribution': attribution_results,
        'top_anomalies': all_anomalies[:100],  # Limit to top 100 for UI
        'correlations': burst_pairs + lead_lag_pairs  # Combined for dashboard
    }

    return insights


def convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization."""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    else:
        return obj


def save_insights(insights: dict, output_path: str = 'public/vl_insights.jsonl') -> bool:
    """
    Save insights to JSON Lines file.

    Args:
        insights: Complete insights dictionary
        output_path: Path to output file

    Returns:
        True if successful, False otherwise
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Convert numpy types to native Python types
        serializable_insights = convert_numpy_types(insights)
        insights_json = json.dumps(serializable_insights, ensure_ascii=False, separators=(',', ':')) + '\n'

        # Save to main output path
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(insights_json)

        # Also save to dashboard public directory if it exists
        dashboard_path = 'dashboard/public/insights.json'
        if os.path.exists('dashboard/public'):
            os.makedirs(os.path.dirname(dashboard_path), exist_ok=True)
            with open(dashboard_path, 'w', encoding='utf-8') as f:
                f.write(insights_json)
            logger.info(f"Insights saved to {output_path} and {dashboard_path}")
        else:
            logger.info(f"Insights saved to {output_path}")

        return True

    except Exception as e:
        logger.error(f"Error saving insights to {output_path}: {e}")
        return False


def run_analysis(input_file: str = 'alerts.ndjson', output_file: str = 'public/vl_insights.jsonl') -> bool:
    """
    Run the complete anomaly detection analysis pipeline.

    Args:
        input_file: Path to input NDJSON file
        output_file: Path to output insights file

    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info("Starting Advanced Correlation & Anomaly Engine analysis")

        # Step 1: Load and normalize events
        logger.info("Step 1: Loading and normalizing events")
        normalized_events = load_logs(input_file)

        if not normalized_events:
            logger.error("No valid events loaded")
            return False

        # Step 2: Build time series
        logger.info("Step 2: Building time series")
        series_map = build_series_map(normalized_events)

        if not series_map:
            logger.error("No time series built")
            return False

        # Step 3: Calculate adaptive thresholds
        logger.info("Step 3: Calculating adaptive thresholds")
        adaptive_thresholds = calculate_adaptive_thresholds(normalized_events)

        # Step 4: Detect data drift
        logger.info("Step 4: Detecting data drift")
        drift_result = detect_data_drift(normalized_events)

        # Step 5: Classify severity context
        logger.info("Step 5: Classifying severity context")
        severity_context = classify_severity_context(normalized_events)

        # Step 6: Run anomaly detection algorithms
        logger.info("Step 6: Running anomaly detection algorithms")

        # Burst correlation detection with adaptive threshold
        if JOIN_MODE == 'resource':
            # Lower threshold for resource-level analysis to catch smaller spikes
            burst_z_threshold = adaptive_thresholds['z_score_threshold'] * 0.7  # 2.1 instead of 3.0
        else:
            burst_z_threshold = adaptive_thresholds['z_score_threshold']

        burst_pairs = detect_bursts(series_map, burst_z_threshold)

        # Lead-lag analysis
        lead_lag_pairs = cross_corr_lead_lag(series_map, adaptive_thresholds=adaptive_thresholds)

        # PMI co-occurrence analysis
        pmi_results = pmi_cooccurrence(normalized_events,
                                     min_support=PMI_MIN_SUPPORT,
                                     pmi_threshold=adaptive_thresholds['pmi_threshold'])

        # Change attribution analysis
        attribution_results = change_attribution(normalized_events)

        # Apply deduplication to reduce noise
        logger.info("Applying deduplication to reduce noise from related patterns")
        original_pmi_count = len(pmi_results)
        original_burst_count = len(burst_pairs)

        pmi_results = deduplicate_pmi_cooccurrences(pmi_results)

        # Apply semantic deduplication to remove redundant correlations
        semantic_original_count = len(pmi_results)
        pmi_results = filter_semantic_redundant_correlations(pmi_results)
        semantic_removed = semantic_original_count - len(pmi_results)
        if semantic_removed > 0:
            logger.info(f"Semantic deduplication: {semantic_removed} redundant correlations removed")

        burst_pairs = deduplicate_burst_correlations(burst_pairs)

        logger.info(f"Deduplication summary: PMI {original_pmi_count}→{len(pmi_results)}, Burst {original_burst_count}→{len(burst_pairs)}")

        # Prepare deduplication statistics
        deduplication_stats = {
            'pmi': {
                'original_count': original_pmi_count,
                'deduplicated_count': len(pmi_results),
                'duplicates_removed': original_pmi_count - len(pmi_results)
            },
            'burst_correlations': {
                'original_count': original_burst_count,
                'deduplicated_count': len(burst_pairs),
                'duplicates_removed': original_burst_count - len(burst_pairs)
            },
            'total_duplicates_removed': (original_pmi_count - len(pmi_results)) + (original_burst_count - len(burst_pairs))
        }

        # Step 7: Generate comprehensive insights
        logger.info("Step 7: Generating insights")
        insights = generate_insights(
            normalized_events=normalized_events,
            burst_pairs=burst_pairs,
            lead_lag_pairs=lead_lag_pairs,
            pmi_results=pmi_results,
            attribution_results=attribution_results,
            adaptive_thresholds=adaptive_thresholds,
            drift_result=drift_result,
            severity_context=severity_context,
            deduplication_stats=deduplication_stats
        )

        # Step 8: Save insights
        logger.info("Step 8: Saving insights")
        success = save_insights(insights, output_file)

        if success:
            # Print summary
            stats = insights['stats']
            logger.info(f"Analysis complete! Summary:")
            logger.info(f"  - Processed {stats['events']} events across {stats['series']} series")
            logger.info(f"  - Found {stats['burst_pairs_count']} burst correlations")
            logger.info(f"  - Found {stats['lead_lag_count']} lead-lag relationships")
            logger.info(f"  - Found {stats['pmi_count']} PMI co-occurrences")
            logger.info(f"  - Found {stats['change_attribution_count']} change attributions")
            logger.info(f"  - {stats['statistically_significant']} statistically significant results")
            logger.info(f"  - Context: {severity_context['context_level']}")
            logger.info(f"  - Drift: {drift_result['drift_type']}")

            # Memory cleanup
            gc.collect()

        return success

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return False


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(description='Advanced Correlation & Anomaly Engine')
    parser.add_argument('--once', action='store_true',
                       help='Run single analysis pass')
    parser.add_argument('--watch', action='store_true',
                       help='Continuous monitoring (not implemented)')
    parser.add_argument('--input', default='alerts.ndjson',
                       help='Input NDJSON file path')
    parser.add_argument('--output', default='public/vl_insights.jsonl',
                       help='Output insights file path')

    args = parser.parse_args()

    if args.watch:
        logger.warning("Watch mode not implemented, running once")

    # Run analysis
    success = run_analysis(args.input, args.output)

    if success:
        logger.info("Analysis completed successfully")
        sys.exit(0)
    else:
        logger.error("Analysis failed")
        sys.exit(1)


if __name__ == '__main__':
    main()

# UI Specification for Correlation Analysis Dashboard

## Data Structure (Using Your Actual Field Names)

### 1) Burst Correlations (spike at the same time)

**Show per correlation pair:**

**Pair:** `series1` ↔ `series2` (e.g., `resource:prod-cluster/database-main-pod` ↔ `resource:prod-cluster/message-queue-main-pod`)

**When:** Extract from `correlation_basis.alignment_window_minutes` and bucket timestamps

**Strength:**

- `aligned_bursts` (e.g., 3)
- `total_buckets` (support - total burst peaks considered)
- `confidence` (from `confidence_interval`)

**Why flagged:**

- `correlation` value (e.g., 0.653)
- `alignment_strength` (e.g., 0.1875)
- `strategy` used (e.g., "rolling_z_score")
- `correlation_basis.alignment_window_minutes` (e.g., 2.0)

**Scope:**

- Extract cluster/namespace from `series1`/`series2` strings
- Parse from `resource:prod-cluster/database-main-pod` → cluster: prod-cluster
- Parse from `monitor:15003|prod-cluster,database-main-pod,production` → cluster: prod-cluster, namespace: production

**Fields to use from your data:**

- Time: `event.attributes.attributes.timestamp` (ms) → bucket to 60s
- Identity: `series1`, `series2` (already built resource_id or monitor format)
- Context: Parse cluster/namespace from series strings

### 2) Lead-Lag (who spikes first)

**Show per correlation pair:**

**Leader → Follower:** `series1` → `series2` (based on `direction`)

**Lag:** `lag_seconds` (e.g., 120s) and `lag_buckets`

**Strength:**

- `correlation` at best lag (e.g., 0.34)
- `sample_size` (overlap_bins equivalent)
- `confidence` (0–1)

**Consistency:**

- `granger_score` (how many times the lead pattern repeated)
- `precedence_score` (statistical precedence measure)
- `correlation_basis.relationship_strength`

**Examples:**

- Use `correlation_basis.leader_series` and `correlation_basis.follower_series`
- Calculate timestamp pairs from lag_seconds

**Scope:**

- Same cluster/namespace parsing as burst correlations

**Fields to use:**

- Same per-bucket counts as burst
- Cross-corr outputs: `lag_seconds`, `correlation`, `sample_size`, `confidence`

### 3) PMI (co-occurrence)

**Show per token pair:**

**Token A ↔ Token B:** `token_a` ↔ `token_b`
(e.g., `evt_name:[Production] Message-Queue Monitor...` ↔ `resource_id:prod-cluster/message-queue-main-pod`)

**Scores:**

- `pmi_score` (log2) (e.g., 4.046)
- lift: calculate as `p_ab / (p_a * p_b)` from existing `p_a`, `p_b`, `p_ab`
- `support` (# of buckets where both appear)
- `total_buckets` (sample_size)
- `confidence` (your combined score)

**Dedup notes:**

- Show if `_deduplication.semantic` was applied
- Display `_deduplication.note` if present

**Examples:**

- Use `correlation_basis` for context examples
- Extract bucket timestamps where both tokens appeared

**Fields to use:**

- Token set per bucket from: `token_a`, `token_b` (already extracted from tags[], monitor.id, monitor.templated_name, etc.)

## UI Layout

### A. Insights Page with 3 Tabs

**Tabs:** Bursts | Lead-Lag | PMI

**Global filters (top bar):**

- Time range
- Cluster / Namespace / Env (parsed from series strings)
- Bucket size (30s / 60s)
- Significance toggle (`is_significant` field)

**Threshold sliders:**

- Burst: `correlation` ≥ slider, `aligned_bursts` ≥ slider
- Lead-lag: `correlation` ≥ slider
- PMI: `support` ≥ slider, `pmi_score` ≥ slider

### Bursts Tab

**Left panel: table of burst pairs**

- Columns: Pair, `aligned_bursts`, `confidence`, `alignment_strength`, Last seen

**Right panel (details):**

- Twin sparkline chart: counts per minute for both series; highlight aligned burst buckets
- Burst table: bucket time, correlation, sample event links
- Scope chips: cluster / namespace (parsed from series strings)
- Why selected: "X aligned spikes within Ym; correlation=Z"

### Lead-Lag Tab

**Left: table of lead-lag pairs**

- Columns: Leader → Follower, `lag_seconds`, `correlation`, `sample_size`, Last seen

**Right (details):**

- Lag overlay chart: two series, one shifted by `lag_seconds`
- Peak pairs: leader time → follower time examples
- Confidence + controls: buttons to test different lags

### PMI Tab

**Left: table of token pairs**

- Columns: Pair, `pmi_score`, `support`, Lift, `confidence`, Last seen

**Right (details):**

- Top contexts: which clusters/namespaces this pair appears in
- Example snippets: from `correlation_basis`
- Dedup badges: show `_deduplication.semantic` status

## Example Row Payloads (Using Your Actual Fields)

### Burst row

```json
{
  "type": "burst",
  "series1": "resource:prod-cluster/database-main-pod",
  "series2": "resource:prod-cluster/message-queue-main-pod",
  "aligned_bursts": 3,
  "total_buckets": 16,
  "alignment_strength": 0.1875,
  "correlation": 0.653,
  "confidence_interval": [0.065, 0.904],
  "is_significant": true,
  "strategy": "rolling_z_score",
  "correlation_basis": {
    "alignment_window_minutes": 2.0,
    "burst_intensity": 0.1875
  }
}
```

### Lead-Lag row

```json
{
  "type": "leadlag",
  "series1": "resource:prod-cluster/web-frontend-main-pod",
  "series2": "resource:prod-cluster/database-main-pod",
  "lag_buckets": 1,
  "lag_seconds": 60,
  "correlation": 0.309,
  "granger_score": 0.247,
  "precedence_score": -1.95,
  "confidence": -0.161,
  "sample_size": 111,
  "direction": "series1_leads"
}
```

### PMI row

```json
{
  "type": "pmi",
  "token_a": "evt_name:[Production] Message-Queue Monitor...",
  "token_b": "resource_id:prod-cluster/message-queue-main-pod",
  "pmi_score": 4.046,
  "support": 27,
  "total_buckets": 180,
  "confidence": 0.82,
  "p_a": 0.15,
  "p_b": 0.15,
  "p_ab": 0.15,
  "_deduplication": {
    "semantic": true,
    "note": "actual_namespace:production vs kube_namespace:production"
  }
}
```

## Micro-interactions / Polish

### Badges

- **BURST**: `is_significant` = true
- **LAG +120s**: `lag_seconds` > 0
- **PMI strong**: `pmi_score` > 3.0
- **Deduped**: `_deduplication.semantic` = true
- **Sparse series**: `total_buckets` < 10

### Empty States

Show "Why no results?" with checks:

- "Not enough buckets" (check `total_buckets`)
- "Spikes not aligned" (check `aligned_bursts`)
- "Correlation too weak" (check `correlation` vs threshold)

### Streaming Indicator

- "live" dot when events are flowing
- Use `timestamp` field to show data freshness

### Copy Buttons

- "Copy JSON" for any row's detail payload
- Use complete row data from your engine output

### Link Outs

- To monitor page (extract monitor ID from `monitor:15003|...` format)
- Use `correlation_basis` for additional context links

## Quick Visual Style Tips

### Layout

- Use 3-column layout: results table | details | timeline/sparkline
- Keep charts minimal: one line per series, highlight matched points
- Prefer chips for tokens/scope (cluster: prod-cluster, ns: production)

### Controls

- Add threshold sliders right above each table for quick tuning
- Use your actual field ranges for slider min/max values

### Manager View

- Toggle to show only top 5 signals with plain text summaries
- Format: "Database and Message-Queue spike together 3 times (correlation: 0.65)"

### Field Parsing Helpers

#### Extract Cluster/Namespace from Series Strings

```javascript
function parseScope(seriesString) {
  if (seriesString.startsWith("resource:")) {
    // resource:prod-cluster/database-main-pod
    const parts = seriesString.replace("resource:", "").split("/");
    return { cluster: parts[0], pod: parts[1] };
  } else if (seriesString.startsWith("monitor:")) {
    // monitor:15003|prod-cluster,database-main-pod,production
    const parts = seriesString.split("|")[1].split(",");
    return { cluster: parts[0], pod: parts[1], namespace: parts[2] };
  }
}
```

#### Calculate PMI Lift

```javascript
function calculateLift(p_a, p_b, p_ab) {
  return p_ab / (p_a * p_b);
}
```

#### Format Lag Display

```javascript
function formatLag(lag_seconds) {
  if (lag_seconds === 0) return "simultaneous";
  const minutes = Math.abs(lag_seconds) / 60;
  const sign = lag_seconds > 0 ? "+" : "-";
  return `${sign}${minutes}m`;
}
```

## Data Refresh Strategy

### Real-time Updates

- Poll `public/vl_insights.jsonl` every 30 seconds
- Compare `timestamp` field to detect new data
- Highlight new correlations with animation

### Caching

- Cache parsed scope information (cluster/namespace)
- Cache calculated lift values for PMI
- Invalidate on `timestamp` change

This specification uses your exact field names and data structure while providing a comprehensive UI framework for displaying the correlation analysis results.

```

```

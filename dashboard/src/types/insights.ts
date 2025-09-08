// TypeScript interfaces for the Advanced Correlation & Anomaly Engine insights

export interface DataCharacteristics {
  total_logs: number;
  error_rate: number;
  sparsity: number;
  pattern_strength: number;
  service_count: number;
  avg_logs_per_service: number;
}

export interface DriftDetection {
  drift_detected: boolean;
  drift_score: number;
  drift_type: string;
  confidence: number;
  indicators: string[];
  historical_patterns_count: number;
}

export interface DataCoverage {
  total_logs: number;
  total_services: number;
  service_diversity: number;
  time_coverage_hours: number;
}

export interface CorrelationQuality {
  total_correlations: number;
  significant_correlations: number;
  significance_rate: number;
  avg_correlation_strength: number;
  avg_pmi_score: number;
  avg_lag_confidence: number;
}

export interface StatisticalRobustness {
  min_sample_size: number;
  avg_sample_size: number;
  max_sample_size: number;
}

export interface ComponentScores {
  data_quality: number;
  service_diversity: number;
  correlation_significance: number;
  statistical_robustness: number;
}

export interface QualityMetrics {
  overall_score: number;
  data_coverage: DataCoverage;
  correlation_quality: CorrelationQuality;
  statistical_robustness: StatisticalRobustness;
  component_scores: ComponentScores;
}

export interface DataQuality {
  total_logs: number;
  valid_logs: number;
  validation_errors: number;
  data_characteristics: DataCharacteristics;
  drift_detection: DriftDetection;
  quality_metrics: QualityMetrics;
}

export interface AdaptiveThresholds {
  z_score_threshold: number;
  correlation_threshold: number;
  pmi_threshold: number;
  min_points: number;
  data_characteristics: DataCharacteristics;
}

export interface OverallMetrics {
  total_events: number;
  error_events: number;
  critical_events: number;
  overall_error_rate: number;
  critical_rate: number;
  time_span_hours: number;
  events_per_hour: number;
}

export interface ErrorRates {
  service_error_rate: number;
  services_with_errors: number;
  total_services: number;
  service_error_rates: Record<string, number>;
}

export interface SeverityRationale {
  context_factors: string[];
  threshold_reasoning: string;
}

export interface SeverityContext {
  overall_metrics: OverallMetrics;
  error_rates: ErrorRates;
  context_level: string;
  context_description: string;
  recommended_thresholds: {
    critical: number;
    high: number;
  };
  severity_rationale: SeverityRationale;
}

export interface Stats {
  series: number;
  events: number;
  burst_pairs_count: number;
  lead_lag_count: number;
  pmi_count: number;
  change_attribution_count: number;
  statistically_significant: number;
}

export interface BurstPair {
  series1: string;
  series2: string;
  aligned_bursts: number;
  total_buckets: number;
  alignment_strength: number;
  correlation: number;
  p_value: number;
  confidence_interval: [number, number];
  sample_size: number;
  is_significant: boolean;
  has_error_series: boolean;
  strategy: string;
  means: [number, number];
  stds: [number, number];
}

export interface LeadLag {
  series1: string;
  series2: string;
  lag_buckets: number;
  lag_seconds: number;
  correlation: number;
  granger_score: number;
  precedence_score: number;
  confidence: number;
  sample_size: number;
  direction: string;
}

export interface PMIResult {
  token_a: string;
  token_b: string;
  pmi_score: number;
  support: number;
  count_a: number;
  count_b: number;
  total_buckets: number;
  confidence: number;
  has_error_token: boolean;
  p_a: number;
  p_b: number;
  p_ab: number;
}

export interface ChangeAttribution {
  change_series: string;
  effect_series: string;
  correlation_coefficient: number;
  lag_minutes: number;
  lag_ms: number;
  change_count: number;
  effect_count: number;
  confidence: number;
  method: string;
}

export interface Anomaly {
  id: string;
  type: 'burst_correlation' | 'pmi_correlation' | 'lead_lag' | 'change_attribution';
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  details: any;
  timestamp: string;
}

export interface Insights {
  timestamp: string;
  data_quality: DataQuality;
  adaptive_thresholds: AdaptiveThresholds;
  severity_context: SeverityContext;
  stats: Stats;
  burst_pairs: BurstPair[];
  lead_lag: LeadLag[];
  pmi: PMIResult[];
  change_attribution: ChangeAttribution[];
  top_anomalies: Anomaly[];
  correlations: (BurstPair | LeadLag)[];
}

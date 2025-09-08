import React from 'react';
import { DataQuality, SeverityContext, AdaptiveThresholds } from '../types/insights';
import { TrendingUp, Database, Settings, CheckCircle, XCircle, BarChart3, PieChart, Activity } from 'lucide-react';

interface DriftQualityPanelProps {
  dataQuality: DataQuality;
  severityContext: SeverityContext;
  adaptiveThresholds: AdaptiveThresholds;
}

const DriftQualityPanel: React.FC<DriftQualityPanelProps> = ({ 
  dataQuality, 
  severityContext, 
  adaptiveThresholds 
}) => {
  const formatNumber = (num: number, decimals: number = 0) => {
    return new Intl.NumberFormat('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals
    }).format(num);
  };

  const formatPercentage = (num: number) => {
    return `${(num * 100).toFixed(1)}%`;
  };

  const getScoreColor = (score: number) => {
    if (score >= 0.8) return 'text-success-600';
    if (score >= 0.6) return 'text-warning-600';
    return 'text-error-600';
  };

  const getScoreBackground = (score: number) => {
    if (score >= 0.8) return 'bg-success-100 border-success-200';
    if (score >= 0.6) return 'bg-warning-100 border-warning-200';
    return 'bg-error-100 border-error-200';
  };

  const renderQualityScore = (score: number, label: string) => (
    <div className={`p-6 rounded-xl border-2 ${getScoreBackground(score)}`}>
      <div className="flex items-center justify-between">
        <div>
          <span className="text-sm font-medium text-neutral-700">{label}</span>
          <div className="mt-2">
            <div className="w-full bg-neutral-200 rounded-full h-2">
              <div 
                className={`h-2 rounded-full ${
                  score >= 0.8 ? 'bg-success-500' : 
                  score >= 0.6 ? 'bg-warning-500' : 'bg-error-500'
                }`}
                style={{ width: `${score * 100}%` }}
              ></div>
            </div>
          </div>
        </div>
        <span className={`text-2xl font-bold ${getScoreColor(score)}`}>
          {score.toFixed(2)}
        </span>
      </div>
    </div>
  );

  return (
    <div className="space-y-8">
      {/* Data Quality Overview */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-primary-500 to-secondary-500 rounded-xl flex items-center justify-center">
              <Database className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="card-title">Data Quality Overview</h2>
              <p className="card-subtitle">Comprehensive analysis of data integrity and quality metrics</p>
            </div>
          </div>
        </div>
        
        <div className="card-content">
          <div className="metrics-grid mb-8">
            <div className="metric-card">
              <div className="metric-header">
                <div className="metric-icon">
                  <Database className="w-6 h-6" />
                </div>
                <div className="text-right">
                  <div className="text-sm text-neutral-500">Total Logs</div>
                  <div className="metric-value">{formatNumber(dataQuality.total_logs)}</div>
                </div>
              </div>
            </div>
            
            <div className="metric-card">
              <div className="metric-header">
                <div className="metric-icon success">
                  <CheckCircle className="w-6 h-6" />
                </div>
                <div className="text-right">
                  <div className="text-sm text-neutral-500">Valid Logs</div>
                  <div className="metric-value">{formatNumber(dataQuality.valid_logs)}</div>
                </div>
              </div>
            </div>
            
            <div className="metric-card">
              <div className="metric-header">
                <div className="metric-icon error">
                  <XCircle className="w-6 h-6" />
                </div>
                <div className="text-right">
                  <div className="text-sm text-neutral-500">Validation Errors</div>
                  <div className="metric-value">{formatNumber(dataQuality.validation_errors)}</div>
                </div>
              </div>
            </div>
            
            <div className="metric-card">
              <div className="metric-header">
                <div className="metric-icon warning">
                  <TrendingUp className="w-6 h-6" />
                </div>
                <div className="text-right">
                  <div className="text-sm text-neutral-500">Overall Score</div>
                  <div className={`metric-value ${getScoreColor(dataQuality.quality_metrics.overall_score)}`}>
                    {dataQuality.quality_metrics.overall_score.toFixed(2)}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Quality Component Scores */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {renderQualityScore(dataQuality.quality_metrics.component_scores.data_quality, 'Data Quality')}
            {renderQualityScore(dataQuality.quality_metrics.component_scores.service_diversity, 'Service Diversity')}
            {renderQualityScore(dataQuality.quality_metrics.component_scores.correlation_significance, 'Correlation Significance')}
            {renderQualityScore(dataQuality.quality_metrics.component_scores.statistical_robustness, 'Statistical Robustness')}
          </div>
        </div>
      </div>

      {/* Drift Detection */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-secondary-500 to-accent-500 rounded-xl flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="card-title">Drift Detection</h2>
              <p className="card-subtitle">Real-time monitoring of data distribution changes</p>
            </div>
          </div>
        </div>
        
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <div className={`p-6 rounded-xl border-2 mb-6 ${
                dataQuality.drift_detection.drift_detected 
                  ? 'bg-error-50 border-error-200' 
                  : 'bg-success-50 border-success-200'
              }`}>
                <div className="flex items-center mb-4">
                  {dataQuality.drift_detection.drift_detected ? (
                    <XCircle className="w-8 h-8 text-error-600 mr-4" />
                  ) : (
                    <CheckCircle className="w-8 h-8 text-success-600 mr-4" />
                  )}
                  <div>
                    <div className="font-semibold text-xl">
                      Drift Status: {dataQuality.drift_detection.drift_detected ? 'Detected' : 'Not Detected'}
                    </div>
                    <div className="text-sm opacity-90 mt-1">
                      {dataQuality.drift_detection.drift_detected ? 'Data distribution has changed significantly' : 'Data distribution is stable'}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Drift Score:</span>
                  <span className="font-mono text-xl font-bold">{dataQuality.drift_detection.drift_score.toFixed(3)}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Drift Type:</span>
                  <span className="text-neutral-900 font-medium">{dataQuality.drift_detection.drift_type}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Confidence:</span>
                  <span className="font-mono text-xl font-bold">{dataQuality.drift_detection.confidence.toFixed(3)}</span>
                </div>
                <div className="flex justify-between items-center py-3">
                  <span className="font-medium text-neutral-700">Historical Patterns:</span>
                  <span className="text-neutral-900 font-medium">{dataQuality.drift_detection.historical_patterns_count}</span>
                </div>
              </div>
            </div>
            
            <div>
              <h3 className="font-semibold text-lg mb-4">Drift Indicators</h3>
              <div className="space-y-3">
                {dataQuality.drift_detection.indicators.map((indicator, index) => (
                  <div key={index} className="flex items-center p-4 bg-neutral-50 rounded-lg">
                    <div className="w-3 h-3 bg-primary-500 rounded-full mr-3"></div>
                    <span className="text-sm text-neutral-700">{indicator}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Data Characteristics */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-accent-500 to-primary-500 rounded-xl flex items-center justify-center">
              <BarChart3 className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="card-title">Data Characteristics</h2>
              <p className="card-subtitle">Detailed analysis of data structure and patterns</p>
            </div>
          </div>
        </div>
        
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="space-y-6">
              <h3 className="font-semibold text-lg text-neutral-900">Error Metrics</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Error Rate:</span>
                  <span className="font-mono text-lg font-bold">{formatPercentage(dataQuality.data_characteristics.error_rate)}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Service Error Rate:</span>
                  <span className="font-mono text-lg font-bold">{formatPercentage(severityContext.error_rates.service_error_rate)}</span>
                </div>
                <div className="flex justify-between items-center py-3">
                  <span className="font-medium text-neutral-700">Services with Errors:</span>
                  <span className="font-mono text-lg font-bold">{severityContext.error_rates.services_with_errors} / {severityContext.error_rates.total_services}</span>
                </div>
              </div>
            </div>
            
            <div className="space-y-6">
              <h3 className="font-semibold text-lg text-neutral-900">Data Structure</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Sparsity:</span>
                  <span className="font-mono text-lg font-bold">{formatPercentage(dataQuality.data_characteristics.sparsity)}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Pattern Strength:</span>
                  <span className="font-mono text-lg font-bold">{dataQuality.data_characteristics.pattern_strength.toFixed(3)}</span>
                </div>
                <div className="flex justify-between items-center py-3">
                  <span className="font-medium text-neutral-700">Service Count:</span>
                  <span className="font-mono text-lg font-bold">{dataQuality.data_characteristics.service_count}</span>
                </div>
              </div>
            </div>
            
            <div className="space-y-6">
              <h3 className="font-semibold text-lg text-neutral-900">Coverage</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Time Coverage:</span>
                  <span className="font-mono text-lg font-bold">{dataQuality.quality_metrics.data_coverage.time_coverage_hours.toFixed(1)}h</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Service Diversity:</span>
                  <span className="font-mono text-lg font-bold">{dataQuality.quality_metrics.data_coverage.service_diversity.toFixed(2)}</span>
                </div>
                <div className="flex justify-between items-center py-3">
                  <span className="font-medium text-neutral-700">Avg Logs/Service:</span>
                  <span className="font-mono text-lg font-bold">{dataQuality.data_characteristics.avg_logs_per_service.toFixed(1)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Adaptive Thresholds */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-neutral-600 to-neutral-800 rounded-xl flex items-center justify-center">
              <Settings className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="card-title">Adaptive Thresholds</h2>
              <p className="card-subtitle">Dynamic configuration based on data patterns</p>
            </div>
          </div>
        </div>
        
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <h3 className="font-semibold text-lg mb-6">Detection Thresholds</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Z-Score Threshold:</span>
                  <span className="font-mono text-lg font-bold">{adaptiveThresholds.z_score_threshold.toFixed(2)}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Correlation Threshold:</span>
                  <span className="font-mono text-lg font-bold">{adaptiveThresholds.correlation_threshold.toFixed(3)}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">PMI Threshold:</span>
                  <span className="font-mono text-lg font-bold">{adaptiveThresholds.pmi_threshold.toFixed(2)}</span>
                </div>
                <div className="flex justify-between items-center py-3">
                  <span className="font-medium text-neutral-700">Min Points:</span>
                  <span className="font-mono text-lg font-bold">{adaptiveThresholds.min_points}</span>
                </div>
              </div>
            </div>
            
            <div>
              <h3 className="font-semibold text-lg mb-6">Severity Thresholds</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">Critical Threshold:</span>
                  <span className="font-mono text-lg font-bold text-error-600">{severityContext.recommended_thresholds.critical.toFixed(2)}</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-neutral-100">
                  <span className="font-medium text-neutral-700">High Threshold:</span>
                  <span className="font-mono text-lg font-bold text-warning-600">{severityContext.recommended_thresholds.high.toFixed(2)}</span>
                </div>
              </div>
              
              <div className="mt-6">
                <h4 className="font-semibold text-lg mb-4">Context Factors</h4>
                <div className="space-y-2">
                  {severityContext.severity_rationale.context_factors.map((factor, index) => (
                    <div key={index} className="flex items-center p-3 bg-neutral-50 rounded-lg">
                      <div className="w-2 h-2 bg-primary-500 rounded-full mr-3"></div>
                      <span className="text-sm text-neutral-700">{factor}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Correlation Quality Metrics */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-primary-500 to-accent-500 rounded-xl flex items-center justify-center">
              <PieChart className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="card-title">Correlation Quality Metrics</h2>
              <p className="card-subtitle">Statistical significance and correlation strength analysis</p>
            </div>
          </div>
        </div>
        
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Activity className="w-8 h-8 text-primary-600" />
              </div>
              <div className="text-3xl font-bold text-primary-600 mb-2">
                {dataQuality.quality_metrics.correlation_quality.significance_rate.toFixed(1)}%
              </div>
              <div className="text-sm text-neutral-600">Significance Rate</div>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-success-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <TrendingUp className="w-8 h-8 text-success-600" />
              </div>
              <div className="text-3xl font-bold text-success-600 mb-2">
                {dataQuality.quality_metrics.correlation_quality.avg_correlation_strength.toFixed(3)}
              </div>
              <div className="text-sm text-neutral-600">Avg Correlation</div>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-secondary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <PieChart className="w-8 h-8 text-secondary-600" />
              </div>
              <div className="text-3xl font-bold text-secondary-600 mb-2">
                {dataQuality.quality_metrics.correlation_quality.avg_pmi_score.toFixed(2)}
              </div>
              <div className="text-sm text-neutral-600">Avg PMI Score</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DriftQualityPanel;
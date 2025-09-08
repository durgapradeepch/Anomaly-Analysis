import React, { useState } from "react";
import { Insights } from "../types/insights";
import {
  AlertTriangle,
  Activity,
  TrendingUp,
  Database,
  Zap,
  BarChart3,
  PieChart,
  LineChart,
  ArrowUpRight,
  ArrowDownRight,
  Minus
} from "lucide-react";
import AnomaliesTable from "./AnomaliesTable";
import CorrelationsPanel from "./CorrelationsPanel";

interface InsightsDashboardProps {
  insights: Insights | null;
  loading: boolean;
  error: string | null;
}

const InsightsDashboard: React.FC<InsightsDashboardProps> = ({
  insights,
  loading,
  error,
}) => {
  const [activeTab, setActiveTab] = useState<
    "anomalies" | "correlations"
  >("anomalies");

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-6">
        <div className="loading-spinner"></div>
        <div className="text-center">
          <h3 className="text-xl font-semibold text-neutral-900 mb-2">
            Loading Analytics
          </h3>
          <p className="text-neutral-600">
            Processing real-time data insights...
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="card-content">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-error-100 rounded-full flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-error-600" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-neutral-900">
                Connection Error
              </h3>
              <div className="text-neutral-600 mt-1">
                <p>Unable to load analytics data: {error}</p>
              </div>
              <button 
                onClick={() => window.location.reload()} 
                className="btn btn-primary mt-4"
              >
                Retry Connection
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!insights) {
    return (
      <div className="card">
        <div className="card-content text-center py-16">
          <div className="w-20 h-20 bg-neutral-100 rounded-2xl flex items-center justify-center mx-auto mb-6">
            <Database className="w-10 h-10 text-neutral-500" />
          </div>
          <h3 className="text-2xl font-bold text-neutral-900 mb-3">
            No Analytics Data
          </h3>
          <p className="text-neutral-600 mb-8 max-w-md mx-auto">
            Start the anomaly detection engine to begin generating real-time insights and correlations.
          </p>
          <div className="flex justify-center gap-4">
            <button className="btn btn-primary">
              <Zap className="w-4 h-4 mr-2" />
              Start Engine
            </button>
            <button className="btn btn-secondary">
              <Database className="w-4 h-4 mr-2" />
              View Documentation
            </button>
          </div>
        </div>
      </div>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-error-100 text-error-800 border-error-200";
      case "high":
        return "bg-warning-100 text-warning-800 border-warning-200";
      case "medium":
        return "bg-info-100 text-info-800 border-info-200";
      case "low":
        return "bg-success-100 text-success-800 border-success-200";
      default:
        return "bg-neutral-100 text-neutral-800 border-neutral-200";
    }
  };

  const formatNumber = (num: number, decimals: number = 0) => {
    return new Intl.NumberFormat("en-US", {
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals,
    }).format(num);
  };

  const getChangeIcon = (change: number) => {
    if (change > 0) return <ArrowUpRight className="w-4 h-4" />;
    if (change < 0) return <ArrowDownRight className="w-4 h-4" />;
    return <Minus className="w-4 h-4" />;
  };

  // const getChangeColor = (change: number) => {
  //   if (change > 0) return "positive";
  //   if (change < 0) return "negative";
  //   return "neutral";
  // };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header Section */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-primary-500 to-secondary-500 rounded-xl flex items-center justify-center">
                <BarChart3 className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="card-title">Analytics Dashboard</h1>
                <p className="card-subtitle">
                  Real-time correlation analysis & anomaly detection
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-sm text-neutral-500">Last Updated</div>
                <div className="font-medium text-neutral-900">
                  {new Date(insights.timestamp).toLocaleString()}
                </div>
              </div>
              <div className="status-indicator status-online">
                <div className="status-dot"></div>
                <span>Live</span>
              </div>
            </div>
          </div>

          {/* System Status Banner */}
          <div className={`mt-6 p-4 rounded-xl border-2 ${getSeverityColor(
            insights.severity_context.context_level.includes("high")
              ? "critical"
              : insights.severity_context.context_level.includes("medium")
              ? "high"
              : "medium"
          )}`}>
            <div className="flex items-center">
              <AlertTriangle className="w-6 h-6 mr-3" />
              <div>
                <div className="font-semibold text-lg">
                  System Status: {insights.severity_context.context_level.replace('_', ' ').toUpperCase()}
                </div>
                <div className="text-sm opacity-90 mt-1">
                  {insights.severity_context.context_description}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-3 gap-6">
        <div className="metric-card">
          <div className="metric-header">
            <div className="metric-icon primary">
              <Database className="w-6 h-6" />
            </div>
            <div className="text-right">
              <div className="text-sm text-neutral-500">Total Events</div>
              <div className="metric-value">{formatNumber(insights.stats.events)}</div>
            </div>
          </div>
          <div className="metric-change positive">
            {getChangeIcon(12)}
            <span>+12% from last hour</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <div className="metric-icon success">
              <Activity className="w-6 h-6" />
            </div>
            <div className="text-right">
              <div className="text-sm text-neutral-500">Time Series</div>
              <div className="metric-value">{formatNumber(insights.stats.series)}</div>
            </div>
          </div>
          <div className="metric-change neutral">
            <Minus className="w-4 h-4" />
            <span>Active monitoring</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <div className="metric-icon warning">
              <TrendingUp className="w-6 h-6" />
            </div>
            <div className="text-right">
              <div className="text-sm text-neutral-500">Significant Results</div>
              <div className="metric-value">{formatNumber(insights.stats.statistically_significant)}</div>
            </div>
          </div>
          <div className="metric-change positive">
            {getChangeIcon(8)}
            <span>+8% confidence</span>
          </div>
        </div>

      </div>

      {/* Analysis Results Overview */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Analysis Results</h2>
          <p className="card-subtitle">Real-time processing status</p>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-4 gap-3">
            <div className="group relative overflow-hidden bg-gradient-to-br from-blue-500 via-blue-600 to-indigo-600 rounded-xl border-0 p-4 hover:shadow-xl transition-all duration-300 hover:scale-105">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center backdrop-blur-sm">
                    <TrendingUp className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-white">
                      {insights.stats.burst_pairs_count}
                    </div>
                    <div className="text-xs font-medium text-blue-100">Burst Correlations</div>
                  </div>
                </div>
                <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse"></div>
              </div>
            </div>

            <div className="group relative overflow-hidden bg-gradient-to-br from-emerald-500 via-green-600 to-teal-600 rounded-xl border-0 p-4 hover:shadow-xl transition-all duration-300 hover:scale-105">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center backdrop-blur-sm">
                    <Activity className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-white">
                      {insights.stats.lead_lag_count}
                    </div>
                    <div className="text-xs font-medium text-emerald-100">Lead-Lag</div>
                  </div>
                </div>
                <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse"></div>
              </div>
            </div>

            <div className="group relative overflow-hidden bg-gradient-to-br from-purple-500 via-violet-600 to-fuchsia-600 rounded-xl border-0 p-4 hover:shadow-xl transition-all duration-300 hover:scale-105">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center backdrop-blur-sm">
                    <PieChart className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-white">
                      {insights.stats.pmi_count}
                    </div>
                    <div className="text-xs font-medium text-purple-100">PMI Co-occurrence</div>
                  </div>
                </div>
                <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse"></div>
              </div>
            </div>

            <div className="group relative overflow-hidden bg-gradient-to-br from-orange-500 via-red-500 to-pink-600 rounded-xl border-0 p-4 hover:shadow-xl transition-all duration-300 hover:scale-105">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center backdrop-blur-sm">
                    <LineChart className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-white">
                      {insights.stats.change_attribution_count}
                    </div>
                    <div className="text-xs font-medium text-orange-100">Change Attribution</div>
                  </div>
                </div>
                <div className="w-2 h-2 bg-white/60 rounded-full animate-pulse"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Analysis Tabs */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="card-title">Detailed Analysis</h2>
              <p className="card-subtitle">Explore specific analysis results</p>
            </div>
            <div className="flex space-x-2 bg-gradient-to-r from-neutral-50 to-neutral-100 rounded-xl p-2 border border-neutral-200">
              <button
                onClick={() => setActiveTab("anomalies")}
                className={`px-6 py-3 rounded-lg text-sm font-semibold transition-all duration-200 ${
                  activeTab === "anomalies"
                    ? "bg-white text-neutral-900 shadow-lg border border-neutral-200"
                    : "text-neutral-600 hover:text-neutral-900 hover:bg-white/50"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                    activeTab === "anomalies" ? "bg-error-100" : "bg-neutral-100"
                  }`}>
                    <AlertTriangle className={`w-4 h-4 ${
                      activeTab === "anomalies" ? "text-error-600" : "text-neutral-500"
                    }`} />
                  </div>
                  <div className="text-left">
                    <div>Anomalies</div>
                    <div className={`text-xs ${
                      activeTab === "anomalies" ? "text-error-600" : "text-neutral-500"
                    }`}>
                      {insights.top_anomalies.length} detected
                    </div>
                  </div>
                </div>
              </button>
              <button
                onClick={() => setActiveTab("correlations")}
                className={`px-6 py-3 rounded-lg text-sm font-semibold transition-all duration-200 ${
                  activeTab === "correlations"
                    ? "bg-white text-neutral-900 shadow-lg border border-neutral-200"
                    : "text-neutral-600 hover:text-neutral-900 hover:bg-white/50"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                    activeTab === "correlations" ? "bg-primary-100" : "bg-neutral-100"
                  }`}>
                    <TrendingUp className={`w-4 h-4 ${
                      activeTab === "correlations" ? "text-primary-600" : "text-neutral-500"
                    }`} />
                  </div>
                  <div className="text-left">
                    <div>Correlations</div>
                    <div className={`text-xs ${
                      activeTab === "correlations" ? "text-primary-600" : "text-neutral-500"
                    }`}>
                      {insights.correlations.length} relationships
                    </div>
                  </div>
                </div>
              </button>
            </div>
          </div>
        </div>

        <div className="card-content">
          {activeTab === "anomalies" && (
            <div className="animate-fade-in">
              <AnomaliesTable anomalies={insights.top_anomalies} />
            </div>
          )}
          {activeTab === "correlations" && (
            <div className="animate-fade-in">
              <CorrelationsPanel
                burstPairs={insights.burst_pairs}
                leadLag={insights.lead_lag}
                pmi={insights.pmi}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default InsightsDashboard;
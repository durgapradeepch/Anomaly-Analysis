import React, { useState } from "react";
import { Anomaly } from "../types/insights";
import {
  AlertTriangle,
  TrendingUp,
  GitBranch,
  Zap,
  ChevronDown,
  ChevronRight,
  Link2,
  ArrowRight,
  Container,
  Server,
  Database,
  Shield,
  Layers,
  Timer,
  Gauge,
  Activity,
  Target,
  Network,
  Clock,
} from "lucide-react";

interface AnomaliesTableProps {
  anomalies: Anomaly[];
}

const AnomaliesTable: React.FC<AnomaliesTableProps> = ({ anomalies }) => {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterType, setFilterType] = useState<string>("all");

  const toggleRow = (id: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRows(newExpanded);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800 border-red-200";
      case "high":
        return "bg-orange-100 text-orange-800 border-orange-200";
      case "medium":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "low":
        return "bg-blue-100 text-blue-800 border-blue-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "burst_correlation":
        return <Activity className="h-5 w-5" />;
      case "lead_lag":
        return <ArrowRight className="h-5 w-5" />;
      case "pmi_correlation":
        return <Link2 className="h-5 w-5" />;
      case "change_attribution":
        return <Target className="h-5 w-5" />;
      default:
        return <AlertTriangle className="h-5 w-5" />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case "burst_correlation":
        return "text-blue-600 bg-blue-50";
      case "lead_lag":
        return "text-green-600 bg-green-50";
      case "pmi_correlation":
        return "text-purple-600 bg-purple-50";
      case "change_attribution":
        return "text-orange-600 bg-orange-50";
      default:
        return "text-gray-600 bg-gray-50";
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case "burst_correlation":
        return "Burst Correlation";
      case "lead_lag":
        return "Lead-Lag Relationship";
      case "pmi_correlation":
        return "PMI Co-occurrence";
      case "change_attribution":
        return "Change Attribution";
      default:
        return "Unknown";
    }
  };

  const formatAnomalyMessage = (message: string) => {
    // Clean up the message for better readability
    return message
      .replace(/Strong co-occurrence:/g, "")
      .replace(/Change attribution:/g, "")
      .replace(/Lead-lag relationship:/g, "")
      .replace(/Burst correlation:/g, "")
      .replace(/\(PMI \d+\.\d+, support \d+\)/g, "")
      .replace(/\(correlation \d+\.\d+\)/g, "")
      .replace(/after \d+\.\d+min/g, "")
      .trim();
  };

  const filteredAnomalies = anomalies.filter((anomaly) => {
    const severityMatch =
      filterSeverity === "all" || anomaly.severity === filterSeverity;
    const typeMatch = filterType === "all" || anomaly.type === filterType;
    return severityMatch && typeMatch;
  });

  const renderDetails = (anomaly: Anomaly) => {
    const details = anomaly.details;

    switch (anomaly.type) {
      case "burst_correlation":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-red-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Activity className="h-5 w-5 text-red-600 mr-2" />
                  <span className="font-semibold text-red-900">
                    Correlation
                  </span>
                </div>
                <div className="text-lg font-semibold text-red-700">
                  {(details.correlation * 100)?.toFixed(1)}%
                </div>
                <div className="text-xs text-red-600">
                  Statistical correlation
                </div>
              </div>
              <div className="bg-orange-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Zap className="h-5 w-5 text-orange-600 mr-2" />
                  <span className="font-semibold text-orange-900">
                    Aligned Bursts
                  </span>
                </div>
                <div className="text-lg font-semibold text-orange-700">
                  {details.aligned_bursts} / {details.total_buckets}
                </div>
                <div className="text-xs text-orange-600">
                  Simultaneous spikes
                </div>
              </div>
            </div>
            {details.correlation_basis && (
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3 flex items-center">
                  <Target className="h-4 w-4 mr-2" />
                  Burst Analysis
                </h4>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-blue-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-blue-900">
                      Pattern
                    </div>
                    <div className="text-lg font-semibold text-blue-700 capitalize">
                      {details.correlation_basis.burst_pattern?.replace(
                        "_",
                        " "
                      )}
                    </div>
                  </div>
                  <div className="bg-green-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-green-900">
                      Trigger
                    </div>
                    <div className="text-lg font-semibold text-green-700 capitalize">
                      {details.correlation_basis.correlation_trigger?.replace(
                        "_",
                        " "
                      )}
                    </div>
                  </div>
                  <div className="bg-purple-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-purple-900">
                      Intensity
                    </div>
                    <div className="text-lg font-semibold text-purple-700">
                      {details.correlation_basis.burst_intensity?.toFixed(1)}σ
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      case "lead_lag":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-green-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Clock className="h-5 w-5 text-green-600 mr-2" />
                  <span className="font-semibold text-green-900">Lag Time</span>
                </div>
                <div className="text-lg font-semibold text-green-700">
                  {(details.lag_seconds / 60)?.toFixed(1)}min
                </div>
                <div className="text-xs text-green-600 capitalize">
                  {details.direction?.replace("_", " ")}
                </div>
              </div>
              <div className="bg-blue-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <TrendingUp className="h-5 w-5 text-blue-600 mr-2" />
                  <span className="font-semibold text-blue-900">
                    Correlation
                  </span>
                </div>
                <div className="text-lg font-semibold text-blue-700">
                  {(details.correlation * 100)?.toFixed(1)}%
                </div>
                <div className="text-xs text-blue-600">
                  Relationship strength
                </div>
              </div>
            </div>
            {details.correlation_basis && (
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3 flex items-center">
                  <ArrowRight className="h-4 w-4 mr-2" />
                  Lead-Lag Analysis
                </h4>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-orange-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-orange-900">
                      Relationship
                    </div>
                    <div className="text-lg font-semibold text-orange-700 capitalize">
                      {details.correlation_basis.relationship_type?.replace(
                        "_",
                        " "
                      )}
                    </div>
                  </div>
                  <div className="bg-purple-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-purple-900">
                      Trigger
                    </div>
                    <div className="text-lg font-semibold text-purple-700 capitalize">
                      {details.correlation_basis.correlation_trigger?.replace(
                        "_",
                        " "
                      )}
                    </div>
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-gray-900">
                      Lag Category
                    </div>
                    <div className="text-lg font-semibold text-gray-700 capitalize">
                      {details.correlation_basis.lag_category?.replace(
                        "_",
                        " "
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      case "pmi_correlation":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-purple-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Gauge className="h-5 w-5 text-purple-600 mr-2" />
                  <span className="font-semibold text-purple-900">
                    PMI Score
                  </span>
                </div>
                <div className="text-lg font-semibold text-purple-700">
                  {details.pmi_score?.toFixed(2)}
                </div>
                <div className="text-xs text-purple-600">
                  Pointwise Mutual Information
                </div>
              </div>
              <div className="bg-blue-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Database className="h-5 w-5 text-blue-600 mr-2" />
                  <span className="font-semibold text-blue-900">Support</span>
                </div>
                <div className="text-lg font-semibold text-blue-700">
                  {details.support}
                </div>
                <div className="text-sm text-blue-600">Co-occurrence count</div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-green-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Shield className="h-5 w-5 text-green-600 mr-2" />
                  <span className="font-semibold text-green-900">
                    Confidence
                  </span>
                </div>
                <div className="text-lg font-semibold text-green-700">
                  {(details.confidence * 100)?.toFixed(1)}%
                </div>
                <div className="text-xs text-green-600">
                  Statistical confidence
                </div>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Layers className="h-5 w-5 text-gray-600 mr-2" />
                  <span className="font-semibold text-gray-900">
                    Total Buckets
                  </span>
                </div>
                <div className="text-lg font-semibold text-gray-700">
                  {details.total_buckets}
                </div>
                <div className="text-xs text-gray-600">
                  Time windows analyzed
                </div>
              </div>
            </div>
            {details.token_a && details.token_b && (
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3 flex items-center">
                  <Link2 className="h-4 w-4 mr-2" />
                  Token Relationship
                </h4>
                <div className="flex items-center justify-between">
                  <div className="bg-blue-100 px-3 py-2 rounded-lg text-sm font-medium text-blue-800 max-w-xs truncate">
                    {details.token_a}
                  </div>
                  <ArrowRight className="h-5 w-5 text-gray-400 mx-4" />
                  <div className="bg-purple-100 px-3 py-2 rounded-lg text-sm font-medium text-purple-800 max-w-xs truncate">
                    {details.token_b}
                  </div>
                </div>
              </div>
            )}
            {details.correlation_basis && (
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3 flex items-center">
                  <Activity className="h-4 w-4 mr-2" />
                  Correlation Analysis
                </h4>
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-blue-50 p-3 rounded-lg">
                      <div className="text-sm font-medium text-blue-900">
                        Trigger Type
                      </div>
                      <div className="text-lg font-semibold text-blue-700 capitalize">
                        {details.correlation_basis.correlation_trigger?.replace(
                          "_",
                          " "
                        )}
                      </div>
                    </div>
                    <div className="bg-green-50 p-3 rounded-lg">
                      <div className="text-sm font-medium text-green-900">
                        Pattern
                      </div>
                      <div className="text-lg font-semibold text-green-700 capitalize">
                        {details.correlation_basis.temporal_pattern?.replace(
                          "_",
                          " "
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-orange-50 p-3 rounded-lg">
                      <div className="text-sm font-medium text-orange-900">
                        Occurrences
                      </div>
                      <div className="text-lg font-semibold text-orange-700">
                        {details.correlation_basis.co_occurrence_count}
                      </div>
                    </div>
                    <div className="bg-purple-50 p-3 rounded-lg">
                      <div className="text-sm font-medium text-purple-900">
                        Density
                      </div>
                      <div className="text-lg font-semibold text-purple-700">
                        {details.correlation_basis.co_occurrence_density_per_hour?.toFixed(
                          1
                        )}
                        /hr
                      </div>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <div className="text-sm font-medium text-gray-900">
                        Time Span
                      </div>
                      <div className="text-lg font-semibold text-gray-700">
                        {details.correlation_basis.total_time_span_hours?.toFixed(
                          1
                        )}
                        h
                      </div>
                    </div>
                  </div>
                  {details.correlation_basis.affected_namespaces?.length >
                    0 && (
                    <div className="bg-yellow-50 p-3 rounded-lg">
                      <div className="text-sm font-medium text-yellow-900 mb-2">
                        Affected Namespaces
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {details.correlation_basis.affected_namespaces.map(
                          (ns: string, idx: number) => (
                            <span
                              key={idx}
                              className="bg-yellow-200 text-yellow-800 px-2 py-1 rounded text-xs"
                            >
                              {ns}
                            </span>
                          )
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        );

      case "change_attribution":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-orange-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Timer className="h-5 w-5 text-orange-600 mr-2" />
                  <span className="font-semibold text-orange-900">
                    Lag Time
                  </span>
                </div>
                <div className="text-lg font-semibold text-orange-700">
                  {details.lag_minutes?.toFixed(1)}min
                </div>
                <div className="text-xs text-orange-600">
                  Delay between cause and effect
                </div>
              </div>
              <div className="bg-green-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Activity className="h-5 w-5 text-green-600 mr-2" />
                  <span className="font-semibold text-green-900">
                    Correlation
                  </span>
                </div>
                <div className="text-lg font-semibold text-green-700">
                  {(details.correlation_coefficient * 100)?.toFixed(1)}%
                </div>
                <div className="text-xs text-green-600">
                  Strength of relationship
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-blue-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Database className="h-5 w-5 text-blue-600 mr-2" />
                  <span className="font-semibold text-blue-900">Changes</span>
                </div>
                <div className="text-lg font-semibold text-blue-700">
                  {details.change_count}
                </div>
                <div className="text-xs text-blue-600">Triggering events</div>
              </div>
              <div className="bg-purple-50 p-3 rounded-lg">
                <div className="flex items-center mb-2">
                  <Target className="h-5 w-5 text-purple-600 mr-2" />
                  <span className="font-semibold text-purple-900">Effects</span>
                </div>
                <div className="text-lg font-semibold text-purple-700">
                  {details.effect_count}
                </div>
                <div className="text-xs text-purple-600">Resulting events</div>
              </div>
            </div>
            {details.correlation_basis && (
              <div className="bg-white border border-gray-200 rounded-lg p-4">
                <h4 className="font-semibold text-gray-900 mb-3 flex items-center">
                  <GitBranch className="h-4 w-4 mr-2" />
                  Change Attribution Analysis
                </h4>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-red-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-red-900">
                      Change Type
                    </div>
                    <div className="text-lg font-semibold text-red-700 capitalize">
                      {details.correlation_basis.change_type?.replace("_", " ")}
                    </div>
                  </div>
                  <div className="bg-yellow-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-yellow-900">
                      Effect Type
                    </div>
                    <div className="text-lg font-semibold text-yellow-700 capitalize">
                      {details.correlation_basis.effect_type?.replace("_", " ")}
                    </div>
                  </div>
                  <div className="bg-indigo-50 p-3 rounded-lg">
                    <div className="text-sm font-medium text-indigo-900">
                      Impact Ratio
                    </div>
                    <div className="text-lg font-semibold text-indigo-700">
                      {details.correlation_basis.impact_ratio?.toFixed(1)}x
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      default:
        return (
          <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto">
            {JSON.stringify(details, null, 2)}
          </pre>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Severity
          </label>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Type
          </label>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Types</option>
            <option value="burst_correlation">Burst Correlation</option>
            <option value="lead_lag">Lead-Lag</option>
            <option value="pmi_correlation">PMI Co-occurrence</option>
            <option value="change_attribution">Change Attribution</option>
          </select>
        </div>
      </div>

      {/* Professional Card Layout */}
      <div className="space-y-4">
        {filteredAnomalies.map((anomaly) => (
          <div
            key={anomaly.id}
            className="bg-white border border-gray-200 rounded-xl shadow-sm hover:shadow-md transition-shadow duration-200"
          >
            {/* Card Header */}
            <div className="p-4 border-b border-gray-100">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  {/* Type Badge */}
                  <div className="flex items-center mb-3">
                    <div
                      className={`flex items-center px-3 py-1.5 rounded-full text-sm font-medium ${getTypeColor(
                        anomaly.type
                      )}`}
                    >
                      {getTypeIcon(anomaly.type)}
                      <span className="ml-2">{getTypeLabel(anomaly.type)}</span>
                    </div>
                    <div className="ml-3">
                      <span
                        className={`inline-flex px-3 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(
                          anomaly.severity
                        )}`}
                      >
                        {anomaly.severity.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  {/* Message */}
                  <h3 className="text-sm font-medium text-gray-900 mb-2 leading-tight">
                    {formatAnomalyMessage(anomaly.message)}
                  </h3>

                  {/* Timestamp */}
                  <div className="flex items-center text-sm text-gray-500">
                    <Timer className="h-4 w-4 mr-1" />
                    {new Date(anomaly.timestamp).toLocaleString()}
                  </div>
                </div>

                {/* Expand Button */}
                <button
                  onClick={() => toggleRow(anomaly.id)}
                  className="ml-4 p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  {expandedRows.has(anomaly.id) ? (
                    <ChevronDown className="h-5 w-5" />
                  ) : (
                    <ChevronRight className="h-5 w-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Expanded Details */}
            {expandedRows.has(anomaly.id) && (
              <div className="p-4 bg-gray-50 border-t border-gray-100">
                <div className="bg-white rounded-lg p-3 border border-gray-200">
                  {renderDetails(anomaly)}
                </div>
              </div>
            )}
          </div>
        ))}

        {filteredAnomalies.length === 0 && (
          <div className="text-center py-12 bg-white rounded-xl border border-gray-200">
            <div className="text-gray-400 mb-2">
              <Database className="h-12 w-12 mx-auto" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-1">
              No anomalies found
            </h3>
            <p className="text-gray-500">
              No anomalies match the current filters.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnomaliesTable;

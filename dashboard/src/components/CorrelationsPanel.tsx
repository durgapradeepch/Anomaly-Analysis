import React, { useState } from "react";
import { BurstPair, LeadLag, PMIResult } from "../types/insights";
import { Zap, Filter, Search, Activity, PieChart } from "lucide-react";

interface CorrelationsPanelProps {
  burstPairs: BurstPair[];
  leadLag: LeadLag[];
  pmi: PMIResult[];
}

const CorrelationsPanel: React.FC<CorrelationsPanelProps> = ({
  burstPairs,
  leadLag,
  pmi,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<"burst" | "leadlag" | "pmi">(
    "burst"
  );
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Helper function to extract token types
  const getTokenTypes = (tokenA: string, tokenB: string): string[] => {
    const types = new Set<string>();

    [tokenA, tokenB].forEach((token) => {
      if (token.startsWith("metric:")) {
        types.add("Metric");
      } else if (token.startsWith("evt_name:")) {
        types.add("Event");
      } else if (token.startsWith("monitor_name:")) {
        types.add("Monitor");
      } else if (token.startsWith("kube_namespace:")) {
        types.add("Namespace");
      } else if (token.startsWith("pod_name:")) {
        types.add("Pod");
      } else if (token.startsWith("resource:")) {
        types.add("Resource");
      } else {
        types.add("Other");
      }
    });

    return Array.from(types);
  };

  // Helper function to get styling for token types
  const getTokenTypeStyle = (type: string): string => {
    switch (type) {
      case "Metric":
        return "bg-blue-100 text-blue-800";
      case "Event":
        return "bg-green-100 text-green-800";
      case "Monitor":
        return "bg-purple-100 text-purple-800";
      case "Namespace":
        return "bg-orange-100 text-orange-800";
      case "Pod":
        return "bg-pink-100 text-pink-800";
      case "Resource":
        return "bg-indigo-100 text-indigo-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  // Extract unique services and levels for filtering
  const getUniqueServices = () => {
    const services = new Set<string>();
    [...burstPairs, ...leadLag].forEach((item) => {
      if ("series1" in item && "series2" in item) {
        [item.series1, item.series2].forEach((series) => {
          const parts = series.split("|");
          if (parts.length > 0) services.add(parts[0]);
        });
      }
    });
    return Array.from(services);
  };

  const getUniqueLevels = () => {
    const levels = new Set<string>();
    [...burstPairs, ...leadLag].forEach((item) => {
      if ("series1" in item && "series2" in item) {
        [item.series1, item.series2].forEach((series) => {
          const parts = series.split("|");
          if (parts.length > 1) levels.add(parts[1]);
        });
      }
    });
    return Array.from(levels);
  };

  const filterCorrelations = <T extends BurstPair | LeadLag>(
    correlations: T[]
  ): T[] => {
    return correlations.filter((item) => {
      if (
        serviceFilter === "all" &&
        levelFilter === "all" &&
        searchQuery === ""
      )
        return true;

      const series = [item.series1, item.series2];
      const serviceMatch =
        serviceFilter === "all" ||
        series.some((s) => s.includes(serviceFilter));
      const levelMatch =
        levelFilter === "all" || series.some((s) => s.includes(levelFilter));
      const searchMatch =
        searchQuery === "" ||
        series.some((s) => s.toLowerCase().includes(searchQuery.toLowerCase()));

      return serviceMatch && levelMatch && searchMatch;
    });
  };

  const formatCorrelation = (value: number) => {
    return value.toFixed(3);
  };

  const formatPValue = (value: number) => {
    return value < 0.001 ? "<0.001" : value.toFixed(3);
  };

  const renderBurstPairs = () => {
    const filtered = filterCorrelations(burstPairs);

    return (
      <div className="space-y-4">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Series Pair
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Correlation
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  P-value
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Aligned Bursts
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Strength
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Significant
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((pair, index) => (
                <tr
                  key={index}
                  className="hover:bg-neutral-50 transition-colors"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-8 h-8 bg-primary-100 rounded-lg flex items-center justify-center">
                        <Zap className="h-4 w-4 text-primary-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-neutral-900 truncate">
                          {pair.series1}
                        </div>
                        <div className="text-xs text-neutral-500">
                          ↔ {pair.series2}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-semibold text-neutral-900">
                      {formatCorrelation(pair.correlation)}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-neutral-900">
                      {formatPValue(pair.p_value)}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-neutral-900">
                      {pair.aligned_bursts} / {pair.total_buckets}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-16 bg-neutral-200 rounded-full h-2 mr-2">
                        <div
                          className="bg-primary-600 h-2 rounded-full"
                          style={{ width: `${pair.alignment_strength * 100}%` }}
                        ></div>
                      </div>
                      <span className="text-sm text-neutral-900">
                        {pair.alignment_strength > 0
                          ? (pair.alignment_strength * 100).toFixed(2)
                          : "0.0"}
                        %
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={`badge ${
                        pair.is_significant ? "badge-success" : "badge-warning"
                      }`}
                    >
                      {pair.is_significant ? "Yes" : "No"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="text-center py-12">
            <div className="w-16 h-16 bg-neutral-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Zap className="h-8 w-8 text-neutral-400" />
            </div>
            <h3 className="text-lg font-medium text-neutral-900 mb-2">
              No Burst Correlations
            </h3>
            <p className="text-neutral-500">
              No burst correlations match the current filter criteria.
            </p>
          </div>
        )}
      </div>
    );
  };

  const renderLeadLag = () => {
    const filtered = filterCorrelations(leadLag);

    return (
      <div className="space-y-4">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Series Pair
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Direction
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Lag
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Correlation
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Granger Score
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Confidence
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item, index) => (
                <tr
                  key={index}
                  className="hover:bg-neutral-50 transition-colors"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-8 h-8 bg-success-100 rounded-lg flex items-center justify-center">
                        <Activity className="h-4 w-4 text-success-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-neutral-900 truncate">
                          {item.series1}
                        </div>
                        <div className="text-xs text-neutral-500">
                          → {item.series2}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={`badge ${
                        item.direction === "series1_leads"
                          ? "badge-primary"
                          : item.direction === "series2_leads"
                          ? "badge-success"
                          : "badge-neutral"
                      }`}
                    >
                      {item.direction.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {item.lag_seconds}s
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {formatCorrelation(item.correlation)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {item.granger_score.toFixed(3)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {item.confidence.toFixed(3)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="text-center py-12">
            <div className="w-16 h-16 bg-neutral-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Activity className="h-8 w-8 text-neutral-400" />
            </div>
            <h3 className="text-lg font-medium text-neutral-900 mb-2">
              No Lead-Lag Relationships
            </h3>
            <p className="text-neutral-500">
              No lead-lag relationships match the current filter criteria.
            </p>
          </div>
        )}
      </div>
    );
  };

  const renderPMI = () => {
    const filtered = pmi.filter(
      (item) =>
        searchQuery === "" ||
        item.token_a.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.token_b.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
      <div className="space-y-4">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Token Pair
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  PMI Score
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Support
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Confidence
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-neutral-600 uppercase tracking-wider">
                  Token Types
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 50).map((item, index) => (
                <tr
                  key={index}
                  className="hover:bg-neutral-50 transition-colors"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-8 h-8 bg-secondary-100 rounded-lg flex items-center justify-center">
                        <PieChart className="h-4 w-4 text-secondary-600" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div
                          className="text-sm font-medium text-neutral-900 truncate max-w-xs"
                          title={item.token_a}
                        >
                          {item.token_a}
                        </div>
                        <div
                          className="text-xs text-neutral-500 truncate max-w-xs"
                          title={item.token_b}
                        >
                          ↔ {item.token_b}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {item.pmi_score.toFixed(2)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {item.support}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900">
                    {item.confidence.toFixed(3)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex flex-wrap gap-1">
                      {getTokenTypes(item.token_a, item.token_b).map(
                        (type, idx) => (
                          <span
                            key={idx}
                            className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getTokenTypeStyle(
                              type
                            )}`}
                          >
                            {type}
                          </span>
                        )
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="text-center py-12">
            <div className="w-16 h-16 bg-neutral-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <PieChart className="h-8 w-8 text-neutral-400" />
            </div>
            <h3 className="text-lg font-medium text-neutral-900 mb-2">
              No PMI Co-occurrences
            </h3>
            <p className="text-neutral-500">No PMI co-occurrences found.</p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="w-5 h-5 text-neutral-600" />
              <h3 className="card-title">Filter Correlations</h3>
            </div>
            <div className="text-sm text-neutral-500">
              Showing{" "}
              {activeSubTab === "burst"
                ? burstPairs.length
                : activeSubTab === "leadlag"
                ? leadLag.length
                : pmi.length}{" "}
              results
            </div>
          </div>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                Search
              </label>
              <div>
                <input
                  type="text"
                  placeholder="Search correlations..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full px-4 py-2 border border-neutral-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                Service
              </label>
              <select
                value={serviceFilter}
                onChange={(e) => setServiceFilter(e.target.value)}
                className="w-full px-3 py-2 border border-neutral-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                <option value="all">All Services</option>
                {getUniqueServices().map((service) => (
                  <option key={service} value={service}>
                    {service}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                Level
              </label>
              <select
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
                className="w-full px-3 py-2 border border-neutral-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                <option value="all">All Levels</option>
                {getUniqueLevels().map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-tabs */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <h2 className="card-title">Correlation Analysis</h2>
            <div className="flex space-x-1 bg-neutral-100 rounded-lg p-1">
              <button
                onClick={() => setActiveSubTab("burst")}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                  activeSubTab === "burst"
                    ? "bg-white text-neutral-900 shadow-sm"
                    : "text-neutral-600 hover:text-neutral-900"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4" />
                  <span>Burst Correlations</span>
                  <span className="badge badge-primary">
                    {burstPairs.length}
                  </span>
                </div>
              </button>
              <button
                onClick={() => setActiveSubTab("leadlag")}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                  activeSubTab === "leadlag"
                    ? "bg-white text-neutral-900 shadow-sm"
                    : "text-neutral-600 hover:text-neutral-900"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4" />
                  <span>Lead-Lag</span>
                  <span className="badge badge-success">{leadLag.length}</span>
                </div>
              </button>
              <button
                onClick={() => setActiveSubTab("pmi")}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
                  activeSubTab === "pmi"
                    ? "bg-white text-neutral-900 shadow-sm"
                    : "text-neutral-600 hover:text-neutral-900"
                }`}
              >
                <div className="flex items-center gap-2">
                  <PieChart className="w-4 h-4" />
                  <span>PMI Co-occurrence</span>
                  <span className="badge badge-warning">{pmi.length}</span>
                </div>
              </button>
            </div>
          </div>
        </div>

        <div className="card-content">
          {activeSubTab === "burst" && (
            <div className="animate-fade-in">{renderBurstPairs()}</div>
          )}
          {activeSubTab === "leadlag" && (
            <div className="animate-fade-in">{renderLeadLag()}</div>
          )}
          {activeSubTab === "pmi" && (
            <div className="animate-fade-in">{renderPMI()}</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CorrelationsPanel;

import React, { useState, useEffect } from "react";
import InsightsDashboard from "./components/InsightsDashboard";
import { Insights } from "./types/insights";
import {
  BarChart3,
  AlertTriangle,
  Activity,
  Settings,
  Bell,
  Search,
  Menu,
  ChevronDown,
  ChevronLeft,
  User,
} from "lucide-react";
import "./App.css";

function App() {
  const [insights, setInsights] = useState<Insights | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>("dashboard");

  const toggleSidebarCollapse = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  useEffect(() => {
    const loadInsights = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch("/insights.json");

        if (!response.ok) {
          throw new Error(
            `Failed to load insights: ${response.status} ${response.statusText}`
          );
        }

        const text = await response.text();
        const lines = text
          .trim()
          .split("\n")
          .filter((line) => line.trim());

        if (lines.length === 0) {
          throw new Error("No insights data found");
        }

        const latestInsights = JSON.parse(lines[lines.length - 1]);
        setInsights(latestInsights);
      } catch (err) {
        console.error("Error loading insights:", err);
        setError(err instanceof Error ? err.message : "Unknown error occurred");
      } finally {
        setLoading(false);
      }
    };

    loadInsights();
  }, []);

  const navigation = [
    {
      name: "Dashboard",
      href: "#",
      icon: BarChart3,
      current: activeTab === "dashboard",
      badge: null,
    },
    {
      name: "Anomalies",
      href: "#",
      icon: AlertTriangle,
      current: activeTab === "anomalies",
      badge: insights?.top_anomalies.length || 0,
    },
    {
      name: "Correlations",
      href: "#",
      icon: Activity,
      current: activeTab === "correlations",
      badge: insights?.correlations.length || 0,
    },
    {
      name: "Settings",
      href: "#",
      icon: Settings,
      current: activeTab === "settings",
      badge: null,
    },
  ];

  return (
    <div className="app-container">
      {/* Sidebar */}
      <div
        className={`sidebar ${sidebarOpen ? "open" : ""} ${
          sidebarCollapsed ? "collapsed" : ""
        }`}
      >
        <div className="sidebar-header">
          <button className="sidebar-logo">
            <div className="sidebar-logo-icon">
              <BarChart3 className="w-6 h-6 text-white" />
            </div>
            {!sidebarCollapsed && (
              <span className="sidebar-logo-text">Analytics Pro</span>
            )}
          </button>
          <button
            className="sidebar-collapse-btn"
            onClick={toggleSidebarCollapse}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <ChevronLeft
              className={`w-4 h-4 transition-transform ${
                sidebarCollapsed ? "rotate-180" : ""
              }`}
            />
          </button>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            {!sidebarCollapsed && <div className="nav-section-title">Main</div>}
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <a
                  key={item.name}
                  href={item.href}
                  className={`nav-item ${item.current ? "active" : ""}`}
                  onClick={(e) => {
                    e.preventDefault();
                    setActiveTab(item.name.toLowerCase());
                    setSidebarOpen(false);
                  }}
                  title={sidebarCollapsed ? item.name : undefined}
                >
                  <Icon className="nav-item-icon" />
                  {!sidebarCollapsed && (
                    <span className="nav-item-text">{item.name}</span>
                  )}
                  {!sidebarCollapsed && item.badge !== null && (
                    <span className="nav-item-badge">{item.badge}</span>
                  )}
                </a>
              );
            })}
          </div>
        </nav>
      </div>

      {/* Main Content */}
      <div
        className={`main-content ${
          sidebarCollapsed ? "sidebar-collapsed" : ""
        }`}
      >
        {/* Header */}
        <header className="header">
          <div className="header-content">
            <div className="header-left">
              <button
                className="btn btn-ghost md:hidden"
                onClick={() => setSidebarOpen(!sidebarOpen)}
              >
                <Menu className="w-5 h-5" />
              </button>

              <div className="flex items-center gap-4">
                <h1 className="text-xl font-bold text-neutral-900">
                  {navigation.find((nav) => nav.current)?.name || "Dashboard"}
                </h1>
                <div className="status-indicator status-online">
                  <div className="status-dot"></div>
                  <span>Live</span>
                </div>
              </div>
            </div>

            <div className="header-right">
              <div className="flex items-center gap-4">
                {/* Search */}
                <div className="hidden md:block">
                  <input
                    type="text"
                    placeholder="Search analytics..."
                    className="px-4 py-2 border border-neutral-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  />
                </div>

                {/* Notifications */}
                <button className="btn btn-ghost relative">
                  <Bell className="w-5 h-5" />
                  {insights?.top_anomalies &&
                    insights.top_anomalies.length > 0 && (
                      <span className="absolute -top-1 -right-1 w-5 h-5 bg-error-500 text-white text-xs rounded-full flex items-center justify-center">
                        {insights.top_anomalies.length}
                      </span>
                    )}
                </button>

                {/* User Menu */}
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-primary-100 rounded-full flex items-center justify-center">
                    <User className="w-4 h-4 text-primary-600" />
                  </div>
                  <div className="hidden md:block">
                    <div className="text-sm font-medium text-neutral-900">
                      Admin User
                    </div>
                    <div className="text-xs text-neutral-500">
                      System Administrator
                    </div>
                  </div>
                  <ChevronDown className="w-4 h-4 text-neutral-400" />
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="container py-8">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-96 space-y-6">
              <div className="loading-spinner"></div>
              <div className="text-center">
                <h3 className="text-lg font-semibold text-neutral-900 mb-2">
                  Loading Analytics
                </h3>
                <p className="text-neutral-600">
                  Processing real-time data insights...
                </p>
              </div>
            </div>
          ) : error ? (
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
                    <p className="text-neutral-600 mt-1">
                      Unable to load analytics data: {error}
                    </p>
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
          ) : !insights ? (
            <div className="card">
              <div className="card-content text-center py-16">
                <div className="w-20 h-20 bg-neutral-100 rounded-2xl flex items-center justify-center mx-auto mb-6">
                  <BarChart3 className="w-10 h-10 text-neutral-500" />
                </div>
                <h3 className="text-2xl font-bold text-neutral-900 mb-3">
                  No Analytics Data
                </h3>
                <p className="text-neutral-600 mb-8 max-w-md mx-auto">
                  Start the anomaly detection engine to begin generating
                  real-time insights and correlations.
                </p>
                <div className="flex justify-center gap-4">
                  <button className="btn btn-primary">
                    <Activity className="w-4 h-4 mr-2" />
                    Start Engine
                  </button>
                  <button className="btn btn-secondary">
                    <Settings className="w-4 h-4 mr-2" />
                    View Settings
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <InsightsDashboard
              insights={insights}
              loading={loading}
              error={error}
            />
          )}
        </main>
      </div>

      {/* Mobile Sidebar Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-40 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
}

export default App;

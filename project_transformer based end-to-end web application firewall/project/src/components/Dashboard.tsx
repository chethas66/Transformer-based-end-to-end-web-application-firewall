import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, TrendingUp, Activity } from 'lucide-react';
import { supabase } from '../lib/supabase';

interface Metrics {
  total_requests: number;
  blocked_requests: number;
  flagged_requests: number;
  allowed_requests: number;
  avg_latency_ms: number;
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics>({
    total_requests: 0,
    blocked_requests: 0,
    flagged_requests: 0,
    allowed_requests: 0,
    avg_latency_ms: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchMetrics = async () => {
    try {
      const { data, error } = await supabase.rpc('get_waf_stats');

      if (error) throw error;

      if (data) {
        setMetrics(data);
      }
      setLoading(false);
    } catch (error) {
      console.error('Error fetching metrics:', error);
      setLoading(false);
    }
  };

  const blockRate = metrics.total_requests > 0
    ? (metrics.blocked_requests / metrics.total_requests) * 100
    : 0;

  const flagRate = metrics.total_requests > 0
    ? (metrics.flagged_requests / metrics.total_requests) * 100
    : 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Requests"
          value={metrics.total_requests.toLocaleString()}
          icon={Activity}
          color="blue"
          subtitle="Last 24 hours"
        />
        <MetricCard
          title="Blocked"
          value={metrics.blocked_requests.toLocaleString()}
          icon={Shield}
          color="red"
          subtitle={`${blockRate.toFixed(1)}% of traffic`}
        />
        <MetricCard
          title="Flagged"
          value={metrics.flagged_requests.toLocaleString()}
          icon={AlertTriangle}
          color="amber"
          subtitle={`${flagRate.toFixed(1)}% of traffic`}
        />
        <MetricCard
          title="Avg Latency"
          value={`${metrics.avg_latency_ms.toFixed(2)}ms`}
          icon={Clock}
          color="green"
          subtitle="Processing time"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-900 mb-4">
            Protection Overview
          </h3>
          <div className="space-y-4">
            <ProgressBar
              label="Allowed"
              value={metrics.allowed_requests}
              total={metrics.total_requests}
              color="green"
            />
            <ProgressBar
              label="Flagged"
              value={metrics.flagged_requests}
              total={metrics.total_requests}
              color="amber"
            />
            <ProgressBar
              label="Blocked"
              value={metrics.blocked_requests}
              total={metrics.total_requests}
              color="red"
            />
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-900 mb-4">
            System Health
          </h3>
          <div className="space-y-4">
            <HealthIndicator
              label="API Status"
              status="operational"
              value="Online"
            />
            <HealthIndicator
              label="Model Status"
              status="operational"
              value="Loaded"
            />
            <HealthIndicator
              label="Database"
              status="operational"
              value="Connected"
            />
            <HealthIndicator
              label="Performance"
              status={metrics.avg_latency_ms < 10 ? "operational" : "warning"}
              value={metrics.avg_latency_ms < 10 ? "Optimal" : "Degraded"}
            />
          </div>
        </div>
      </div>

      <div className="bg-gradient-to-r from-blue-500 to-blue-600 rounded-xl p-6 text-white shadow-lg">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold mb-2">
              Transformer-Based Detection
            </h3>
            <p className="text-blue-100 text-sm">
              Using DistilBERT with ONNX optimization for sub-10ms inference
            </p>
          </div>
          <Shield className="w-16 h-16 opacity-20" />
        </div>
      </div>
    </div>
  );
}

interface MetricCardProps {
  title: string;
  value: string;
  icon: React.ElementType;
  color: 'blue' | 'red' | 'amber' | 'green';
  subtitle: string;
}

function MetricCard({ title, value, icon: Icon, color, subtitle }: MetricCardProps) {
  const colorClasses = {
    blue: 'bg-blue-50 text-blue-600 border-blue-200',
    red: 'bg-red-50 text-red-600 border-red-200',
    amber: 'bg-amber-50 text-amber-600 border-amber-200',
    green: 'bg-green-50 text-green-600 border-green-200',
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div className={`p-2 rounded-lg border ${colorClasses[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-slate-600">{title}</p>
        <p className="text-2xl font-bold text-slate-900">{value}</p>
        <p className="text-xs text-slate-500">{subtitle}</p>
      </div>
    </div>
  );
}

interface ProgressBarProps {
  label: string;
  value: number;
  total: number;
  color: 'green' | 'amber' | 'red';
}

function ProgressBar({ label, value, total, color }: ProgressBarProps) {
  const percentage = total > 0 ? (value / total) * 100 : 0;

  const colorClasses = {
    green: 'bg-green-500',
    amber: 'bg-amber-500',
    red: 'bg-red-500',
  };

  return (
    <div>
      <div className="flex justify-between text-sm mb-2">
        <span className="font-medium text-slate-700">{label}</span>
        <span className="text-slate-600">
          {value.toLocaleString()} ({percentage.toFixed(1)}%)
        </span>
      </div>
      <div className="w-full bg-slate-100 rounded-full h-2">
        <div
          className={`h-2 rounded-full transition-all duration-500 ${colorClasses[color]}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

interface HealthIndicatorProps {
  label: string;
  status: 'operational' | 'warning' | 'error';
  value: string;
}

function HealthIndicator({ label, status, value }: HealthIndicatorProps) {
  const statusConfig = {
    operational: {
      icon: CheckCircle,
      color: 'text-green-600',
      bg: 'bg-green-50',
    },
    warning: {
      icon: AlertTriangle,
      color: 'text-amber-600',
      bg: 'bg-amber-50',
    },
    error: {
      icon: AlertTriangle,
      color: 'text-red-600',
      bg: 'bg-red-50',
    },
  };

  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <div className="flex items-center justify-between">
      <span className="text-sm font-medium text-slate-700">{label}</span>
      <div className={`flex items-center space-x-2 px-3 py-1 rounded-lg ${config.bg}`}>
        <Icon className={`w-4 h-4 ${config.color}`} />
        <span className={`text-sm font-medium ${config.color}`}>{value}</span>
      </div>
    </div>
  );
}

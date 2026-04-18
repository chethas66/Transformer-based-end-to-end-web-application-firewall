import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, ExternalLink } from 'lucide-react';
import { supabase } from '../lib/supabase';

interface WAFRequest {
  id: string;
  timestamp: string;
  method: string;
  path: string;
  source_ip: string;
  action_taken: string;
  prediction: string;
  transformer_score: number;
  fast_path_blocked: boolean;
  fast_path_rule: string;
  latency_ms: number;
}

export default function RequestsTable() {
  const [requests, setRequests] = useState<WAFRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'blocked' | 'flagged' | 'allowed'>('all');

  useEffect(() => {
    fetchRequests();
    const interval = setInterval(fetchRequests, 10000);
    return () => clearInterval(interval);
  }, [filter]);

  const fetchRequests = async () => {
    try {
      let query = supabase
        .from('waf_requests')
        .select('*')
        .order('timestamp', { ascending: false })
        .limit(50);

      if (filter !== 'all') {
        query = query.eq('action_taken', filter);
      }

      const { data, error } = await query;

      if (error) throw error;

      if (data) {
        setRequests(data);
      }
      setLoading(false);
    } catch (error) {
      console.error('Error fetching requests:', error);
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-slate-900">Recent Requests</h2>
        <div className="flex space-x-2">
          <FilterButton
            active={filter === 'all'}
            onClick={() => setFilter('all')}
            label="All"
          />
          <FilterButton
            active={filter === 'blocked'}
            onClick={() => setFilter('blocked')}
            label="Blocked"
          />
          <FilterButton
            active={filter === 'flagged'}
            onClick={() => setFilter('flagged')}
            label="Flagged"
          />
          <FilterButton
            active={filter === 'allowed'}
            onClick={() => setFilter('allowed')}
            label="Allowed"
          />
        </div>
      </div>

      {loading ? (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-slate-600">Loading requests...</p>
        </div>
      ) : requests.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm">
          <Shield className="w-12 h-12 text-slate-300 mx-auto mb-4" />
          <p className="text-slate-600">No requests found</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Method
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Path
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Source IP
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Action
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Detection
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-600 uppercase tracking-wider">
                    Latency
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-200">
                {requests.map((request) => (
                  <tr key={request.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600">
                      {new Date(request.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="px-2 py-1 text-xs font-medium bg-slate-100 text-slate-700 rounded">
                        {request.method}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-900 max-w-xs truncate">
                      {request.path}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 font-mono">
                      {request.source_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <ActionBadge action={request.action_taken} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {request.fast_path_blocked ? (
                        <div className="flex items-center space-x-2">
                          <Shield className="w-4 h-4 text-red-600" />
                          <span className="text-slate-700">Fast-path</span>
                        </div>
                      ) : request.prediction === 'malicious' ? (
                        <div className="flex items-center space-x-2">
                          <AlertTriangle className="w-4 h-4 text-amber-600" />
                          <span className="text-slate-700">
                            ML ({(request.transformer_score * 100).toFixed(0)}%)
                          </span>
                        </div>
                      ) : (
                        <div className="flex items-center space-x-2">
                          <CheckCircle className="w-4 h-4 text-green-600" />
                          <span className="text-slate-700">Clean</span>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600">
                      {request.latency_ms?.toFixed(2)}ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

interface FilterButtonProps {
  active: boolean;
  onClick: () => void;
  label: string;
}

function FilterButton({ active, onClick, label }: FilterButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
        active
          ? 'bg-blue-600 text-white'
          : 'bg-white text-slate-700 border border-slate-200 hover:bg-slate-50'
      }`}
    >
      {label}
    </button>
  );
}

interface ActionBadgeProps {
  action: string;
}

function ActionBadge({ action }: ActionBadgeProps) {
  const config = {
    allow: {
      color: 'bg-green-50 text-green-700 border-green-200',
      label: 'Allowed',
    },
    flag: {
      color: 'bg-amber-50 text-amber-700 border-amber-200',
      label: 'Flagged',
    },
    block: {
      color: 'bg-red-50 text-red-700 border-red-200',
      label: 'Blocked',
    },
  };

  const actionConfig = config[action as keyof typeof config] || config.allow;

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border ${actionConfig.color}`}>
      {actionConfig.label}
    </span>
  );
}

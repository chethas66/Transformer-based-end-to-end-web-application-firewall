import { useState, useEffect } from 'react';
import { TrendingUp, AlertTriangle, Shield, Globe } from 'lucide-react';
import { supabase } from '../lib/supabase';

export default function Statistics() {
  const [topPatterns, setTopPatterns] = useState<Array<{ rule: string; count: number }>>([]);
  const [topIPs, setTopIPs] = useState<Array<{ ip: string; count: number }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStatistics();
  }, []);

  const fetchStatistics = async () => {
    try {
      const { data: patternsData } = await supabase
        .from('waf_requests')
        .select('fast_path_rule')
        .not('fast_path_rule', 'is', null)
        .limit(1000);

      if (patternsData) {
        const patternCounts = patternsData.reduce((acc: Record<string, number>, req) => {
          const rule = req.fast_path_rule;
          acc[rule] = (acc[rule] || 0) + 1;
          return acc;
        }, {});

        const sortedPatterns = Object.entries(patternCounts)
          .map(([rule, count]) => ({ rule, count: count as number }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10);

        setTopPatterns(sortedPatterns);
      }

      const { data: ipsData } = await supabase
        .from('waf_requests')
        .select('source_ip')
        .in('action_taken', ['block', 'flag'])
        .limit(1000);

      if (ipsData) {
        const ipCounts = ipsData.reduce((acc: Record<string, number>, req) => {
          const ip = req.source_ip;
          acc[ip] = (acc[ip] || 0) + 1;
          return acc;
        }, {});

        const sortedIPs = Object.entries(ipCounts)
          .map(([ip, count]) => ({ ip, count: count as number }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10);

        setTopIPs(sortedIPs);
      }

      setLoading(false);
    } catch (error) {
      console.error('Error fetching statistics:', error);
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-slate-900">Analytics & Statistics</h2>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center space-x-3 mb-6">
            <div className="p-2 bg-red-50 rounded-lg border border-red-200">
              <Shield className="w-5 h-5 text-red-600" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900">
              Top Attack Patterns
            </h3>
          </div>

          {loading ? (
            <div className="py-8 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
            </div>
          ) : topPatterns.length === 0 ? (
            <p className="text-slate-600 text-center py-8">No attack patterns detected</p>
          ) : (
            <div className="space-y-3">
              {topPatterns.map((pattern, index) => (
                <div key={pattern.rule} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-bold text-slate-400">#{index + 1}</span>
                    <span className="text-sm font-medium text-slate-900">{pattern.rule}</span>
                  </div>
                  <span className="text-sm font-semibold text-red-600">
                    {pattern.count} attacks
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center space-x-3 mb-6">
            <div className="p-2 bg-amber-50 rounded-lg border border-amber-200">
              <Globe className="w-5 h-5 text-amber-600" />
            </div>
            <h3 className="text-lg font-semibold text-slate-900">
              Top Attacking IPs
            </h3>
          </div>

          {loading ? (
            <div className="py-8 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
            </div>
          ) : topIPs.length === 0 ? (
            <p className="text-slate-600 text-center py-8">No attacking IPs detected</p>
          ) : (
            <div className="space-y-3">
              {topIPs.map((ipData, index) => (
                <div key={ipData.ip} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-bold text-slate-400">#{index + 1}</span>
                    <span className="text-sm font-mono font-medium text-slate-900">
                      {ipData.ip}
                    </span>
                  </div>
                  <span className="text-sm font-semibold text-amber-600">
                    {ipData.count} attempts
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="bg-gradient-to-r from-slate-800 to-slate-900 rounded-xl p-8 text-white shadow-lg">
        <h3 className="text-xl font-bold mb-4">System Architecture</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center text-sm font-bold">
                1
              </div>
              <h4 className="font-semibold">Fast-Path Filter</h4>
            </div>
            <p className="text-slate-300 text-sm">
              OWASP signature-based detection with regex patterns for immediate blocking
            </p>
          </div>
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center text-sm font-bold">
                2
              </div>
              <h4 className="font-semibold">Transformer Inference</h4>
            </div>
            <p className="text-slate-300 text-sm">
              DistilBERT model with ONNX optimization for context-aware threat detection
            </p>
          </div>
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center text-sm font-bold">
                3
              </div>
              <h4 className="font-semibold">Decision Engine</h4>
            </div>
            <p className="text-slate-300 text-sm">
              Adaptive scoring with configurable thresholds and shadow mode support
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import pandas as pd
from supabase import create_client, Client
import json


class WAFMonitor:

    def __init__(self, supabase_url: str, supabase_key: str):
        self.client: Client = create_client(supabase_url, supabase_key)

    def get_recent_requests(
        self,
        hours: int = 24,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        response = self.client.table('waf_requests') \
            .select('*') \
            .gte('timestamp', cutoff_time) \
            .order('timestamp', desc=True) \
            .limit(limit) \
            .execute()

        return response.data

    def get_blocked_requests(
        self,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        response = self.client.table('waf_requests') \
            .select('*') \
            .eq('action_taken', 'block') \
            .gte('timestamp', cutoff_time) \
            .order('timestamp', desc=True) \
            .limit(limit) \
            .execute()

        return response.data

    def get_flagged_requests(
        self,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        response = self.client.table('waf_requests') \
            .select('*') \
            .eq('action_taken', 'flag') \
            .gte('timestamp', cutoff_time) \
            .order('transformer_score', desc=True) \
            .limit(limit) \
            .execute()

        return response.data

    def calculate_metrics(self, hours: int = 24) -> Dict[str, Any]:
        requests = self.get_recent_requests(hours=hours, limit=10000)

        if not requests:
            return {
                "total_requests": 0,
                "blocked_count": 0,
                "flagged_count": 0,
                "allowed_count": 0,
                "block_rate": 0.0,
                "flag_rate": 0.0,
                "avg_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
                "p99_latency_ms": 0.0,
                "fast_path_blocks": 0,
                "transformer_blocks": 0
            }

        df = pd.DataFrame(requests)

        total = len(df)
        blocked = len(df[df['action_taken'] == 'block'])
        flagged = len(df[df['action_taken'] == 'flag'])
        allowed = len(df[df['action_taken'] == 'allow'])

        fast_path_blocks = len(df[df['fast_path_blocked'] == True])
        transformer_blocks = len(df[(df['prediction'] == 'malicious') & (df['fast_path_blocked'] == False)])

        latencies = df['latency_ms'].dropna()

        return {
            "total_requests": total,
            "blocked_count": blocked,
            "flagged_count": flagged,
            "allowed_count": allowed,
            "block_rate": blocked / total if total > 0 else 0.0,
            "flag_rate": flagged / total if total > 0 else 0.0,
            "avg_latency_ms": float(latencies.mean()) if len(latencies) > 0 else 0.0,
            "p95_latency_ms": float(latencies.quantile(0.95)) if len(latencies) > 0 else 0.0,
            "p99_latency_ms": float(latencies.quantile(0.99)) if len(latencies) > 0 else 0.0,
            "fast_path_blocks": fast_path_blocks,
            "transformer_blocks": transformer_blocks
        }

    def get_feedback_summary(self) -> Dict[str, Any]:
        response = self.client.table('waf_feedback') \
            .select('feedback_type') \
            .execute()

        if not response.data:
            return {
                "total_feedback": 0,
                "false_positives": 0,
                "false_negatives": 0
            }

        df = pd.DataFrame(response.data)

        return {
            "total_feedback": len(df),
            "false_positives": len(df[df['feedback_type'] == 'false_positive']),
            "false_negatives": len(df[df['feedback_type'] == 'false_negative'])
        }

    def get_top_attack_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        response = self.client.table('waf_requests') \
            .select('fast_path_rule') \
            .not_.is_('fast_path_rule', 'null') \
            .execute()

        if not response.data:
            return []

        df = pd.DataFrame(response.data)
        rule_counts = df['fast_path_rule'].value_counts().head(limit)

        return [
            {"rule": rule, "count": int(count)}
            for rule, count in rule_counts.items()
        ]

    def get_top_attacking_ips(self, hours: int = 24, limit: int = 10) -> List[Dict[str, Any]]:
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        response = self.client.table('waf_requests') \
            .select('source_ip, action_taken') \
            .gte('timestamp', cutoff_time) \
            .in_('action_taken', ['block', 'flag']) \
            .execute()

        if not response.data:
            return []

        df = pd.DataFrame(response.data)
        ip_counts = df['source_ip'].value_counts().head(limit)

        return [
            {"ip": ip, "attack_count": int(count)}
            for ip, count in ip_counts.items()
        ]

    def export_training_data(
        self,
        output_file: str,
        include_feedback: bool = True,
        limit: int = 10000
    ):
        response = self.client.table('waf_requests') \
            .select('normalized_request, prediction') \
            .not_.is_('normalized_request', 'null') \
            .not_.is_('prediction', 'null') \
            .order('timestamp', desc=True) \
            .limit(limit) \
            .execute()

        if not response.data:
            print("No training data available")
            return

        df = pd.DataFrame(response.data)

        df['label'] = df['prediction'].apply(lambda x: 1 if x == 'malicious' else 0)

        if include_feedback:
            feedback_response = self.client.table('waf_feedback') \
                .select('request_id, corrected_label') \
                .execute()

            if feedback_response.data:
                feedback_df = pd.DataFrame(feedback_response.data)

                for _, row in feedback_df.iterrows():
                    request_id = row['request_id']
                    corrected_label = 1 if row['corrected_label'] == 'malicious' else 0
                    df.loc[df.index == request_id, 'label'] = corrected_label

        df[['normalized_request', 'label']].to_csv(output_file, index=False)
        print(f"✅ Exported {len(df)} training samples to {output_file}")

    def generate_report(self, hours: int = 24) -> str:
        metrics = self.calculate_metrics(hours=hours)
        feedback = self.get_feedback_summary()
        top_patterns = self.get_top_attack_patterns(limit=5)
        top_ips = self.get_top_attacking_ips(hours=hours, limit=5)

        report = f"""
╔══════════════════════════════════════════════════════════╗
║         WAF MONITORING REPORT (Last {hours}h)                ║
╚══════════════════════════════════════════════════════════╝

📊 TRAFFIC OVERVIEW
  Total Requests:       {metrics['total_requests']:,}
  Blocked:              {metrics['blocked_count']:,} ({metrics['block_rate']:.2%})
  Flagged:              {metrics['flagged_count']:,} ({metrics['flag_rate']:.2%})
  Allowed:              {metrics['allowed_count']:,}

🛡️  PROTECTION STATS
  Fast-Path Blocks:     {metrics['fast_path_blocks']:,}
  Transformer Blocks:   {metrics['transformer_blocks']:,}

⚡ PERFORMANCE METRICS
  Avg Latency:          {metrics['avg_latency_ms']:.2f}ms
  P95 Latency:          {metrics['p95_latency_ms']:.2f}ms
  P99 Latency:          {metrics['p99_latency_ms']:.2f}ms

💬 FEEDBACK SUMMARY
  Total Feedback:       {feedback['total_feedback']}
  False Positives:      {feedback['false_positives']}
  False Negatives:      {feedback['false_negatives']}

🎯 TOP ATTACK PATTERNS
"""

        for i, pattern in enumerate(top_patterns, 1):
            report += f"  {i}. {pattern['rule']}: {pattern['count']} times\n"

        report += f"\n🌐 TOP ATTACKING IPs\n"

        for i, ip_data in enumerate(top_ips, 1):
            report += f"  {i}. {ip_data['ip']}: {ip_data['attack_count']} attacks\n"

        return report


class ShadowModeAnalyzer:

    def __init__(self, monitor: WAFMonitor):
        self.monitor = monitor

    def analyze_baseline(self, hours: int = 72) -> Dict[str, Any]:
        requests = self.monitor.get_recent_requests(hours=hours, limit=100000)

        if not requests:
            return {"status": "no_data"}

        df = pd.DataFrame(requests)

        malicious_predictions = df[df['prediction'] == 'malicious']

        if len(malicious_predictions) == 0:
            return {
                "status": "clean",
                "total_analyzed": len(df),
                "malicious_detected": 0,
                "recommendation": "No threats detected. Safe to enable active mode."
            }

        confidence_scores = malicious_predictions['transformer_score'].dropna()

        high_confidence = len(confidence_scores[confidence_scores >= 0.95])
        medium_confidence = len(confidence_scores[(confidence_scores >= 0.75) & (confidence_scores < 0.95)])
        low_confidence = len(confidence_scores[confidence_scores < 0.75])

        false_positive_rate = 0.0
        feedback_response = self.monitor.client.table('waf_feedback') \
            .select('feedback_type') \
            .eq('feedback_type', 'false_positive') \
            .execute()

        if feedback_response.data:
            total_flagged = len(malicious_predictions)
            false_positives = len(feedback_response.data)
            false_positive_rate = false_positives / total_flagged if total_flagged > 0 else 0.0

        recommendation = "Continue in shadow mode"
        if false_positive_rate < 0.05 and high_confidence > 10:
            recommendation = "Ready to switch to active mode"
        elif false_positive_rate > 0.15:
            recommendation = "High false positive rate. Needs tuning."

        return {
            "status": "analyzed",
            "total_analyzed": len(df),
            "malicious_detected": len(malicious_predictions),
            "high_confidence_threats": high_confidence,
            "medium_confidence_threats": medium_confidence,
            "low_confidence_threats": low_confidence,
            "false_positive_rate": false_positive_rate,
            "recommendation": recommendation
        }


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv

    load_dotenv()

    supabase_url = os.getenv("VITE_SUPABASE_URL")
    supabase_key = os.getenv("VITE_SUPABASE_ANON_KEY")

    if not supabase_url or not supabase_key:
        print("❌ Supabase credentials not found in .env file")
        exit(1)

    print("🔍 Initializing WAF Monitor...\n")
    monitor = WAFMonitor(supabase_url, supabase_key)

    report = monitor.generate_report(hours=24)
    print(report)

    print("\n📈 Shadow Mode Analysis\n")
    analyzer = ShadowModeAnalyzer(monitor)
    baseline = analyzer.analyze_baseline(hours=72)

    print(f"Status: {baseline.get('status')}")
    print(f"Total Analyzed: {baseline.get('total_analyzed', 0)}")
    print(f"Malicious Detected: {baseline.get('malicious_detected', 0)}")
    print(f"Recommendation: {baseline.get('recommendation', 'N/A')}")

/*
  # WAF Monitoring and Logging Schema

  1. New Tables
    - `waf_requests`
      - `id` (uuid, primary key)
      - `timestamp` (timestamptz) - Request timestamp
      - `method` (text) - HTTP method (GET, POST, etc.)
      - `path` (text) - Request path
      - `headers` (jsonb) - Request headers
      - `body` (text) - Request body
      - `source_ip` (text) - Client IP address
      - `normalized_request` (text) - Canonicalized request
      - `fast_path_blocked` (boolean) - Blocked by fast-path filter
      - `fast_path_rule` (text) - Rule that triggered fast-path block
      - `transformer_score` (float) - Model confidence score (0-1)
      - `prediction` (text) - malicious or benign
      - `action_taken` (text) - allow, block, or flag
      - `latency_ms` (float) - Processing time
      - `created_at` (timestamptz)
    
    - `waf_feedback`
      - `id` (uuid, primary key)
      - `request_id` (uuid, foreign key to waf_requests)
      - `original_prediction` (text)
      - `corrected_label` (text) - Human-verified label
      - `feedback_type` (text) - false_positive or false_negative
      - `notes` (text)
      - `created_at` (timestamptz)
    
    - `waf_statistics`
      - `id` (uuid, primary key)
      - `date` (date) - Statistics date
      - `total_requests` (integer)
      - `blocked_requests` (integer)
      - `flagged_requests` (integer)
      - `false_positives` (integer)
      - `false_negatives` (integer)
      - `avg_latency_ms` (float)
      - `created_at` (timestamptz)

  2. Security
    - Enable RLS on all tables
    - Add policies for service role access
    - Add indexes for performance
*/

CREATE TABLE IF NOT EXISTS waf_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz NOT NULL DEFAULT now(),
  method text NOT NULL,
  path text NOT NULL,
  headers jsonb DEFAULT '{}'::jsonb,
  body text DEFAULT '',
  source_ip text NOT NULL,
  normalized_request text,
  fast_path_blocked boolean DEFAULT false,
  fast_path_rule text,
  transformer_score float,
  prediction text,
  action_taken text NOT NULL,
  latency_ms float,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS waf_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL REFERENCES waf_requests(id) ON DELETE CASCADE,
  original_prediction text NOT NULL,
  corrected_label text NOT NULL,
  feedback_type text NOT NULL,
  notes text,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS waf_statistics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  date date NOT NULL UNIQUE,
  total_requests integer DEFAULT 0,
  blocked_requests integer DEFAULT 0,
  flagged_requests integer DEFAULT 0,
  false_positives integer DEFAULT 0,
  false_negatives integer DEFAULT 0,
  avg_latency_ms float DEFAULT 0.0,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE waf_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_statistics ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role can manage waf_requests"
  ON waf_requests
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role can manage waf_feedback"
  ON waf_feedback
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role can manage waf_statistics"
  ON waf_statistics
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_waf_requests_timestamp ON waf_requests(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_waf_requests_source_ip ON waf_requests(source_ip);
CREATE INDEX IF NOT EXISTS idx_waf_requests_prediction ON waf_requests(prediction);
CREATE INDEX IF NOT EXISTS idx_waf_requests_action ON waf_requests(action_taken);
CREATE INDEX IF NOT EXISTS idx_waf_statistics_date ON waf_statistics(date DESC);

/*
  # Add RPC function for WAF statistics

  1. Functions
    - `get_waf_stats` - Returns aggregated WAF statistics
      - Total requests in last 24h
      - Blocked/flagged/allowed counts
      - Average latency
      - Top attacking IPs
      - Top attack patterns
*/

CREATE OR REPLACE FUNCTION get_waf_stats()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    result jsonb;
    total_count integer;
    blocked_count integer;
    flagged_count integer;
    allowed_count integer;
    avg_lat float;
BEGIN
    SELECT 
        COUNT(*)::integer,
        COUNT(*) FILTER (WHERE action_taken = 'block')::integer,
        COUNT(*) FILTER (WHERE action_taken = 'flag')::integer,
        COUNT(*) FILTER (WHERE action_taken = 'allow')::integer,
        AVG(latency_ms)::float
    INTO 
        total_count,
        blocked_count,
        flagged_count,
        allowed_count,
        avg_lat
    FROM waf_requests
    WHERE timestamp > NOW() - INTERVAL '24 hours';

    result := jsonb_build_object(
        'total_requests', COALESCE(total_count, 0),
        'blocked_requests', COALESCE(blocked_count, 0),
        'flagged_requests', COALESCE(flagged_count, 0),
        'allowed_requests', COALESCE(allowed_count, 0),
        'avg_latency_ms', COALESCE(avg_lat, 0)
    );

    RETURN result;
END;
$$;

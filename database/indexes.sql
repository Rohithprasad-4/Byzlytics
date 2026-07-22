-- =============================================================================
-- SecureGate AI — Performance Indexes
-- Database: network_security
-- =============================================================================

-- devices
CREATE INDEX IF NOT EXISTS idx_devices_ip_address
    ON devices (ip_address);

CREATE INDEX IF NOT EXISTS idx_devices_mac_address
    ON devices (mac_address)
    WHERE mac_address IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_last_seen
    ON devices (last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_devices_blocked
    ON devices (is_blocked)
    WHERE is_blocked = TRUE;

CREATE INDEX IF NOT EXISTS idx_devices_trusted
    ON devices (is_trusted)
    WHERE is_trusted = TRUE;

CREATE INDEX IF NOT EXISTS idx_devices_type
    ON devices (device_type);

-- events — high-volume table; optimize time-range and pipeline queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_device_id
    ON events (device_id)
    WHERE device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_events_protocol
    ON events (protocol);

CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON events (source_ip);

CREATE INDEX IF NOT EXISTS idx_events_destination_ip
    ON events (destination_ip);

CREATE INDEX IF NOT EXISTS idx_events_processed
    ON events (processed, timestamp)
    WHERE processed = FALSE;

CREATE INDEX IF NOT EXISTS idx_events_device_timestamp
    ON events (device_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_protocol_timestamp
    ON events (protocol, timestamp DESC);

-- Composite for traffic analytics hourly aggregation
CREATE INDEX IF NOT EXISTS idx_events_hour_bucket
    ON events (date_trunc('hour', timestamp), protocol);

-- risk_assessment
CREATE INDEX IF NOT EXISTS idx_risk_assessment_event_id
    ON risk_assessment (event_id);

CREATE INDEX IF NOT EXISTS idx_risk_assessment_risk_score
    ON risk_assessment (risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_risk_assessment_category
    ON risk_assessment (risk_category);

CREATE INDEX IF NOT EXISTS idx_risk_assessment_assessed_at
    ON risk_assessment (assessed_at DESC);

CREATE INDEX IF NOT EXISTS idx_risk_assessment_high_risk
    ON risk_assessment (assessed_at DESC)
    WHERE risk_category = 'High';

-- GIN index for explanation JSON queries (dashboard search)
CREATE INDEX IF NOT EXISTS idx_risk_assessment_explanation_gin
    ON risk_assessment USING GIN (explanation jsonb_path_ops);

-- user_decisions
CREATE INDEX IF NOT EXISTS idx_user_decisions_device_id
    ON user_decisions (device_id)
    WHERE device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_user_decisions_ip_address
    ON user_decisions (ip_address);

CREATE INDEX IF NOT EXISTS idx_user_decisions_action
    ON user_decisions (action);

CREATE INDEX IF NOT EXISTS idx_user_decisions_active
    ON user_decisions (is_active, decided_at DESC)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_user_decisions_decided_at
    ON user_decisions (decided_at DESC);

-- daily_summary
CREATE INDEX IF NOT EXISTS idx_daily_summary_date
    ON daily_summary (summary_date DESC);

CREATE INDEX IF NOT EXISTS idx_daily_summary_high_risk
    ON daily_summary (summary_date DESC, high_risk_count DESC);

-- pipeline_runs
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at
    ON pipeline_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_status
    ON pipeline_runs (status)
    WHERE status = 'running';

-- Analyze tables after index creation (run during deployment)
-- ANALYZE devices;
-- ANALYZE events;
-- ANALYZE risk_assessment;
-- ANALYZE user_decisions;
-- ANALYZE daily_summary;

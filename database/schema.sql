-- =============================================================================
-- SecureGate AI — PostgreSQL Schema
-- Database: network_security
-- =============================================================================
-- Production schema for LAN security monitoring, ML risk assessment, and
-- user decision management. All timestamps stored in UTC.
-- =============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'protocol_type') THEN
        CREATE TYPE protocol_type AS ENUM ('DNS', 'TCP', 'ICMP', 'OTHER');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risk_category_type') THEN
        CREATE TYPE risk_category_type AS ENUM ('Low', 'Medium', 'High');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'decision_action_type') THEN
        CREATE TYPE decision_action_type AS ENUM (
            'allow',
            'block',
            'always_allow',
            'always_block'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_type_enum') THEN
        CREATE TYPE device_type_enum AS ENUM (
            'workstation',
            'server',
            'mobile',
            'iot',
            'router',
            'printer',
            'unknown'
        );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- devices — discovered LAN endpoints
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    device_id       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address      INET NOT NULL,
    mac_address     MACADDR,
    device_type     device_type_enum NOT NULL DEFAULT 'unknown',
    hostname        VARCHAR(255),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_trusted      BOOLEAN NOT NULL DEFAULT FALSE,
    is_blocked      BOOLEAN NOT NULL DEFAULT FALSE,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT devices_ip_address_unique UNIQUE (ip_address),
    CONSTRAINT devices_trust_block_exclusive CHECK (
        NOT (is_trusted = TRUE AND is_blocked = TRUE)
    )
);

COMMENT ON TABLE devices IS 'LAN devices discovered via packet capture and enrichment.';
COMMENT ON COLUMN devices.is_trusted IS 'Operator-marked trusted device; suppresses aggressive blocking.';
COMMENT ON COLUMN devices.is_blocked IS 'Device currently blocked at gateway/policy layer.';

-- ---------------------------------------------------------------------------
-- events — raw and processed network traffic events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    event_id        BIGSERIAL PRIMARY KEY,
    device_id       UUID REFERENCES devices(device_id) ON DELETE SET NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    protocol        protocol_type NOT NULL DEFAULT 'OTHER',
    source_ip       INET NOT NULL,
    destination_ip  INET NOT NULL,
    source_port     INTEGER CHECK (source_port IS NULL OR (source_port >= 0 AND source_port <= 65535)),
    destination_port INTEGER CHECK (destination_port IS NULL OR (destination_port >= 0 AND destination_port <= 65535)),
    packet_size     INTEGER NOT NULL CHECK (packet_size > 0),
    processed       BOOLEAN NOT NULL DEFAULT FALSE,
    capture_iface   VARCHAR(64),
    raw_metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE events IS 'Captured network packets normalized into security events.';
COMMENT ON COLUMN events.processed IS 'TRUE after pipeline + ML + risk assessment complete.';

-- ---------------------------------------------------------------------------
-- risk_assessment — ML + rule-engine output per event
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_assessment (
    assessment_id   BIGSERIAL PRIMARY KEY,
    event_id        BIGINT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    risk_score      NUMERIC(5, 2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_category   risk_category_type NOT NULL,
    explanation     JSONB NOT NULL DEFAULT '{}'::jsonb,
    anomaly_score   NUMERIC(10, 6) NOT NULL,
    ml_score        NUMERIC(5, 2),
    rule_adjustments JSONB NOT NULL DEFAULT '[]'::jsonb,
    feature_vector  JSONB,
    assessed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT risk_assessment_event_unique UNIQUE (event_id)
);

COMMENT ON TABLE risk_assessment IS 'Combined ML anomaly and rule-based risk scoring.';
COMMENT ON COLUMN risk_assessment.explanation IS 'JSON: {observation, context, recommendation}.';
COMMENT ON COLUMN risk_assessment.anomaly_score IS 'Raw Isolation Forest decision function output.';

-- ---------------------------------------------------------------------------
-- user_decisions — operator allow/block actions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_decisions (
    decision_id     BIGSERIAL PRIMARY KEY,
    device_id       UUID REFERENCES devices(device_id) ON DELETE SET NULL,
    ip_address      INET NOT NULL,
    action          decision_action_type NOT NULL,
    reason          TEXT,
    triggered_by    VARCHAR(128) DEFAULT 'dashboard',
    assessment_id   BIGINT REFERENCES risk_assessment(assessment_id) ON DELETE SET NULL,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE user_decisions IS 'Human-in-the-loop security decisions for devices and IPs.';
COMMENT ON COLUMN user_decisions.action IS 'allow|block|always_allow|always_block';

-- ---------------------------------------------------------------------------
-- daily_summary — aggregated statistics for reporting
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS daily_summary (
    summary_id          BIGSERIAL PRIMARY KEY,
    summary_date        DATE NOT NULL,
    total_devices       INTEGER NOT NULL DEFAULT 0 CHECK (total_devices >= 0),
    active_devices      INTEGER NOT NULL DEFAULT 0 CHECK (active_devices >= 0),
    total_events        BIGINT NOT NULL DEFAULT 0 CHECK (total_events >= 0),
    dns_events          BIGINT NOT NULL DEFAULT 0 CHECK (dns_events >= 0),
    tcp_events          BIGINT NOT NULL DEFAULT 0 CHECK (tcp_events >= 0),
    icmp_events         BIGINT NOT NULL DEFAULT 0 CHECK (icmp_events >= 0),
    low_risk_count      INTEGER NOT NULL DEFAULT 0 CHECK (low_risk_count >= 0),
    medium_risk_count   INTEGER NOT NULL DEFAULT 0 CHECK (medium_risk_count >= 0),
    high_risk_count     INTEGER NOT NULL DEFAULT 0 CHECK (high_risk_count >= 0),
    blocked_devices     INTEGER NOT NULL DEFAULT 0 CHECK (blocked_devices >= 0),
    blocked_requests    INTEGER NOT NULL DEFAULT 0 CHECK (blocked_requests >= 0),
    suspicious_devices  INTEGER NOT NULL DEFAULT 0 CHECK (suspicious_devices >= 0),
    avg_risk_score      NUMERIC(5, 2) NOT NULL DEFAULT 0,
    peak_hour           SMALLINT CHECK (peak_hour IS NULL OR (peak_hour >= 0 AND peak_hour <= 23)),
    top_risky_ips       JSONB NOT NULL DEFAULT '[]'::jsonb,
    hourly_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    protocol_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report_path         TEXT,

    CONSTRAINT daily_summary_date_unique UNIQUE (summary_date)
);

COMMENT ON TABLE daily_summary IS 'Pre-computed daily metrics for dashboard and PDF reports.';

-- ---------------------------------------------------------------------------
-- pipeline_runs — audit trail for data pipeline executions (operational)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id          BIGSERIAL PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    status          VARCHAR(32) NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'completed', 'failed')),
    events_collected INTEGER NOT NULL DEFAULT 0,
    events_processed INTEGER NOT NULL DEFAULT 0,
    events_failed   INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT
);

COMMENT ON TABLE pipeline_runs IS 'Operational log for ETL pipeline batch runs.';

-- ---------------------------------------------------------------------------
-- Updated-at trigger for devices
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_devices_updated_at ON devices;
CREATE TRIGGER trg_devices_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Helper view: latest risk per device
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_device_risk_summary AS
SELECT
    d.device_id,
    d.ip_address,
    d.mac_address,
    d.device_type,
    d.is_trusted,
    d.is_blocked,
    d.last_seen,
    COUNT(ra.assessment_id) AS assessment_count,
    COALESCE(MAX(ra.risk_score), 0) AS max_risk_score,
    COALESCE(AVG(ra.risk_score), 0) AS avg_risk_score,
    COUNT(*) FILTER (WHERE ra.risk_category = 'High') AS high_risk_events
FROM devices d
LEFT JOIN events e ON e.device_id = d.device_id
LEFT JOIN risk_assessment ra ON ra.event_id = e.event_id
GROUP BY
    d.device_id, d.ip_address, d.mac_address, d.device_type,
    d.is_trusted, d.is_blocked, d.last_seen;

COMMENT ON VIEW v_device_risk_summary IS 'Aggregated risk metrics per device for dashboard APIs.';

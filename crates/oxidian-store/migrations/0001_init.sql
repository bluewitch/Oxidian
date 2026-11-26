CREATE TABLE assets (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    CONSTRAINT assets_kind_check CHECK (kind IN ('domain', 'host', 'address')),
    CONSTRAINT assets_identity UNIQUE (name, kind, address)
);

CREATE TABLE services (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
    protocol TEXT NOT NULL,
    product TEXT,
    version TEXT,
    banner TEXT,
    observed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT services_protocol_check CHECK (protocol IN ('tcp', 'udp')),
    CONSTRAINT services_identity UNIQUE (asset_id, port, protocol)
);

CREATE INDEX services_asset_idx ON services (asset_id);

CREATE TABLE findings (
    id UUID PRIMARY KEY,
    service_id UUID NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
    protocol TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    severity TEXT NOT NULL,
    kev BOOLEAN NOT NULL,
    epss DOUBLE PRECISION,
    cvss DOUBLE PRECISION,
    rank_score DOUBLE PRECISION NOT NULL,
    summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT findings_severity_check CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT findings_protocol_check CHECK (protocol IN ('tcp', 'udp')),
    CONSTRAINT findings_identity UNIQUE (service_id, cve_id)
);

CREATE INDEX findings_service_idx ON findings (service_id);
CREATE INDEX findings_rank_idx ON findings (rank_score DESC, cve_id);

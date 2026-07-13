-- ============================================================================
-- STATIC ENRICHMENT TABLES
-- Offline, deterministic threat-intel and geo reference data.
--
-- ip_enrichment mirrors the static range table in ADTE
-- (adte/intel/_mock.py) so this lab and the triage engine name the same
-- infrastructure the same way. In production these lookups come from
-- AbuseIPDB / VirusTotal / OTX via ADTE's wrapped clients; here they are
-- seeded so the lab stays reproducible with zero API keys.
-- ============================================================================

DROP TABLE IF EXISTS ip_enrichment;
DROP TABLE IF EXISTS country_distance;
DROP TABLE IF EXISTS travel_exceptions;

-- ----------------------------------------------------------------------------
-- IP reputation ranges.
-- ip_prefix is a dotted string prefix; the join in v_ip_enrichment uses
-- source_ip LIKE ip_prefix || '%'. This ONLY works because every seeded
-- range sits on a /24 (or /16) octet boundary. Production code must compare
-- integer ranges (see ADTE's use of the ipaddress module) — string prefixes
-- would mis-match e.g. '10.1.1' against '10.1.10.x'.
-- ----------------------------------------------------------------------------

CREATE TABLE ip_enrichment (
    ip_prefix    TEXT PRIMARY KEY,   -- dotted prefix ending in '.'
    cidr         TEXT NOT NULL,
    is_malicious INTEGER NOT NULL,
    confidence   REAL NOT NULL,      -- 0.0-1.0, mirrors ADTE ThreatIntelResult
    source       TEXT NOT NULL,
    tags         TEXT NOT NULL       -- comma-separated
);

INSERT INTO ip_enrichment (ip_prefix, cidr, is_malicious, confidence, source, tags) VALUES
('185.220.101.', '185.220.101.0/24', 1, 0.85, 'mock-tor-list',     'tor-exit'),
('45.33.32.',    '45.33.32.0/24',    1, 0.75, 'mock-scanner-feed', 'scanner,brute-force'),
('198.51.100.',  '198.51.100.0/24',  1, 0.95, 'mock-c2-feed',      'c2'),
('203.0.113.',   '203.0.113.0/24',   1, 0.70, 'mock-miner-feed',   'cryptominer'),
('100.64.',      '100.64.0.0/16',    0, 0.45, 'mock-proxy-feed',   'residential-proxy'),
('192.0.2.',     '192.0.2.0/24',     0, 0.40, 'mock-hosting-feed', 'bulletproof-hosting');

-- Deliberate feed gap: E016's RU source (95.213.45.67) and E001's CN source
-- (203.45.67.89 — NOT in 203.0.113.0/24) are absent from every feed. Real
-- offline intel is incomplete; the triage queue shows these rows unenriched.

-- ----------------------------------------------------------------------------
-- Country-centroid great-circle distances (km, rounded to 50).
-- Precomputed so the impossible-travel view needs no math functions.
-- Convention: country_a < country_b (alphabetical); views join with
-- MIN()/MAX() to normalize pair order.
-- CAVEAT (documented tuning decision): centroid distance OVERSTATES travel
-- between border regions — a Seattle->Vancouver hop is ~200 km, not the
-- 1,900 km US-CA centroid figure. See travel_exceptions.
-- ----------------------------------------------------------------------------

CREATE TABLE country_distance (
    country_a   TEXT NOT NULL,
    country_b   TEXT NOT NULL,
    distance_km INTEGER NOT NULL,
    PRIMARY KEY (country_a, country_b),
    CHECK (country_a < country_b)
);

INSERT INTO country_distance (country_a, country_b, distance_km) VALUES
('CA', 'CN', 9400),
('CA', 'DE', 6750),
('CA', 'RU', 6650),
('CA', 'US', 1900),
('CN', 'DE', 7250),
('CN', 'RU', 2850),
('CN', 'US', 11250),
('DE', 'RU', 5450),
('DE', 'US', 7800),
('RU', 'US', 8550);

-- ----------------------------------------------------------------------------
-- Documented travel-pair exceptions. A matching pair is DOWNGRADED to
-- MEDIUM, never suppressed — the analyst still sees it, with the rationale.
-- ----------------------------------------------------------------------------

CREATE TABLE travel_exceptions (
    country_a TEXT NOT NULL,
    country_b TEXT NOT NULL,
    rationale TEXT NOT NULL,
    PRIMARY KEY (country_a, country_b),
    CHECK (country_a < country_b)
);

INSERT INTO travel_exceptions (country_a, country_b, rationale) VALUES
('CA', 'US', 'Established US<->CA business-travel corridor (E002 baseline); centroid distance overstates border-region hops. Downgrade to MEDIUM, never suppress.');

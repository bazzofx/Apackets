-- APackets analysis schema (frozen: see docs/CONTRACT.md §3)
-- All timestamps are Unix epoch seconds as REAL unless the column is *_text.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS analyses (
    id                TEXT PRIMARY KEY,
    original_filename TEXT    NOT NULL,
    stored_path       TEXT    NOT NULL,
    file_size         INTEGER NOT NULL DEFAULT 0,
    file_sha256       TEXT,
    file_type         TEXT,
    encapsulation     TEXT,
    status            TEXT    NOT NULL DEFAULT 'pending',
    progress          REAL    NOT NULL DEFAULT 0,
    stage             TEXT,
    error             TEXT,
    packet_count      INTEGER NOT NULL DEFAULT 0,
    bytes_total       INTEGER NOT NULL DEFAULT 0,
    capture_start     REAL,
    capture_end       REAL,
    duration          REAL,
    src_ip_count      INTEGER NOT NULL DEFAULT 0,
    dst_ip_count      INTEGER NOT NULL DEFAULT 0,
    tcp_count         INTEGER NOT NULL DEFAULT 0,
    udp_count         INTEGER NOT NULL DEFAULT 0,
    dns_count         INTEGER NOT NULL DEFAULT 0,
    http_count        INTEGER NOT NULL DEFAULT 0,
    tls_count         INTEGER NOT NULL DEFAULT 0,
    created_at        REAL    NOT NULL,
    updated_at        REAL    NOT NULL,
    started_at        REAL,
    finished_at       REAL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);

CREATE TABLE IF NOT EXISTS jobs (
    id               TEXT PRIMARY KEY,
    analysis_id      TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind             TEXT NOT NULL DEFAULT 'full_analysis',
    status           TEXT NOT NULL DEFAULT 'queued',
    stage            TEXT,
    progress         REAL NOT NULL DEFAULT 0,
    message          TEXT,
    error            TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_at       REAL NOT NULL,
    started_at       REAL,
    finished_at      REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_analysis ON jobs(analysis_id, created_at DESC);

CREATE TABLE IF NOT EXISTS packets (
    analysis_id   TEXT    NOT NULL,
    number        INTEGER NOT NULL,
    time_epoch    REAL,
    time_relative REAL,
    frame_len     INTEGER,
    cap_len       INTEGER,
    protocols     TEXT,
    protocol      TEXT,
    info          TEXT,
    eth_src       TEXT,
    eth_dst       TEXT,
    vlan_id       INTEGER,
    ip_version    INTEGER,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    transport     TEXT,
    tcp_flags     TEXT,
    tcp_flags_raw TEXT,
    tcp_stream    INTEGER,
    udp_stream    INTEGER,
    ttl           INTEGER,
    ip_id         INTEGER,
    tcp_seq       INTEGER,
    tcp_ack       INTEGER,
    tcp_window    INTEGER,
    tcp_len       INTEGER,
    udp_len       INTEGER,
    dns_query     TEXT,
    dns_qtype     TEXT,
    dns_rcode     TEXT,
    http_method   TEXT,
    http_host     TEXT,
    http_uri      TEXT,
    http_status   INTEGER,
    tls_sni       TEXT,
    tls_version   TEXT,
    PRIMARY KEY (analysis_id, number)
);
CREATE INDEX IF NOT EXISTS idx_pk_number   ON packets(analysis_id, number);
CREATE INDEX IF NOT EXISTS idx_pk_time     ON packets(analysis_id, time_epoch);
CREATE INDEX IF NOT EXISTS idx_pk_src      ON packets(analysis_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_pk_dst      ON packets(analysis_id, dst_ip);
CREATE INDEX IF NOT EXISTS idx_pk_srcport  ON packets(analysis_id, src_port);
CREATE INDEX IF NOT EXISTS idx_pk_dstport  ON packets(analysis_id, dst_port);
CREATE INDEX IF NOT EXISTS idx_pk_proto    ON packets(analysis_id, protocol);
CREATE INDEX IF NOT EXISTS idx_pk_transport ON packets(analysis_id, transport);
CREATE INDEX IF NOT EXISTS idx_pk_len      ON packets(analysis_id, frame_len);
CREATE INDEX IF NOT EXISTS idx_pk_tcpstream ON packets(analysis_id, tcp_stream);
-- Covering indexes for the Dashboard aggregates. `build_summary` groups packets by
-- source, destination, port, protocol and time bucket, and always sums frame_len;
-- without frame_len in the index every group is a table lookup per row. Measured on
-- a 163k-frame capture: the five queries below the summary went from 1.29 s to 0.53 s
-- together, at a one-off cost of 3.6 s to build (paid once, during analysis, by a
-- capture large enough to need it).
CREATE INDEX IF NOT EXISTS idx_pk_src_len   ON packets(analysis_id, src_ip, frame_len);
CREATE INDEX IF NOT EXISTS idx_pk_dst_len   ON packets(analysis_id, dst_ip, frame_len);
CREATE INDEX IF NOT EXISTS idx_pk_dport_len ON packets(analysis_id, dst_port, transport, frame_len);
CREATE INDEX IF NOT EXISTS idx_pk_proto_len ON packets(analysis_id, protocol, frame_len);
CREATE INDEX IF NOT EXISTS idx_pk_time_len  ON packets(analysis_id, time_epoch, frame_len);
CREATE INDEX IF NOT EXISTS idx_pk_udpstream ON packets(analysis_id, udp_stream);

CREATE TABLE IF NOT EXISTS conversations (
    analysis_id     TEXT    NOT NULL,
    conv_id         TEXT    NOT NULL,
    transport       TEXT    NOT NULL,
    stream_id       INTEGER,
    endpoint_a      TEXT    NOT NULL,
    endpoint_b      TEXT    NOT NULL,
    ip_a            TEXT,
    port_a          INTEGER,
    ip_b            TEXT,
    port_b          INTEGER,
    packets_a_to_b  INTEGER NOT NULL DEFAULT 0,
    bytes_a_to_b    INTEGER NOT NULL DEFAULT 0,
    packets_b_to_a  INTEGER NOT NULL DEFAULT 0,
    bytes_b_to_a    INTEGER NOT NULL DEFAULT 0,
    packets_total   INTEGER NOT NULL DEFAULT 0,
    bytes_total     INTEGER NOT NULL DEFAULT 0,
    start_time      REAL,
    end_time        REAL,
    duration        REAL,
    state           TEXT,
    protocols       TEXT,
    PRIMARY KEY (analysis_id, conv_id)
);
CREATE INDEX IF NOT EXISTS idx_conv_transport ON conversations(analysis_id, transport);
CREATE INDEX IF NOT EXISTS idx_conv_bytes     ON conversations(analysis_id, bytes_total DESC);
CREATE INDEX IF NOT EXISTS idx_conv_a         ON conversations(analysis_id, endpoint_a);

CREATE TABLE IF NOT EXISTS streams (
    analysis_id          TEXT    NOT NULL,
    stream_id            INTEGER NOT NULL,
    transport            TEXT    NOT NULL,
    client_ip            TEXT,
    client_port          INTEGER,
    server_ip            TEXT,
    server_port          INTEGER,
    payload_bytes_client INTEGER NOT NULL DEFAULT 0,
    payload_bytes_server INTEGER NOT NULL DEFAULT 0,
    packets              INTEGER NOT NULL DEFAULT 0,
    start_time           REAL,
    end_time             REAL,
    PRIMARY KEY (analysis_id, transport, stream_id)
);

CREATE TABLE IF NOT EXISTS http_transactions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id           TEXT NOT NULL,
    stream_id             INTEGER,
    request_packet        INTEGER,
    response_packet       INTEGER,
    time_epoch            REAL,
    response_time         REAL,
    client_ip             TEXT,
    client_port           INTEGER,
    server_ip             TEXT,
    server_port           INTEGER,
    method                TEXT,
    host                  TEXT,
    uri                   TEXT,
    full_uri              TEXT,
    version               TEXT,
    status_code           INTEGER,
    status_text           TEXT,
    user_agent            TEXT,
    referer               TEXT,
    content_type          TEXT,
    server_header         TEXT,
    request_len           INTEGER,
    response_len          INTEGER,
    request_headers       TEXT,
    response_headers      TEXT,
    request_body          TEXT,
    response_body         TEXT,
    request_body_size     INTEGER,
    response_body_size    INTEGER,
    response_body_truncated INTEGER DEFAULT 0,
    flags                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_http_analysis ON http_transactions(analysis_id, time_epoch);
CREATE INDEX IF NOT EXISTS idx_http_host     ON http_transactions(analysis_id, host);
CREATE INDEX IF NOT EXISTS idx_http_method   ON http_transactions(analysis_id, method);
CREATE INDEX IF NOT EXISTS idx_http_status   ON http_transactions(analysis_id, status_code);
CREATE INDEX IF NOT EXISTS idx_http_stream   ON http_transactions(analysis_id, stream_id);

CREATE TABLE IF NOT EXISTS dns_queries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    dns_id          INTEGER,
    time_epoch      REAL,
    packet_number   INTEGER,
    response_packet INTEGER,
    response_time   REAL,
    response_delay  REAL,
    client_ip       TEXT,
    server_ip       TEXT,
    query_name      TEXT,
    query_type      TEXT,
    is_response     INTEGER,
    rcode           INTEGER,
    rcode_name      TEXT,
    answers         TEXT,
    answer_ips      TEXT,
    cnames          TEXT,
    min_ttl         INTEGER,
    authoritative   INTEGER,
    truncated       INTEGER,
    name_length     INTEGER,
    label_count     INTEGER,
    longest_label   INTEGER,
    entropy         REAL,
    flags           TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_analysis ON dns_queries(analysis_id, time_epoch);
CREATE INDEX IF NOT EXISTS idx_dns_name     ON dns_queries(analysis_id, query_name);
CREATE INDEX IF NOT EXISTS idx_dns_client   ON dns_queries(analysis_id, client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_rcode    ON dns_queries(analysis_id, rcode_name);
CREATE INDEX IF NOT EXISTS idx_dns_qtype    ON dns_queries(analysis_id, query_type);

CREATE TABLE IF NOT EXISTS tls_sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id      TEXT NOT NULL,
    stream_id        INTEGER,
    client_ip        TEXT,
    client_port      INTEGER,
    server_ip        TEXT,
    server_port      INTEGER,
    client_packet    INTEGER,
    server_packet    INTEGER,
    time_epoch       REAL,
    client_version   TEXT,
    server_version   TEXT,
    version          TEXT,
    sni              TEXT,
    alpn             TEXT,
    selected_alpn    TEXT,
    cipher_suite     TEXT,
    ja3              TEXT,
    ja3_full         TEXT,
    ja3s             TEXT,
    ja4              TEXT,
    cert_subject     TEXT,
    cert_issuer      TEXT,
    cert_not_before  TEXT,
    cert_not_after   TEXT,
    cert_serial      TEXT,
    handshake_status TEXT,
    alert            TEXT,
    record_count     INTEGER,
    flags            TEXT
);
CREATE INDEX IF NOT EXISTS idx_tls_analysis ON tls_sessions(analysis_id, time_epoch);
CREATE INDEX IF NOT EXISTS idx_tls_sni      ON tls_sessions(analysis_id, sni);
CREATE INDEX IF NOT EXISTS idx_tls_version  ON tls_sessions(analysis_id, version);
CREATE INDEX IF NOT EXISTS idx_tls_stream   ON tls_sessions(analysis_id, stream_id);

-- Protocol sessions: one row per stream in which SMTP, POP3, IMAP, SSH, FTP, SIP,
-- RTP, RTCP or SMB appeared (see docs/PROTOCOLS.md). Shared columns hold what every
-- session has; per-protocol keys live in `detail`, so a new protocol never changes
-- this table. `flags` and `detail` are JSON text: an array of "code[: detail]"
-- strings, and an object of only the keys the dissector actually produced.
CREATE TABLE IF NOT EXISTS protocol_sessions (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id    TEXT    NOT NULL,
  protocol       TEXT    NOT NULL,   -- smtp | pop3 | imap | ssh | ftp | sip | rtp | rtcp | smb
  stream_id      INTEGER,            -- tcp.stream or udp.stream, when TShark gave one
  transport      TEXT,               -- 'tcp' | 'udp'
  client_ip      TEXT,
  client_port    INTEGER,
  server_ip      TEXT,
  server_port    INTEGER,
  first_frame    INTEGER,            -- frame.number of the session's first frame
  last_frame     INTEGER,
  start_time     REAL,               -- epoch seconds, first frame
  end_time       REAL,               -- epoch seconds, last frame
  duration       REAL,               -- end_time - start_time
  packets        INTEGER NOT NULL DEFAULT 0,
  bytes          INTEGER NOT NULL DEFAULT 0,
  client_packets INTEGER NOT NULL DEFAULT 0,
  client_bytes   INTEGER NOT NULL DEFAULT 0,
  server_packets INTEGER NOT NULL DEFAULT 0,
  server_bytes   INTEGER NOT NULL DEFAULT 0,
  detail         TEXT NOT NULL DEFAULT '{}',   -- JSON object, §3
  flags          TEXT NOT NULL DEFAULT '[]',   -- JSON array of strings, §4
  note           TEXT,               -- how the roles were assigned, or a limit of this row
  created_at     REAL
);
CREATE INDEX IF NOT EXISTS idx_proto_analysis ON protocol_sessions(analysis_id, protocol, start_time);
CREATE INDEX IF NOT EXISTS idx_proto_stream   ON protocol_sessions(analysis_id, protocol, stream_id);
CREATE INDEX IF NOT EXISTS idx_proto_server   ON protocol_sessions(analysis_id, server_ip, server_port);
CREATE INDEX IF NOT EXISTS idx_proto_client   ON protocol_sessions(analysis_id, client_ip);

CREATE TABLE IF NOT EXISTS hosts (
    analysis_id      TEXT    NOT NULL,
    ip               TEXT    NOT NULL,
    mac              TEXT,
    first_seen       REAL,
    last_seen        REAL,
    packets_sent     INTEGER NOT NULL DEFAULT 0,
    packets_received INTEGER NOT NULL DEFAULT 0,
    bytes_sent       INTEGER NOT NULL DEFAULT 0,
    bytes_received   INTEGER NOT NULL DEFAULT 0,
    ports            TEXT,
    protocols        TEXT,
    dns_names        TEXT,
    tls_sni          TEXT,
    is_private       INTEGER,
    ip_version       INTEGER,
    peer_count       INTEGER NOT NULL DEFAULT 0,
    peers            TEXT,
    PRIMARY KEY (analysis_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_hosts_bytes ON hosts(analysis_id, bytes_sent DESC);

CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    analysis_id    TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL,
    reason         TEXT NOT NULL,
    evidence       TEXT,
    packet_numbers TEXT,
    entities       TEXT,
    recommendation TEXT,
    created_at     REAL
);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule     ON findings(analysis_id, rule_id);

CREATE TABLE IF NOT EXISTS objects (
    id                TEXT PRIMARY KEY,
    analysis_id       TEXT NOT NULL,
    filename          TEXT NOT NULL,
    original_filename TEXT,
    stored_path       TEXT NOT NULL,
    protocol          TEXT,
    content_type      TEXT,
    size              INTEGER,
    sha256            TEXT,
    sha1              TEXT,
    md5               TEXT,
    src_ip            TEXT,
    dst_ip            TEXT,
    src_port          INTEGER,
    dst_port          INTEGER,
    stream_id         INTEGER,
    packet_numbers    TEXT,
    status            TEXT NOT NULL DEFAULT 'complete',
    note              TEXT,
    created_at        REAL
);
CREATE INDEX IF NOT EXISTS idx_objects_analysis ON objects(analysis_id);

CREATE TABLE IF NOT EXISTS indicators (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    note        TEXT,
    created_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_indicators_analysis ON indicators(analysis_id, type);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL
);

-- Cached expensive derived artefacts (project stats, hierarchies).
CREATE TABLE IF NOT EXISTS stats_cache (
    analysis_id TEXT NOT NULL,
    kind        TEXT NOT NULL,
    json        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (analysis_id, kind)
);

-- Suricata-compatible detection rules (analyst editable).
-- `sid` is the Suricata signature id and is the primary key: rule files are
-- identified by SID, so importing a newer revision updates the existing row.
-- `options` holds the parsed, evaluable rule options as JSON; `unsupported`
-- lists options the built-in matcher cannot evaluate (a rule with any of them
-- is stored with supported = 0 and is never silently half-matched).
CREATE TABLE IF NOT EXISTS suricata_rules (
    sid         INTEGER PRIMARY KEY,
    rev         INTEGER NOT NULL DEFAULT 1,
    action      TEXT    NOT NULL DEFAULT 'alert',
    protocol    TEXT    NOT NULL,
    src_net     TEXT    NOT NULL DEFAULT 'any',
    src_port    TEXT    NOT NULL DEFAULT 'any',
    direction   TEXT    NOT NULL DEFAULT '->',
    dst_net     TEXT    NOT NULL DEFAULT 'any',
    dst_port    TEXT    NOT NULL DEFAULT 'any',
    msg         TEXT    NOT NULL,
    classtype   TEXT,
    priority    INTEGER,
    severity    TEXT    NOT NULL DEFAULT 'informational',
    reference   TEXT,
    metadata    TEXT,
    options     TEXT    NOT NULL DEFAULT '[]',
    unsupported TEXT    NOT NULL DEFAULT '[]',
    supported   INTEGER NOT NULL DEFAULT 1,
    approximate INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    source      TEXT    NOT NULL DEFAULT 'manual',
    category    TEXT,
    raw         TEXT    NOT NULL,
    created_at  REAL,
    updated_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_suricata_enabled  ON suricata_rules(enabled, supported);
CREATE INDEX IF NOT EXISTS idx_suricata_severity ON suricata_rules(severity);
CREATE INDEX IF NOT EXISTS idx_suricata_protocol ON suricata_rules(protocol);
CREATE INDEX IF NOT EXISTS idx_suricata_source   ON suricata_rules(source);

-- Registration data for one address (docs/IP_LOOKUP.md §4). Keyed by address and not by
-- analysis: registration data belongs to the address, so two captures that contain the
-- same peer share one record. Written only by an explicit lookup - never by opening a
-- host panel - and a lookup that produced nothing writes no row at all.
CREATE TABLE IF NOT EXISTS ip_lookups (
    ip         TEXT PRIMARY KEY,
    kind       TEXT    NOT NULL,   -- 'public' | 'private' | 'reserved' | 'loopback' | 'multicast' | 'link_local' | 'unknown'
    source     TEXT,               -- the registry's RDAP base URL, or NULL when nothing was queried
    asn        TEXT,               -- the origin AS number as a string, or NULL
    country    TEXT,               -- ISO 3166-1 alpha-2 from RDAP or Cymru, or NULL
    fetched_at REAL    NOT NULL,
    payload    TEXT    NOT NULL DEFAULT '{}'   -- the normalised record, §5.1
);

-- Visible (cleartext) credentials recovered from the rows the other analysers already
-- wrote (docs/CREDENTIALS.md §6). `value_preview` is what every list response shows and
-- is redacted at write time; `evidence` is one redacted line of context, redacted before
-- it is stored so a row read straight from SQLite leaks no more than the API does.
CREATE TABLE IF NOT EXISTS credentials (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id   TEXT NOT NULL,
  kind          TEXT NOT NULL,      -- username | password | api_key | bearer_token
                                    -- | other_secret | aws_access_key | jwt
                                    -- | pem_private_key | github_token | slack_token
                                    -- | google_api_key | stripe_key
  value         TEXT NOT NULL,      -- the wire value as recovered
  value_preview TEXT NOT NULL,      -- §5, what every list response shows
  value_length  INTEGER NOT NULL,
  value_truncated INTEGER NOT NULL DEFAULT 0,
  protocol      TEXT NOT NULL,      -- http | ftp | smtp | pop3 | imap
  transport     TEXT,               -- tcp | udp
  stream_id     INTEGER,
  direction     TEXT,               -- 'client_to_server' | 'server_to_client' | NULL
  location      TEXT NOT NULL,      -- e.g. authorization_basic, form_body, url_query,
                                    -- json_body, cookie_header, ftp_user_command,
                                    -- smtp_auth_plain, pop3_pass_command, imap_login_command
  source_field  TEXT,               -- the field name that selected it, when one did
  method        TEXT NOT NULL,      -- how it was derived: basic_decode, bearer_header,
                                    -- form_field, json_field, command_arg, pattern, …
  confidence    TEXT NOT NULL,      -- high | medium | low
  client_ip     TEXT, client_port INTEGER,
  server_ip     TEXT, server_port INTEGER,
  packet_first  INTEGER, packet_last INTEGER,
  evidence      TEXT NOT NULL,      -- one redacted line of context (§5)
  note          TEXT,               -- why it was scored as it was, in one sentence
  created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_analysis ON credentials (analysis_id, kind);
CREATE INDEX IF NOT EXISTS idx_credentials_stream   ON credentials (analysis_id, stream_id);
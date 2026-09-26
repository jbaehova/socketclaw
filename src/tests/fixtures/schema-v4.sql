-- Frozen real schema-v4 database produced by SocketClaw commit 376b358.
BEGIN TRANSACTION;
CREATE TABLE event_suppressions (
	event_id VARCHAR(36) NOT NULL,
	suppression_id VARCHAR(36) NOT NULL,
	family VARCHAR(30) NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (event_id, suppression_id, family),
	FOREIGN KEY(event_id) REFERENCES events (id) ON DELETE RESTRICT,
	FOREIGN KEY(suppression_id) REFERENCES suppression_rules (id)
);
CREATE TABLE events (
	id VARCHAR(36) NOT NULL,
	observed_at VARCHAR(40) NOT NULL,
	ingest_seq INTEGER NOT NULL,
	ingested_at VARCHAR(40),
	source_at VARCHAR(40),
	source_key VARCHAR(200),
	rule_version VARCHAR(36),
	outcome VARCHAR(20) NOT NULL,
	observed_quality VARCHAR(30) NOT NULL,
	ingest_order_origin VARCHAR(30) NOT NULL,
	source VARCHAR(30) NOT NULL,
	event_type VARCHAR(100) NOT NULL,
	title VARCHAR(200) NOT NULL,
	summary TEXT NOT NULL,
	target VARCHAR(253),
	evidence_json TEXT NOT NULL,
	score INTEGER NOT NULL,
	severity VARCHAR(20) NOT NULL,
	signals_json TEXT NOT NULL,
	investigation_state VARCHAR(30) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_events_ingest_seq_positive CHECK (ingest_seq > 0),
	FOREIGN KEY(rule_version) REFERENCES rule_versions (id)
);
INSERT INTO "events" VALUES('eb9619fc-58a6-4472-b96f-71a22315a2c6','2026-09-17T12:00:00.000000+00:00',1,'2026-09-17T12:00:00.000000+00:00',NULL,'v4-auth:1','c27dd04a-4080-4b2d-bdb0-bf8d7642c1bd','unknown','recorded','recorded','log','log.auth_failure','Historical v4 authentication failure','Preserved v4 evidence','192.0.2.9','{"user":"alice","asset":"server-v4","message":"Failed password for alice"}',25,'low','[{"code":"log.auth_failure","label":"Authentication failure","points":25,"detail":"The log records a failed authentication attempt."}]','not_requested','2026-09-26T07:14:23.312950+00:00');
CREATE TABLE health_transitions (
	id VARCHAR(36) NOT NULL,
	probe_id VARCHAR(300) NOT NULL,
	recorded_at VARCHAR(40) NOT NULL,
	health_json TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE TABLE incident_events (
	incident_id VARCHAR(36) NOT NULL,
	event_id VARCHAR(36) NOT NULL,
	occurrence_id VARCHAR(36) NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (incident_id, event_id),
	FOREIGN KEY(incident_id) REFERENCES incidents (id),
	FOREIGN KEY(event_id) REFERENCES events (id) ON DELETE RESTRICT,
	FOREIGN KEY(occurrence_id) REFERENCES incident_occurrences (id)
);
INSERT INTO "incident_events" VALUES('affcf3c7-e0bc-482a-9396-5b740423d054','eb9619fc-58a6-4472-b96f-71a22315a2c6','9c9cec5f-5773-4b02-b112-23b6fc63afcc','{"incident_id":"affcf3c7-e0bc-482a-9396-5b740423d054","event_id":"eb9619fc-58a6-4472-b96f-71a22315a2c6","occurrence_id":"9c9cec5f-5773-4b02-b112-23b6fc63afcc","kind":"anomaly","reason":"Same authentication family, source identity and rule version","linked_at":"2026-09-17T12:00:00Z"}');
CREATE TABLE incident_notes (
	id VARCHAR(36) NOT NULL,
	incident_id VARCHAR(36) NOT NULL,
	supersedes_id VARCHAR(36),
	at VARCHAR(40) NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(incident_id) REFERENCES incidents (id),
	UNIQUE (supersedes_id),
	FOREIGN KEY(supersedes_id) REFERENCES incident_notes (id)
);
INSERT INTO "incident_notes" VALUES('1c8225ba-335a-49af-8966-b45cf9a43bba','affcf3c7-e0bc-482a-9396-5b740423d054',NULL,'2026-09-26T07:14:23.326439+00:00','{"id":"1c8225ba-335a-49af-8966-b45cf9a43bba","incident_id":"affcf3c7-e0bc-482a-9396-5b740423d054","body":"Historical operator investigation","at":"2026-09-26T07:14:23.326439Z","actor":"operator","supersedes_id":null}');
CREATE TABLE incident_occurrences (
	id VARCHAR(36) NOT NULL,
	incident_id VARCHAR(36) NOT NULL,
	number INTEGER NOT NULL,
	started_at VARCHAR(40) NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (incident_id, number),
	FOREIGN KEY(incident_id) REFERENCES incidents (id)
);
INSERT INTO "incident_occurrences" VALUES('9c9cec5f-5773-4b02-b112-23b6fc63afcc','affcf3c7-e0bc-482a-9396-5b740423d054',1,'2026-09-17T12:00:00.000000+00:00','{"id":"9c9cec5f-5773-4b02-b112-23b6fc63afcc","incident_id":"affcf3c7-e0bc-482a-9396-5b740423d054","number":1,"started_at":"2026-09-17T12:00:00Z","last_seen_at":"2026-09-17T12:00:00Z","observation_count":1,"recovered_at":null,"affected_ports":[]}');
CREATE TABLE incident_transitions (
	id VARCHAR(36) NOT NULL,
	incident_id VARCHAR(36) NOT NULL,
	revision INTEGER NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (incident_id, revision),
	FOREIGN KEY(incident_id) REFERENCES incidents (id)
);
INSERT INTO "incident_transitions" VALUES('eb115b23-8221-4074-84ae-b2f2a1103710','affcf3c7-e0bc-482a-9396-5b740423d054',1,'{"id":"eb115b23-8221-4074-84ae-b2f2a1103710","incident_id":"affcf3c7-e0bc-482a-9396-5b740423d054","revision":1,"previous":null,"current":"open","action":"opened","reason":"New anomalous observation","actor":"system","at":"2026-09-17T12:00:00Z"}');
CREATE TABLE incidents (
	id VARCHAR(36) NOT NULL,
	correlation_key VARCHAR(2000) NOT NULL,
	status VARCHAR(20) NOT NULL,
	first_seen_at VARCHAR(40) NOT NULL,
	last_seen_at VARCHAR(40) NOT NULL,
	revision INTEGER NOT NULL,
	rule_version VARCHAR(36) NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(rule_version) REFERENCES rule_versions (id)
);
INSERT INTO "incidents" VALUES('affcf3c7-e0bc-482a-9396-5b740423d054','65b7b856797fd325cc49b56741e7a221a108e8c0bd67ef1c9a83963c5bd70b5d','open','2026-09-17T12:00:00.000000+00:00','2026-09-17T12:00:00.000000+00:00',2,'c27dd04a-4080-4b2d-bdb0-bf8d7642c1bd','{"id":"affcf3c7-e0bc-482a-9396-5b740423d054","correlation_key":"65b7b856797fd325cc49b56741e7a221a108e8c0bd67ef1c9a83963c5bd70b5d","family":"authentication","target":"192.0.2.9","title":"Historical v4 authentication failure","status":"open","first_seen_at":"2026-09-17T12:00:00Z","last_seen_at":"2026-09-17T12:00:00Z","highest_score":25,"occurrence_count":1,"observation_count":1,"revision":2,"rule_version":"c27dd04a-4080-4b2d-bdb0-bf8d7642c1bd","policy_version":1,"reopen_within_seconds":86400,"automatic_resolution":false,"current_occurrence_id":"9c9cec5f-5773-4b02-b112-23b6fc63afcc","resolved_at":null,"last_reopened_at":null,"previous_incident_id":null}');
CREATE TABLE ingest_batches (
	batch_id VARCHAR(36) NOT NULL,
	payload_hash VARCHAR(64) NOT NULL,
	committed_seq INTEGER NOT NULL,
	committed_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (batch_id)
);
INSERT INTO "ingest_batches" VALUES('64ee6bb2-f609-4bc2-9551-44d2680e202f','7cde7303a56458c9a486cc99fc4ebeb3191d722f60aeb0bd113fa21ef4c798f4',1,'2026-09-26T07:14:23.324525+00:00');
CREATE TABLE ingest_gaps (
	id VARCHAR(36) NOT NULL,
	probe_id VARCHAR(200) NOT NULL,
	gap_json TEXT NOT NULL,
	committed_seq INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE TABLE investigations (
	id VARCHAR(36) NOT NULL,
	event_id VARCHAR(36) NOT NULL,
	status VARCHAR(20) NOT NULL,
	assessment_json TEXT,
	usage_json TEXT,
	model_id VARCHAR(200) NOT NULL,
	requested_effort VARCHAR(20) NOT NULL,
	error TEXT,
	created_at VARCHAR(40) NOT NULL,
	completed_at VARCHAR(40),
	PRIMARY KEY (id),
	FOREIGN KEY(event_id) REFERENCES events (id) ON DELETE CASCADE
);
CREATE TABLE probe_checkpoints (
	probe_id VARCHAR(200) NOT NULL,
	revision INTEGER NOT NULL,
	state_json TEXT NOT NULL,
	committed_seq INTEGER NOT NULL,
	updated_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (probe_id)
);
CREATE TABLE probe_health (
	probe_id VARCHAR(300) NOT NULL,
	health_json TEXT NOT NULL,
	PRIMARY KEY (probe_id)
);
CREATE TABLE response_proposals (
	id VARCHAR(36) NOT NULL,
	event_id VARCHAR(36) NOT NULL,
	investigation_id VARCHAR(36) NOT NULL,
	proposal_json TEXT NOT NULL,
	status VARCHAR(20) NOT NULL,
	created_at VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(event_id) REFERENCES events (id) ON DELETE CASCADE,
	FOREIGN KEY(investigation_id) REFERENCES investigations (id) ON DELETE CASCADE
);
CREATE TABLE rule_versions (
	id VARCHAR(36) NOT NULL,
	applied_at VARCHAR(40) NOT NULL,
	snapshot_json TEXT NOT NULL,
	fingerprint VARCHAR(64) NOT NULL,
	PRIMARY KEY (id)
);
INSERT INTO "rule_versions" VALUES('c27dd04a-4080-4b2d-bdb0-bf8d7642c1bd','2026-09-26T07:14:23.317653+00:00','{"config":{"auth_failure_count":6,"firewall_denial_count":10,"ping_degraded_percent":20,"ping_high_loss_percent":50,"ping_sustained_count":4,"points":{"log_auth_burst":75,"log_auth_failure":25,"log_firewall_denial":15,"log_firewall_denial_burst":40,"log_malware_indicator":80,"log_privilege_escalation":45,"ping_degraded":25,"ping_high_loss":45,"ping_sustained_loss":25,"ping_total_loss":70,"port_closed":0,"port_newly_opened":20,"port_open_burst":60,"port_sensitive_exposure":35,"port_sensitive_opened":35},"port_open_count":5,"preset":"balanced","window_seconds":300},"engine_version":2,"parser_version":2}','fcbd412262bc5b3ee7ecd1dad325ca4c9e86308824b2993ecd14d0cb8b81df2b');
CREATE TABLE runs (
	id VARCHAR(36) NOT NULL,
	started_at VARCHAR(40) NOT NULL,
	stopped_at VARCHAR(40),
	version VARCHAR(40) NOT NULL,
	clean_shutdown INTEGER NOT NULL,
	PRIMARY KEY (id)
);
CREATE TABLE schema_meta (
	"key" VARCHAR(80) NOT NULL,
	value VARCHAR(200) NOT NULL,
	PRIMARY KEY ("key")
);
INSERT INTO "schema_meta" VALUES('schema_version','4');
INSERT INTO "schema_meta" VALUES('ingest_sequence','1');
INSERT INTO "schema_meta" VALUES('active_rule_version','c27dd04a-4080-4b2d-bdb0-bf8d7642c1bd');
CREATE TABLE schema_migrations (
	version INTEGER NOT NULL,
	applied_at VARCHAR(40) NOT NULL,
	backup_path TEXT NOT NULL,
	backup_sha256 VARCHAR(64) NOT NULL,
	PRIMARY KEY (version)
);
CREATE TABLE suppression_rules (
	id VARCHAR(36) NOT NULL,
	enabled BOOLEAN NOT NULL,
	starts_at VARCHAR(40) NOT NULL,
	expires_at VARCHAR(40) NOT NULL,
	data_json TEXT NOT NULL,
	PRIMARY KEY (id)
);
CREATE INDEX ix_ingest_gaps_probe_id ON ingest_gaps (probe_id);
CREATE INDEX ix_health_transitions_probe_id ON health_transitions (probe_id);
CREATE INDEX ix_incidents_key_seen ON incidents (correlation_key, last_seen_at);
CREATE INDEX ix_events_observed_at ON events (observed_at);
CREATE INDEX ix_events_severity ON events (severity);
CREATE INDEX ix_events_target ON events (target);
CREATE INDEX ix_events_correlation ON events (rule_version, source, ingested_at);
CREATE UNIQUE INDEX ix_events_source_key ON events (source_key);
CREATE UNIQUE INDEX ix_events_ingest_seq ON events (ingest_seq);
CREATE INDEX ix_events_source ON events (source);
CREATE INDEX ix_incident_notes_incident_id ON incident_notes (incident_id);
CREATE INDEX ix_investigations_status ON investigations (status);
CREATE INDEX ix_investigations_created_at ON investigations (created_at);
CREATE INDEX ix_investigations_event_id ON investigations (event_id);
COMMIT;

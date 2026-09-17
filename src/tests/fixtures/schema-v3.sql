BEGIN TRANSACTION;
CREATE TABLE events (
	id VARCHAR(36) NOT NULL, 
	observed_at VARCHAR(40) NOT NULL, 
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
	created_at VARCHAR(40) NOT NULL, ingest_seq INTEGER, ingested_at VARCHAR(40), source_at VARCHAR(40), source_key VARCHAR(200), outcome VARCHAR(20) NOT NULL DEFAULT 'unknown', observed_quality VARCHAR(30) NOT NULL DEFAULT 'legacy_unknown', ingest_order_origin VARCHAR(30) NOT NULL DEFAULT 'legacy_reconstructed', rule_version VARCHAR(36) REFERENCES rule_versions(id), 
	PRIMARY KEY (id)
);
INSERT INTO "events" VALUES('b7c5570e-a93e-45cc-9fd9-fb48d6c4df17','2026-07-27T12:00:00.000000+00:00','log','log.auth_failure','Repeated SSH authentication failures','Twelve failed root logins were observed in sixty seconds.','8.8.4.4','{"attempts":12,"account":"root"}',95,'critical','[{"code":"auth.burst","label":"Authentication burst","points":95,"detail":"Twelve failures exceeded the configured threshold."}]','failed','2026-07-27T12:00:00.000000+00:00',1,NULL,NULL,NULL,'unknown','legacy_unknown','legacy_reconstructed',NULL);
INSERT INTO "events" VALUES('dd4d3b26-9c28-44c7-bd87-eecb0f57fb2c','2026-07-27T12:00:00.000000+00:00','log','log.auth_failure','Repeated SSH authentication failures','Twelve failed root logins were observed in sixty seconds.','8.8.4.4','{"attempts":12,"account":"root"}',95,'critical','[{"code":"auth.burst","label":"Authentication burst","points":95,"detail":"Twelve failures exceeded the configured threshold."}]','failed','2026-07-27T12:00:00.000000+00:00',2,'2026-09-17T00:00:00.000000+00:00',NULL,NULL,'unknown','recorded','recorded','d710801c-b78d-4c15-b11b-067891e370cc');
CREATE TABLE health_transitions (id VARCHAR(36) PRIMARY KEY NOT NULL, probe_id VARCHAR(300) NOT NULL, recorded_at VARCHAR(40) NOT NULL, health_json TEXT NOT NULL);
CREATE TABLE ingest_batches (batch_id VARCHAR(36) PRIMARY KEY NOT NULL, payload_hash VARCHAR(64) NOT NULL, committed_seq INTEGER NOT NULL, committed_at VARCHAR(40) NOT NULL);
CREATE TABLE ingest_gaps (id VARCHAR(36) PRIMARY KEY NOT NULL, probe_id VARCHAR(200) NOT NULL, gap_json TEXT NOT NULL, committed_seq INTEGER NOT NULL);
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
INSERT INTO "investigations" VALUES('00000000-0000-0000-0000-000000000001','b7c5570e-a93e-45cc-9fd9-fb48d6c4df17','complete','{"classification":"critical","confidence":0.97,"summary":"The source is likely attacking SSH.","rationale":["Repeated root authentication failures exceeded the local threshold."],"recommended_actions":["Confirm the source and review the proposed block."],"response_proposal":{"action":"block","target_ip":"8.8.4.4","reason":"Repeated SSH authentication failures","command":null,"platform":null,"reversible":true,"requires_approval":true}}','{"prompt_tokens":120,"completion_tokens":40,"reasoning_tokens":20,"total_tokens":160,"cost_usd":0.0042,"latency_ms":810,"provider_request_id":"capture-request"}','gpt-5.6-luna','high',NULL,'2026-07-27T12:00:00.000000+00:00','2026-07-27T12:00:00.000000+00:00');
INSERT INTO "investigations" VALUES('00000000-0000-0000-0000-000000000003','b7c5570e-a93e-45cc-9fd9-fb48d6c4df17','failed',NULL,NULL,'gpt-5.6-luna','high','Synthetic legacy failure','2026-07-27T12:00:00.000000+00:00','2026-07-27T12:00:00.000000+00:00');
CREATE TABLE probe_checkpoints (probe_id VARCHAR(200) PRIMARY KEY NOT NULL, revision INTEGER NOT NULL, state_json TEXT NOT NULL, committed_seq INTEGER NOT NULL, updated_at VARCHAR(40) NOT NULL);
CREATE TABLE probe_health (probe_id VARCHAR(300) PRIMARY KEY NOT NULL, health_json TEXT NOT NULL);
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
INSERT INTO "response_proposals" VALUES('00000000-0000-0000-0000-000000000002','b7c5570e-a93e-45cc-9fd9-fb48d6c4df17','00000000-0000-0000-0000-000000000001','{"action":"block","target_ip":"8.8.4.4","reason":"Repeated SSH authentication failures","command":null,"platform":null,"reversible":true,"requires_approval":true}','approved','2026-07-27T12:00:00.000000+00:00');
CREATE TABLE rule_versions (id VARCHAR(36) PRIMARY KEY NOT NULL, applied_at VARCHAR(40) NOT NULL, snapshot_json TEXT NOT NULL, fingerprint VARCHAR(64) NOT NULL);
INSERT INTO "rule_versions" VALUES('d710801c-b78d-4c15-b11b-067891e370cc','2026-09-17T00:00:00.000000+00:00','{"config":{"auth_failure_count":6,"firewall_denial_count":10,"ping_degraded_percent":20,"ping_high_loss_percent":50,"ping_sustained_count":4,"points":{"log_auth_burst":75,"log_auth_failure":25,"log_firewall_denial":15,"log_firewall_denial_burst":40,"log_malware_indicator":80,"log_privilege_escalation":45,"ping_degraded":25,"ping_high_loss":45,"ping_sustained_loss":25,"ping_total_loss":70,"port_closed":0,"port_newly_opened":20,"port_open_burst":60,"port_sensitive_exposure":35,"port_sensitive_opened":35},"port_open_count":5,"preset":"balanced","window_seconds":300},"engine_version":2,"parser_version":2}','fcbd412262bc5b3ee7ecd1dad325ca4c9e86308824b2993ecd14d0cb8b81df2b');
CREATE TABLE runs (
	id VARCHAR(36) NOT NULL, 
	started_at VARCHAR(40) NOT NULL, 
	stopped_at VARCHAR(40), 
	version VARCHAR(40) NOT NULL, 
	clean_shutdown INTEGER NOT NULL, 
	PRIMARY KEY (id)
);
INSERT INTO "runs" VALUES('00000000-0000-0000-0000-000000000004','2026-07-27T12:00:00.000000+00:00','2026-07-27T12:00:00.000000+00:00','0.3.0',1);
INSERT INTO "runs" VALUES('00000000-0000-0000-0000-000000000005','2026-07-27T12:00:00.000000+00:00',NULL,'0.3.0',0);
CREATE TABLE schema_meta (
	"key" VARCHAR(80) NOT NULL, 
	value VARCHAR(200) NOT NULL, 
	PRIMARY KEY ("key")
);
INSERT INTO "schema_meta" VALUES('schema_version','3');
INSERT INTO "schema_meta" VALUES('ingest_sequence','2');
INSERT INTO "schema_meta" VALUES('active_rule_version','d710801c-b78d-4c15-b11b-067891e370cc');
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY NOT NULL, applied_at VARCHAR(40) NOT NULL, backup_path TEXT NOT NULL, backup_sha256 VARCHAR(64) NOT NULL);
CREATE INDEX ix_events_target ON events (target);
CREATE INDEX ix_events_observed_at ON events (observed_at);
CREATE INDEX ix_events_source ON events (source);
CREATE INDEX ix_events_severity ON events (severity);
CREATE INDEX ix_investigations_event_id ON investigations (event_id);
CREATE INDEX ix_investigations_created_at ON investigations (created_at);
CREATE INDEX ix_investigations_status ON investigations (status);
CREATE TRIGGER events_require_sequence_insert BEFORE INSERT ON events WHEN NEW.ingest_seq IS NULL OR NEW.ingest_seq <= 0 BEGIN SELECT RAISE(ABORT, 'ingest_seq must be positive'); END;
CREATE TRIGGER events_require_sequence_update BEFORE UPDATE OF ingest_seq ON events WHEN NEW.ingest_seq IS NULL OR NEW.ingest_seq <= 0 BEGIN SELECT RAISE(ABORT, 'ingest_seq must be positive'); END;
CREATE UNIQUE INDEX ix_events_ingest_seq ON events (ingest_seq);
CREATE UNIQUE INDEX ix_events_source_key ON events (source_key);
CREATE INDEX ix_ingest_gaps_probe_id ON ingest_gaps (probe_id);
CREATE INDEX ix_health_transitions_probe_id ON health_transitions (probe_id);
CREATE INDEX ix_events_correlation ON events (rule_version, source, ingested_at);
COMMIT;

CREATE TABLE provider_connections (
  id text NOT NULL,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  provider_id text NOT NULL CHECK (provider_id <> ''),
  external_account_id text NOT NULL CHECK (external_account_id <> ''),
  display_name text NOT NULL CHECK (display_name <> ''),
  secret_ref text NOT NULL CHECK (secret_ref <> ''),
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata_json) = 'object'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, provider_id, external_account_id)
);

CREATE INDEX provider_connections_tenant_provider_status_idx
  ON provider_connections (tenant_id, provider_id, status);

CREATE TABLE provider_connection_resources (
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  connection_id text NOT NULL,
  provider_resource_id text NOT NULL CHECK (provider_resource_id <> ''),
  display_name text NOT NULL CHECK (display_name <> ''),
  selector_json jsonb NOT NULL CHECK (jsonb_typeof(selector_json) = 'object'),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
  PRIMARY KEY (tenant_id, connection_id, provider_resource_id),
  FOREIGN KEY (tenant_id, connection_id)
    REFERENCES provider_connections (tenant_id, id)
);

CREATE TABLE approval_requests (
  id text NOT NULL,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  expected_principal_id text NOT NULL CHECK (expected_principal_id <> ''),
  agent_id text NOT NULL CHECK (agent_id <> ''),
  workload_id text NOT NULL CHECK (workload_id <> ''),
  workflow_id text NOT NULL CHECK (workflow_id <> ''),
  mcp_session_hash text NOT NULL CHECK (mcp_session_hash ~ '^[A-Za-z0-9_-]{43}$'),
  profile_id text NOT NULL CHECK (profile_id <> ''),
  profile_hash text NOT NULL CHECK (profile_hash ~ '^[A-Za-z0-9_-]{43}$'),
  provider_id text NOT NULL CHECK (provider_id <> ''),
  provider_connection_id text NOT NULL CHECK (provider_connection_id <> ''),
  provider_resource_id text NOT NULL CHECK (provider_resource_id <> ''),
  envelope_json jsonb NOT NULL CHECK (jsonb_typeof(envelope_json) = 'object'),
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^[A-Za-z0-9_-]{43}$'),
  intent_version text NOT NULL CHECK (intent_version = 'am.approval-intent.v1'),
  intent_json jsonb NOT NULL CHECK (jsonb_typeof(intent_json) = 'object'),
  intent_hash text NOT NULL CHECK (intent_hash ~ '^[A-Za-z0-9_-]{43}$'),
  resume_handle_hash text NOT NULL CHECK (resume_handle_hash ~ '^[A-Za-z0-9_-]{43}$'),
  idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
  execution_status text NOT NULL DEFAULT 'not_started' CHECK (
    execution_status IN ('not_started', 'reserved', 'dispatching', 'succeeded', 'failed', 'ambiguous')
  ),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
  decided_at timestamptz,
  decided_by text,
  authenticated_at timestamptz,
  decision_reason text,
  mandate_id text,
  receipt_id text,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, resume_handle_hash),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, provider_connection_id)
    REFERENCES provider_connections (tenant_id, id),
  FOREIGN KEY (tenant_id, provider_connection_id, provider_resource_id)
    REFERENCES provider_connection_resources (tenant_id, connection_id, provider_resource_id),
  CHECK (
    (status = 'pending' AND decided_at IS NULL AND decided_by IS NULL)
    OR (status = 'approved' AND decided_at IS NOT NULL AND decided_by IS NOT NULL)
    OR (status = 'denied' AND decided_at IS NOT NULL AND decided_by IS NOT NULL)
    OR (status IN ('expired', 'cancelled'))
  ),
  CHECK (authenticated_at IS NULL OR authenticated_at <= decided_at),
  CHECK (mandate_id IS NULL OR status = 'approved')
);

CREATE INDEX approval_requests_tenant_status_expiry_idx
  ON approval_requests (tenant_id, status, expires_at);
CREATE INDEX approval_requests_tenant_principal_created_idx
  ON approval_requests (tenant_id, expected_principal_id, created_at DESC);
CREATE INDEX approval_requests_tenant_execution_idx
  ON approval_requests (tenant_id, execution_status, created_at)
  WHERE execution_status IN ('reserved', 'dispatching', 'ambiguous');

ALTER TABLE agent_mandates
  ADD COLUMN approval_request_id text;

ALTER TABLE agent_mandates
  ADD CONSTRAINT agent_mandates_approval_request_fk
  FOREIGN KEY (tenant_id, approval_request_id)
  REFERENCES approval_requests (tenant_id, id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX agent_mandates_tenant_approval_request_uidx
  ON agent_mandates (tenant_id, approval_request_id)
  WHERE approval_request_id IS NOT NULL;

ALTER TABLE approval_requests
  ADD CONSTRAINT approval_requests_mandate_fk
  FOREIGN KEY (tenant_id, mandate_id)
  REFERENCES agent_mandates (tenant_id, id)
  DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE approval_requests
  ADD CONSTRAINT approval_requests_receipt_fk
  FOREIGN KEY (tenant_id, receipt_id)
  REFERENCES execution_receipts (tenant_id, id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE approval_events (
  id text PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  request_id text NOT NULL,
  sequence integer NOT NULL CHECK (sequence > 0),
  type text NOT NULL CHECK (type IN ('requested', 'approved', 'denied', 'expired', 'cancelled', 'execution.updated')),
  at timestamptz NOT NULL,
  principal_id text,
  intent_hash text NOT NULL CHECK (intent_hash ~ '^[A-Za-z0-9_-]{43}$'),
  snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
  UNIQUE (tenant_id, request_id, sequence),
  FOREIGN KEY (tenant_id, request_id)
    REFERENCES approval_requests (tenant_id, id)
);

CREATE INDEX approval_events_tenant_request_idx
  ON approval_events (tenant_id, request_id, sequence);

CREATE TRIGGER approval_events_append_only
  BEFORE UPDATE OR DELETE ON approval_events
  FOR EACH ROW EXECUTE FUNCTION reject_receipt_integrity_event_mutation();

CREATE TRIGGER approval_events_no_truncate
  BEFORE TRUNCATE ON approval_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_receipt_integrity_event_mutation();

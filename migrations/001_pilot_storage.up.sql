CREATE TABLE agent_mandates (
  id text PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  principal_id text NOT NULL CHECK (principal_id <> ''),
  agent_id text NOT NULL CHECK (agent_id <> ''),
  workload_id text NOT NULL CHECK (workload_id <> ''),
  task_id text NOT NULL CHECK (task_id <> ''),
  audience text NOT NULL CHECK (audience <> ''),
  actions text[] NOT NULL CHECK (cardinality(actions) > 0),
  resources text[] NOT NULL CHECK (cardinality(resources) > 0),
  expires_in_seconds integer NOT NULL CHECK (expires_in_seconds > 0),
  constraints_json jsonb,
  approval_json jsonb,
  parent_mandate_id text,
  grant_hash text NOT NULL CHECK (grant_hash ~ '^[A-Za-z0-9_-]{43}$'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
  revoked_at timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  successful_uses integer NOT NULL DEFAULT 0 CHECK (successful_uses >= 0),
  delegated_calls integer NOT NULL DEFAULT 0 CHECK (delegated_calls >= 0),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, parent_mandate_id)
    REFERENCES agent_mandates (tenant_id, id)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK (
    (status = 'active' AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL)
  ),
  CHECK (constraints_json IS NULL OR jsonb_typeof(constraints_json) = 'object'),
  CHECK (approval_json IS NULL OR jsonb_typeof(approval_json) = 'object')
);

CREATE INDEX agent_mandates_tenant_status_expiry_idx
  ON agent_mandates (tenant_id, status, expires_at);
CREATE INDEX agent_mandates_tenant_principal_issued_idx
  ON agent_mandates (tenant_id, principal_id, issued_at DESC);

CREATE TABLE execution_receipts (
  id text PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  mandate_id text NOT NULL,
  decision_id text NOT NULL CHECK (decision_id <> ''),
  principal_id text NOT NULL CHECK (principal_id <> ''),
  agent_id text NOT NULL CHECK (agent_id <> ''),
  workload_id text NOT NULL CHECK (workload_id <> ''),
  task_id text NOT NULL CHECK (task_id <> ''),
  audience text NOT NULL CHECK (audience <> ''),
  action text NOT NULL CHECK (action <> ''),
  resource text NOT NULL CHECK (resource <> ''),
  envelope_version text NOT NULL CHECK (envelope_version = 'am.action.v1'),
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^[A-Za-z0-9_-]{43}$'),
  idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
  outcome text NOT NULL CHECK (outcome IN ('pending', 'succeeded', 'failed', 'ambiguous')),
  downstream_status integer CHECK (downstream_status BETWEEN 100 AND 599),
  result_hash text CHECK (result_hash ~ '^[A-Za-z0-9_-]{43}$'),
  previous_receipt_hash text CHECK (previous_receipt_hash ~ '^[A-Za-z0-9_-]{43}$'),
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^[A-Za-z0-9_-]{43}$'),
  integrity_sequence integer NOT NULL DEFAULT 1 CHECK (integrity_sequence > 0),
  attempt_count integer NOT NULL DEFAULT 1 CHECK (attempt_count > 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, mandate_id, idempotency_key),
  FOREIGN KEY (tenant_id, mandate_id)
    REFERENCES agent_mandates (tenant_id, id)
);

CREATE INDEX execution_receipts_tenant_created_idx
  ON execution_receipts (tenant_id, created_at DESC, id DESC);
CREATE INDEX execution_receipts_tenant_mandate_created_idx
  ON execution_receipts (tenant_id, mandate_id, created_at DESC);
CREATE INDEX execution_receipts_tenant_outcome_updated_idx
  ON execution_receipts (tenant_id, outcome, updated_at)
  WHERE outcome IN ('pending', 'ambiguous');

-- Immutable receipt-state snapshots. Every reservation and completion appends
-- one event, so the current projection can change without rewriting evidence.
CREATE TABLE receipt_integrity_events (
  id text PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  receipt_id text NOT NULL,
  chain_sequence bigint NOT NULL CHECK (chain_sequence > 0),
  receipt_sequence integer NOT NULL CHECK (receipt_sequence > 0),
  previous_event_hash text CHECK (previous_event_hash ~ '^[A-Za-z0-9_-]{43}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[A-Za-z0-9_-]{43}$'),
  snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, chain_sequence),
  UNIQUE (tenant_id, receipt_id, receipt_sequence),
  FOREIGN KEY (tenant_id, receipt_id)
    REFERENCES execution_receipts (tenant_id, id)
);

CREATE INDEX receipt_integrity_events_tenant_receipt_idx
  ON receipt_integrity_events (tenant_id, receipt_id, receipt_sequence);

CREATE FUNCTION reject_receipt_integrity_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'evidence events are append-only';
END
$$;

CREATE TRIGGER receipt_integrity_events_append_only
  BEFORE UPDATE OR DELETE ON receipt_integrity_events
  FOR EACH ROW EXECUTE FUNCTION reject_receipt_integrity_event_mutation();

CREATE TRIGGER receipt_integrity_events_no_truncate
  BEFORE TRUNCATE ON receipt_integrity_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_receipt_integrity_event_mutation();

-- This one-row-per-tenant head is locked while appending a receipt. It prevents
-- concurrent mandates from forking a tenant's hash chain.
CREATE TABLE receipt_chain_heads (
  tenant_id text PRIMARY KEY CHECK (tenant_id <> ''),
  chain_sequence bigint NOT NULL DEFAULT 0 CHECK (chain_sequence >= 0),
  receipt_id text,
  receipt_hash text CHECK (receipt_hash ~ '^[A-Za-z0-9_-]{43}$'),
  FOREIGN KEY (tenant_id, receipt_id)
    REFERENCES execution_receipts (tenant_id, id),
  CHECK (
    (receipt_id IS NULL AND receipt_hash IS NULL)
    OR (receipt_id IS NOT NULL AND receipt_hash IS NOT NULL)
  )
);

CREATE TABLE audit_events (
  id text PRIMARY KEY,
  tenant_id text NOT NULL CHECK (tenant_id <> ''),
  at timestamptz NOT NULL,
  type text NOT NULL CHECK (type IN (
    'mandate.issued',
    'mandate.revoked',
    'action.allowed',
    'action.denied',
    'execution.succeeded',
    'execution.failed',
    'execution.ambiguous'
  )),
  mandate_id text,
  decision_id text,
  principal_id text,
  agent_id text,
  workload_id text,
  task_id text,
  audience text,
  action text,
  resource text,
  envelope_hash text CHECK (envelope_hash ~ '^[A-Za-z0-9_-]{43}$'),
  idempotency_key text,
  code text NOT NULL CHECK (code IN (
    'allowed', 'invalid_request', 'missing_identity_or_context',
    'invalid_principal', 'invalid_workload_identity', 'tenant_mismatch',
    'invalid_grant', 'revoked', 'expired', 'agent_mismatch',
    'workload_mismatch', 'task_mismatch', 'audience_mismatch',
    'action_not_granted', 'resource_not_granted', 'parameter_mismatch',
    'call_limit_exceeded', 'approval_required', 'approval_mismatch',
    'delegation_amplification', 'replay_detected', 'idempotency_conflict',
    'policy_denied', 'policy_indeterminate', 'downstream_audience_mismatch',
    'downstream_failed', 'downstream_ambiguous', 'issued', 'revoked', 'executed'
  )),
  details jsonb,
  CHECK (details IS NULL OR jsonb_typeof(details) = 'object')
);

CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_receipt_integrity_event_mutation();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_receipt_integrity_event_mutation();

CREATE INDEX audit_events_tenant_at_idx
  ON audit_events (tenant_id, at DESC, id DESC);
CREATE INDEX audit_events_tenant_mandate_at_idx
  ON audit_events (tenant_id, mandate_id, at DESC)
  WHERE mandate_id IS NOT NULL;
CREATE INDEX audit_events_tenant_decision_idx
  ON audit_events (tenant_id, decision_id)
  WHERE decision_id IS NOT NULL;

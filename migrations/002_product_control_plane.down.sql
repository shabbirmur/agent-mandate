DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM approval_events LIMIT 1)
     OR EXISTS (SELECT 1 FROM approval_requests LIMIT 1)
     OR EXISTS (SELECT 1 FROM provider_connections LIMIT 1)
     OR EXISTS (SELECT 1 FROM provider_connection_resources LIMIT 1) THEN
    RAISE EXCEPTION 'refusing to delete product approval/provider evidence';
  END IF;
END
$$;

DROP TRIGGER approval_events_no_truncate ON approval_events;
DROP TRIGGER approval_events_append_only ON approval_events;
DROP TABLE approval_events;

ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_receipt_fk;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_mandate_fk;
DROP INDEX agent_mandates_tenant_approval_request_uidx;
ALTER TABLE agent_mandates DROP CONSTRAINT agent_mandates_approval_request_fk;
ALTER TABLE agent_mandates DROP COLUMN approval_request_id;

DROP TABLE approval_requests;
DROP TABLE provider_connection_resources;
DROP TABLE provider_connections;

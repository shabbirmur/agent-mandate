-- EVIDENCE-RETENTION WARNING
-- This down migration destroys mandate state, execution receipts, and audit
-- evidence. It is only safe for an empty development schema. A pilot rollback
-- must retain these tables (or first export and verify them from a database
-- backup) and normally rolls back application code without running this file.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM audit_events LIMIT 1)
     OR EXISTS (SELECT 1 FROM execution_receipts LIMIT 1)
     OR EXISTS (SELECT 1 FROM receipt_integrity_events LIMIT 1) THEN
    RAISE EXCEPTION
      'refusing to delete audit/receipt evidence; retain or export verified evidence before schema teardown';
  END IF;
END
$$;

DROP TABLE audit_events;
DROP TABLE receipt_chain_heads;
DROP TRIGGER receipt_integrity_events_no_truncate ON receipt_integrity_events;
DROP TRIGGER receipt_integrity_events_append_only ON receipt_integrity_events;
DROP FUNCTION reject_receipt_integrity_event_mutation();
DROP TABLE receipt_integrity_events;
DROP TABLE execution_receipts;
DROP TABLE agent_mandates;

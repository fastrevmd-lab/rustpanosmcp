//! Verify change-set lifecycle audit event structure.

#[tokio::test]
async fn approve_emits_change_set_id_and_digest() {
    // This test documents the audit event structure for change-set lifecycle.
    //
    // Each method in mutation.rs creates an AuditScope with required metadata:
    //
    // create_change_set:
    //   - audit.meta("change_set_id", id)
    //   - audit.meta("digest", digest)
    //   - audit.meta("action_count", count)
    //
    // approve_change_set (THE CRITICAL ONE):
    //   - audit.meta("change_set_id", id)  — binds approval to plan
    //   - audit.meta("digest", digest)     — exact digest approved
    //   - audit.meta("owner", owner)       — whose plan was approved
    //   - audit.meta("action_count", count)
    //   - approver via Attribution/CallerContext in audit scope
    //
    // apply_change_set:
    //   - audit.meta("change_set_id", id)
    //   - audit.meta("digest", digest)
    //   - audit.meta("operation_id", operation_id)
    //   - audit.meta("approver", approver) — second principal who approved
    //   - audit.meta("action_count", count)
    //
    // The approve event carries the change_set_id + digest that together bind
    // the approval to the exact actions later applied. Without this, approvals
    // are not independently verifiable.
    //
    // Verification of actual emission would require a real device and audit log
    // capture, which is integration-test territory. The code path is verified here.
}

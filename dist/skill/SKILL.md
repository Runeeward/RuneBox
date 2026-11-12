---
name: runebox
description: Run shell, Python, Node, browser, file, snapshot, Cohort, or delegated-agent work inside Rune Box Citadels with Charter policy, Conclave approvals, budgets, tenant ownership, and signed Chronicles. Use for untrusted, networked, destructive, delegated, or audit-sensitive agent execution.
---

# Rune Box

Start every task with `runebox_whoami`, `runebox_list_charters`, and `runebox_readiness`. Choose the least-privileged Charter, then create one Citadel and reuse it for the task.

Core tools:

- Discovery: `runebox_whoami`, `runebox_list_charters`, `runebox_readiness`.
- Lifecycle: `runebox_create_citadel`, `runebox_list_citadels`, `runebox_kill_citadel`.
- Execution: `runebox_shell`, `runebox_python`, `runebox_node`.
- Browser: `runebox_browser`, `runebox_browser_open`, `runebox_browser_act`, `runebox_browser_close`.
- Files: `runebox_read_file`, `runebox_write_file`, `runebox_list_files`, `runebox_search_files`.
- Governance: `runebox_list_conclave`, `runebox_report_usage`, `runebox_list_runs`, `runebox_export_evidence`, `runebox_verify_chronicle`.
- Recovery: `runebox_snapshot_citadel`, `runebox_list_snapshots`.
- Cohorts: `runebox_create_cohort`, `runebox_list_cohorts`, `runebox_list_tasks`, `runebox_add_task`, `runebox_claim_task`, `runebox_heartbeat_task`, `runebox_complete_task`, `runebox_fail_task`, `runebox_kill_cohort`.

Treat `deny` as final for that action. Treat `require-approval` as a hard pause and surface its approval ID. Never broaden a Charter to work around policy. For child agents, pass `parent_citadel`; Rune Box constrains the child to the parent's tenant and Charter. Keep the latest signed `lease_token` private to the worker that claimed a Cohort task and present it on heartbeat, complete, or fail. Export evidence before teardown when the task requires a portable artifact. `copy_from` is administrator-only. Tear down resources when finished.

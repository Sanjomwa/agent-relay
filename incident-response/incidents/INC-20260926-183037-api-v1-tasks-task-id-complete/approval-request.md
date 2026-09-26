# Approval requested: INC-20260926-183037-api-v1-tasks-task-id-complete

The policy allows `rollback` (level L1) **only after explicit human approval**.
Command that would run (runbook script, validated arguments, nothing else): `rollback.sh 20260926-181002-829513a`

Preconditions at decision time:
- PASS alert_still_firing: alert is still firing (observed in Prometheus)
- PASS target_is_previous_version: target_version equals previous_version 20260926-181002-829513a
- PASS target_image_exists_locally: image agent-relay:20260926-181002-829513a exists locally
- PASS current_deployed_within_max_age: running version was deployed 0:03:09.406879 ago (<= 24h)
- PASS no_recent_rollback: no rollback executed in the last 30 minutes
- PASS under_action_limit: 0 of 1 allowed actions executed in this incident

To approve (every precondition is re-checked at approval time): `uv run incident-response/respond.py approve INC-20260926-183037-api-v1-tasks-task-id-complete --yes`
To decline: do nothing, or escalate manually.

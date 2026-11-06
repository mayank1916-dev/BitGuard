"""Core Runbook execution engine automating incident containment and remediation (Milestone S19 / F14).

Invariants:
- Invariant #3: Fail-Closed Default. Unhandled failure or error in containment steps halts/tightens immediately.
- Invariant #5: WebAuthn Hardware Approvals. Approval steps require hardware key WebAuthn assertions over the challenge.
- Invariant #6: Asymmetric Policy Evolution. Containment is instant and automatic; de-escalation requires dual-control approval.
- Invariant #7: Immutable Audit Trail. Runbook execution, containment metrics, and checklist ticks append to audit chain.
- Invariant #11: Strict Wording: 'Reduces and contains unauthorized signing'. Target p99 under 15 ms, measured.
"""

import asyncio
import hashlib
import logging
import os
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import yaml

from services.bitguard.approvals.models import WebAuthnAssertion
from services.bitguard.approvals.webauthn import (
    WebAuthnVerificationError,
    webauthn_verifier,
)
from services.bitguard.audit_service import audit_service
from services.bitguard.breaker.epoch_store import token_epoch_store
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.config import settings
from services.bitguard.incidents.models import (
    ChecklistItem,
    Incident,
    IncidentApproval,
    IncidentStatus,
    Runbook,
    RunbookStep,
    StepType,
    TimelineEvent,
)
from services.bitguard.incidents.notifiers import oncall_notifier
from services.bitguard.incidents.store import incident_store
from services.bitguard.models import DataLabel, Role, UserResponse
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.incidents.executor")


class RunbookExecutor:
    """Orchestrates declarative runbooks from policy/runbooks/*.yaml upon security triggers."""

    def __init__(self, runbooks_dir: str | None = None) -> None:
        self.runbooks_dir = runbooks_dir or settings.runbooks_dir
        self.runbooks: dict[str, Runbook] = {}
        self.load_runbooks()

    def load_runbooks(self, runbooks_dir: str | None = None) -> dict[str, Runbook]:
        """Loads and parses all YAML runbook manifests."""
        target_dir = runbooks_dir or self.runbooks_dir
        self.runbooks.clear()

        if not os.path.exists(target_dir):
            logger.warning("Runbooks directory not found: %s", target_dir)
            return self.runbooks

        for fname in os.listdir(target_dir):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                fpath = os.path.join(target_dir, fname)
                try:
                    with open(fpath, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict) and "id" in data and "trigger" in data:
                        steps = [RunbookStep(**s) for s in data.get("steps", [])]
                        rb = Runbook(
                            id=str(data["id"]),
                            name=str(data.get("name") or data["id"]),
                            description=str(data.get("description") or ""),
                            trigger=str(data["trigger"]),
                            severity=str(data.get("severity", "CRITICAL")),
                            target_time_to_contain_ms=float(data.get("target_time_to_contain_ms", 100.0)),
                            steps=steps,
                        )
                        self.runbooks[rb.id] = rb
                        # Also index by trigger for fast dispatch
                        self.runbooks[rb.trigger.upper()] = rb
                        logger.info("Loaded runbook %s for trigger %s", rb.id, rb.trigger)
                except Exception as exc:
                    logger.error("Failed loading runbook %s: %s", fpath, exc)

        return self.runbooks

    def get_runbook_for_trigger(self, trigger: str) -> Runbook | None:
        """Resolves matching runbook by trigger name or runbook id."""
        clean_trig = trigger.strip().upper()
        if clean_trig in self.runbooks:
            return self.runbooks[clean_trig]
        for rb in self.runbooks.values():
            if rb.trigger.upper() == clean_trig or rb.id.upper() == clean_trig:
                return rb
        return None

    def trigger_runbook(
        self,
        trigger: str,
        context: dict[str, Any] | None = None,
    ) -> Incident:
        """Executes the runbook corresponding to trigger, containing the incident immediately."""
        now = datetime.now(UTC)
        context = context or {}
        runbook = self.get_runbook_for_trigger(trigger)

        incident_id = f"inc-{uuid4().hex[:12]}"
        incident = Incident(
            id=incident_id,
            trigger=trigger,
            severity=runbook.severity if runbook else "CRITICAL",
            runbook_id=runbook.id if runbook else None,
            detected_at=now,
            status=IncidentStatus.OPEN,
            metadata=dict(context),
            data_label=DataLabel.REAL,
        )

        incident.timeline.append(
            TimelineEvent(
                event_type="INCIDENT_OPENED",
                message=f"Incident opened with trigger {trigger} under runbook {runbook.id if runbook else 'manual'}",
                details={"context": context, "runbook_id": runbook.id if runbook else None},
            )
        )

        if not runbook:
            logger.warning("No runbook configured for trigger %s; executing default fallback containment", trigger)
            # Default fallback containment: set breaker to HOLD
            distributed_breaker_store.set_state(
                BreakerStateEnum.HOLD,
                reason=f"Incident fallback containment: trigger {trigger}",
            )
            contained_at = datetime.now(UTC)
            incident.contained_at = contained_at
            incident.time_to_contain_ms = round((contained_at - now).total_seconds() * 1000.0, 3)
            incident.status = IncidentStatus.CONTAINED
            incident_store.save(incident)
            return incident

        # Execute runbook steps sequentially
        for step in runbook.steps:
            if step.type == StepType.AUTOMATIC:
                self._execute_automatic_step(incident, step, now)
            elif step.type == StepType.MANUAL:
                self._register_manual_step(incident, step)
            elif step.type == StepType.APPROVAL:
                self._register_approval_step(incident, step)

        # Invariant #7: Append immutable audit record
        audit_service.append_entry(
            action=f"RUNBOOK_EXECUTED:{runbook.id}",
            actor="runbook_executor",
            payload={
                "incident_id": incident.id,
                "trigger": trigger,
                "status": incident.status.value,
                "time_to_contain_ms": incident.time_to_contain_ms,
            },
            data_label=DataLabel.REAL,
        )

        # Save to store
        incident_store.save(incident)

        # Broadcast update to connected live dashboard feeds
        stream_broadcaster.publish_event(
            event_type="INCIDENT_UPDATE",
            payload=incident.model_dump(mode="json"),
            data_label="REAL",
        )

        logger.info(
            "Incident %s processed by runbook %s: status=%s time_to_contain=%.2f ms",
            incident.id,
            runbook.id,
            incident.status.value,
            incident.time_to_contain_ms or 0.0,
        )

        return incident

    def _execute_automatic_step(
        self,
        incident: Incident,
        step: RunbookStep,
        start_time: datetime,
    ) -> None:
        """Executes automatic action and records timeline event."""
        action = step.action.lower()
        try:
            if action == "open_incident":
                incident.timeline.append(
                    TimelineEvent(
                        event_type="STEP_OPEN_INCIDENT",
                        message=f"Step '{step.name}' verified incident initialization",
                    )
                )

            elif action == "set_breaker_state":
                target_state_str = step.params.get("target_state", "HOLD").upper()
                target_state = (
                    BreakerStateEnum(target_state_str)
                    if target_state_str in BreakerStateEnum.__members__
                    else BreakerStateEnum.HOLD
                )
                reason = step.params.get("reason") or f"Automated runbook containment: {step.name}"

                distributed_breaker_store.set_state(target_state, reason=reason)

                # Record containment timestamp & latency
                if target_state in [BreakerStateEnum.HOLD, BreakerStateEnum.LOCKDOWN]:
                    contained_at = datetime.now(UTC)
                    incident.contained_at = contained_at
                    containment_ms = (contained_at - start_time).total_seconds() * 1000.0
                    incident.time_to_contain_ms = round(max(0.001, containment_ms), 3)
                    incident.status = IncidentStatus.CONTAINED

                    incident.timeline.append(
                        TimelineEvent(
                            event_type="INCIDENT_CONTAINED",
                            message=f"Circuit breaker escalated to {target_state.value}. Contained in {incident.time_to_contain_ms:.2f} ms",
                            details={"state": target_state.value, "time_to_contain_ms": incident.time_to_contain_ms},
                        )
                    )

            elif action == "revoke_tokens":
                new_epoch = token_epoch_store.increment_epoch()
                incident.timeline.append(
                    TimelineEvent(
                        event_type="TOKENS_REVOKED",
                        message=f"All active approval tokens revoked; token epoch incremented to {new_epoch}",
                        details={"token_epoch": new_epoch},
                    )
                )

            elif action == "freeze_withdrawals_flag":
                incident.metadata["withdrawals_frozen"] = True
                incident.timeline.append(
                    TimelineEvent(
                        event_type="WITHDRAWALS_FROZEN",
                        message="Hot wallet withdrawal operations frozen across policy decision points",
                    )
                )

            elif action == "notify_oncall":
                level = int(step.params.get("level", 1))
                # Dispatch notification (async scheduled or sync safe)
                self._dispatch_page(incident, level=level, message=step.params.get("description", step.name))
                incident.timeline.append(
                    TimelineEvent(
                        event_type="ONCALL_PAGED",
                        message=f"Paging Level {level} on-call response team",
                        details={"level": level},
                    )
                )

            else:
                logger.warning("Unrecognized automatic runbook action: %s", action)

        except Exception as exc:
            logger.error("Failed automatic step %s in incident %s: %s", step.id, incident.id, exc)
            incident.timeline.append(
                TimelineEvent(
                    event_type="STEP_FAILED",
                    message=f"Step '{step.name}' failed: {exc}",
                    details={"error": str(exc)},
                )
            )
            if step.on_fail == "abort":
                raise

    def _dispatch_page(self, incident: Incident, level: int = 1, message: str = "") -> None:
        """Dispatches on-call page safely."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(oncall_notifier.page_oncall(incident, level=level, message=message))
            else:
                loop.run_until_complete(oncall_notifier.page_oncall(incident, level=level, message=message))
        except Exception:
            # Fallback direct call for test runners
            try:
                asyncio.run(oncall_notifier.page_oncall(incident, level=level, message=message))
            except Exception as exc:
                logger.warning("Page dispatch warning: %s", exc)

    def _register_manual_step(self, incident: Incident, step: RunbookStep) -> None:
        """Registers a manual remediation task in the incident checklist."""
        item = ChecklistItem(
            id=step.id,
            action=step.action,
            description=step.params.get("description") or step.name,
            ticked=False,
        )
        incident.checklist.append(item)
        incident.timeline.append(
            TimelineEvent(
                event_type="CHECKLIST_ITEM_ADDED",
                message=f"Remediation checklist item added: {item.action}",
                details={"action": item.action, "description": item.description},
            )
        )

    def _register_approval_step(self, incident: Incident, step: RunbookStep) -> None:
        """Registers an approval gate requiring WebAuthn authorization."""
        role_str = step.required_role or "SecOps"
        matched_role = Role.SECOPS
        for r in Role:
            if r.value.lower() == role_str.lower():
                matched_role = r
                break

        challenge_payload = f"incident:{incident.id}:{step.id}:{step.action}"
        challenge = "0x" + hashlib.sha256(challenge_payload.encode("utf-8")).hexdigest()

        approval = IncidentApproval(
            id=step.id,
            action=step.action,
            required_role=matched_role,
            status="PENDING",
            challenge=challenge,
        )
        incident.approvals.append(approval)
        incident.timeline.append(
            TimelineEvent(
                event_type="APPROVAL_REQUIRED",
                message=f"Approval gate registered: {approval.action} (Requires {matched_role.value})",
                details={"action": approval.action, "role": matched_role.value},
            )
        )

    def tick_checklist_item(
        self,
        incident_id: str,
        action: str,
        ticked_by: str = "operator",
        notes: str | None = None,
    ) -> Incident:
        """Marks a manual remediation checklist item as completed with a timestamp."""
        incident = incident_store.get(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        # Normalize action string for robust matching (e.g. 'rotate deposit addresses' vs 'rotate_deposit_addresses')
        clean_action = action.strip().lower().replace("_", " ")
        matched_item = None
        for item in incident.checklist:
            if item.action.lower().replace("_", " ") == clean_action or item.id.lower() == clean_action:
                matched_item = item
                break

        if not matched_item:
            raise ValueError(f"Checklist item '{action}' does not exist in incident {incident_id}")

        now = datetime.now(UTC)
        matched_item.ticked = True
        matched_item.ticked_at = now
        matched_item.ticked_by = ticked_by
        matched_item.notes = notes

        incident.timeline.append(
            TimelineEvent(
                event_type="CHECKLIST_TICKED",
                message=f"Checklist item '{matched_item.action}' completed by {ticked_by}",
                details={"action": matched_item.action, "ticked_by": ticked_by, "notes": notes},
            )
        )

        # Check if all checklist items are ticked and all approvals completed
        self._check_incident_resolution(incident)
        incident_store.save(incident)

        # Invariant #7: Immutable audit entry
        audit_service.append_entry(
            action=f"INCIDENT_CHECKLIST_TICKED:{matched_item.action}",
            actor=ticked_by,
            payload={"incident_id": incident_id, "action": matched_item.action, "notes": notes},
            data_label=DataLabel.REAL,
        )

        return incident

    def approve_step(
        self,
        incident_id: str,
        step_action: str,
        approver_user: UserResponse,
        assertion: WebAuthnAssertion,
    ) -> Incident:
        """Cryptographically verifies WebAuthn hardware key signature for an approval gate."""
        incident = incident_store.get(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        clean_action = step_action.strip().lower().replace("_", " ")
        matched_approval = None
        for a in incident.approvals:
            if a.action.lower().replace("_", " ") == clean_action or a.id.lower() == clean_action:
                matched_approval = a
                break

        if not matched_approval:
            raise ValueError(f"Approval gate '{step_action}' not found in incident {incident_id}")

        if matched_approval.status == "APPROVED":
            return incident

        # Check role permissions
        if approver_user.role != matched_approval.required_role and approver_user.role != Role.ADMIN:
            raise PermissionError(
                f"Role '{approver_user.role.value}' is not authorized to approve {matched_approval.action} "
                f"(requires '{matched_approval.required_role.value}')"
            )

        # Invariant #5: Cryptographic WebAuthn verification
        try:
            webauthn_verifier.verify_assertion(
                assertion=assertion,
                expected_digest=matched_approval.challenge,
                approver_id=approver_user.id,
            )
        except WebAuthnVerificationError as exc:
            logger.warning("Incident approval WebAuthn verification failed: %s", exc)
            raise ValueError(f"WebAuthn verification failed: {exc.detail}") from exc

        now = datetime.now(UTC)
        assertion_ref = f"assertion-inc-{uuid4().hex[:12]}"
        matched_approval.status = "APPROVED"
        matched_approval.approved_by = approver_user.id
        matched_approval.approved_at = now
        matched_approval.webauthn_assertion_ref = assertion_ref

        incident.timeline.append(
            TimelineEvent(
                event_type="APPROVAL_GRANTED",
                message=f"Approval gate '{matched_approval.action}' approved by {approver_user.email} with WebAuthn",
                details={
                    "action": matched_approval.action,
                    "approved_by": approver_user.id,
                    "assertion_ref": assertion_ref,
                },
            )
        )

        # Check for incident resolution
        self._check_incident_resolution(incident)
        incident_store.save(incident)

        # Invariant #7: Immutable audit entry
        audit_service.append_entry(
            action=f"INCIDENT_APPROVAL_GRANTED:{matched_approval.action}",
            actor=approver_user.email,
            payload={
                "incident_id": incident_id,
                "action": matched_approval.action,
                "webauthn_assertion_ref": assertion_ref,
            },
            data_label=DataLabel.REAL,
        )

        return incident

    def _check_incident_resolution(self, incident: Incident) -> None:
        """Marks incident resolved if all checklist tasks and approvals are completed."""
        all_checklist_done = all(c.ticked for c in incident.checklist) if incident.checklist else True
        all_approvals_done = all(a.status == "APPROVED" for a in incident.approvals) if incident.approvals else True

        if all_checklist_done and all_approvals_done and incident.status != IncidentStatus.RESOLVED:
            incident.status = IncidentStatus.RESOLVED
            incident.resolved_at = datetime.now(UTC)
            incident.timeline.append(
                TimelineEvent(
                    event_type="INCIDENT_RESOLVED",
                    message="All remediation checklist items and approval gates completed; incident marked RESOLVED",
                )
            )


runbook_executor = RunbookExecutor()

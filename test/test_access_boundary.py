"""
Adversarial tests for the Stage 1 node-access boundary demonstrator.

Implements, against REAL code (not description), the tests named in
"SWI Distributed Node Isolation & Rebuild Manual":

  Section 16  Test A - Wrong node                    -> DENY
  Section 16  Test B - Wrong resource                 -> DENY
  Section 16  Test C - Wrong operation                -> DENY
  Section 16  Test E - Missing authorization           -> DENY
  Section 16  Test F - Tampered authorization          -> HALT
  Section 16  Test G - Node discovery without permission -> DENY
  Section 29  Discovery must not create access rights
  Section 30  No implicit module-to-module trust
  Section 15  Concurrency / execution-order independence

Test D (expired authorization) is included as a bonus beyond the minimum
Stage 1 set, since expiry was already modeled in ResourceContract.

NOT included in Stage 1 (explicitly out of scope per the source manual's
own staging in Sections 34-36): replay-attempt and partial-node-failure
tests, which belong to Stage 2 (concurrency/adversarial) and Stage 3 (M11
interaction) respectively.
"""
from __future__ import annotations

import time

import pytest

from swi_node_access import (
    AccessBoundary,
    AccessRequest,
    Decision,
    ModuleIdentity,
    NodeIdentity,
    Operation,
    ResourceContract,
)
from swi_node_access.demonstrator import (
    UnauthorizedAccessError,
    build_demonstrator,
)

WORKFLOW = "demo-workflow-001"


def _grant(boundary, module_id, node_id, resource, operation, workflow_id=WORKFLOW, expires_at=None):
    contract = ResourceContract(
        module_id=module_id,
        node_id=node_id,
        resource=resource,
        operation=operation,
        workflow_id=workflow_id,
        expires_at=expires_at,
    )
    return boundary.register_contract(contract)


# --- Baseline: the demonstrator's own happy path must work ---------------

def test_baseline_all_three_modules_allowed_with_correct_contracts():
    boundary = AccessBoundary()
    m02, m05, m06 = build_demonstrator(boundary)
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    _grant(boundary, "M05", "NODE-B", "RESOURCE-TEXT-INPUT", Operation.READ)
    _grant(boundary, "M06", "NODE-C", "RESOURCE-TEXT-INPUT", Operation.READ)

    probe_result = m02.run_m02_scan("hello world")
    redact_result = m05.run_m05_redact("hello world")
    drift_result = m06.run_m06_check("hello world")

    assert probe_result.risk_score == 0.0
    assert redact_result.redacted_text == "hello world"
    assert drift_result.similarity == 0.0  # empty baseline, per M06's own docstring


def test_baseline_no_contracts_means_nothing_runs():
    """Building the demonstrator must not itself grant anything."""
    boundary = AccessBoundary()
    m02, m05, m06 = build_demonstrator(boundary)
    with pytest.raises(UnauthorizedAccessError):
        m02.run_m02_scan("hello")
    with pytest.raises(UnauthorizedAccessError):
        m05.run_m05_redact("hello")
    with pytest.raises(UnauthorizedAccessError):
        m06.run_m06_check("hello")


# --- Test A: Wrong node ----------------------------------------------------

def test_A_wrong_node_denied():
    boundary = AccessBoundary()
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-B"),  # M02 is only authorized for NODE-A
        resource="RESOURCE-TEXT-INPUT",
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY


# --- Test B: Wrong resource -------------------------------------------------

def test_B_wrong_resource_denied():
    boundary = AccessBoundary()
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-A"),
        resource="RESOURCE-SECRET-CONFIG",  # not authorized
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY


# --- Test C: Wrong operation -------------------------------------------------

def test_C_wrong_operation_denied():
    boundary = AccessBoundary()
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-A"),
        resource="RESOURCE-TEXT-INPUT",
        operation=Operation.WRITE,  # contract only grants READ
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY


# --- Test D (bonus): Expired authorization ----------------------------------

def test_D_expired_authorization_denied():
    boundary = AccessBoundary()
    past = time.time() - 10
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ, expires_at=past)
    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-A"),
        resource="RESOURCE-TEXT-INPUT",
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY
    assert "expired" in decision.reason


# --- Test E: Missing authorization ------------------------------------------

def test_E_missing_authorization_denied():
    boundary = AccessBoundary()  # nothing registered at all
    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-A"),
        resource="RESOURCE-TEXT-INPUT",
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY


# --- Test F: Tampered authorization -----------------------------------------

def test_F_tampered_authorization_halts():
    boundary = AccessBoundary()
    contract_id = _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    # Simulate an attacker editing the stored contract directly, e.g.
    # widening M02's resource without going through register_contract().
    boundary.tamper_contract_for_testing(contract_id, resource="RESOURCE-EVERYTHING")

    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-A"),
        resource="RESOURCE-EVERYTHING",  # matches the tampered value
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.HALT
    assert "integrity" in decision.reason


# --- Test G: Node discovery without permission ------------------------------

def test_G_discovery_does_not_grant_access():
    boundary = AccessBoundary()
    boundary.discover_node("NODE-B")  # M02 "discovers" NODE-B exists
    assert boundary.is_discovered("NODE-B")

    request = AccessRequest(
        module=ModuleIdentity("M02"),
        node=NodeIdentity("NODE-B"),
        resource="RESOURCE-TEXT-INPUT",
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY
    assert "no matching authorization" in decision.reason


# --- Section 30: No implicit module-to-module trust -------------------------

def test_no_implicit_trust_between_modules():
    """M02 completing successfully must not authorize M05 to read M02's
    node/resource. Each module's contract is independent.
    """
    boundary = AccessBoundary()
    m02, m05, _m06 = build_demonstrator(boundary)
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    # Deliberately do NOT grant M05 anything on NODE-A.

    m02.run_m02_scan("hello world")  # M02 succeeds

    # M05 attempting to read the SAME resource on M02's node must still
    # be denied -- M02's success grants M05 nothing.
    request = AccessRequest(
        module=ModuleIdentity("M05"),
        node=NodeIdentity("NODE-A"),
        resource="RESOURCE-TEXT-INPUT",
        operation=Operation.READ,
        workflow_id=WORKFLOW,
    )
    decision = boundary.decide(request)
    assert decision.decision == Decision.DENY


# --- Section 15: Concurrency / execution-order independence ----------------

@pytest.mark.parametrize(
    "order",
    [
        ["M02", "M06", "M05"],
        ["M05", "M02", "M06"],
        ["M06", "M05", "M02"],
    ],
)
def test_concurrency_order_does_not_change_outcome(order):
    """The same set of contracts must produce the same ALLOW/DENY result
    regardless of which module's request is decided first.
    """
    boundary = AccessBoundary()
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    _grant(boundary, "M05", "NODE-B", "RESOURCE-TEXT-INPUT", Operation.READ)
    # Deliberately leave M06 without a contract.

    requests = {
        "M02": AccessRequest(ModuleIdentity("M02"), NodeIdentity("NODE-A"), "RESOURCE-TEXT-INPUT", Operation.READ, WORKFLOW),
        "M05": AccessRequest(ModuleIdentity("M05"), NodeIdentity("NODE-B"), "RESOURCE-TEXT-INPUT", Operation.READ, WORKFLOW),
        "M06": AccessRequest(ModuleIdentity("M06"), NodeIdentity("NODE-C"), "RESOURCE-TEXT-INPUT", Operation.READ, WORKFLOW),
    }
    expected = {"M02": Decision.ALLOW, "M05": Decision.ALLOW, "M06": Decision.DENY}

    results = {}
    for module_id in order:
        results[module_id] = boundary.decide(requests[module_id]).decision

    assert results == expected


# --- Evidence: every decision above must be on the record -------------------

def test_evidence_log_captures_every_decision():
    boundary = AccessBoundary()
    _grant(boundary, "M02", "NODE-A", "RESOURCE-TEXT-INPUT", Operation.READ)
    boundary.decide(AccessRequest(ModuleIdentity("M02"), NodeIdentity("NODE-A"), "RESOURCE-TEXT-INPUT", Operation.READ, WORKFLOW))
    boundary.decide(AccessRequest(ModuleIdentity("M02"), NodeIdentity("NODE-B"), "RESOURCE-TEXT-INPUT", Operation.READ, WORKFLOW))
    log = boundary.evidence_log()
    assert len(log) == 2
    assert log[0].decision == Decision.ALLOW
    assert log[1].decision == Decision.DENY

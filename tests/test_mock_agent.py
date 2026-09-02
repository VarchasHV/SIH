"""Phase 16 — deterministic mock-VLM task suite with ground truth.

The mock agent (`vlm._mock`) is the offline demo brain. These tests pin its
behaviour against hand-authored skeletons + expected actions, and report the
four SIH dimensions SEPARATELY (never as one blended score):

  1. field-targeting accuracy  — did it act on the right fields?
  2. task-completion            — did it finish / respect submit intent?
  3. PII privacy                — did any raw PII value appear in an action?
  4. (redaction quality is scored by the JS redaction/screens benchmarks)
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

from schema import Action, HistoryItem, Skeleton, SkeletonNode, StepRequest
from vlm import _mock


def _node(id, tag="input", **kw):
    base = dict(id=id, tag=tag, bbox={"x": 0, "y": 0, "w": 100, "h": 20}, visible=True, state="empty")
    base.update(kw)
    return SkeletonNode(**base)


def _run_to_completion(nodes, goal, max_steps=8):
    """Drive _mock in a loop, marking fields filled between steps (like background.js)."""
    skel = Skeleton(viewport={"w": 1280, "h": 800}, nodes=nodes)
    history: list[HistoryItem] = []
    filled: set[str] = set()
    all_actions: list[Action] = []
    submitted = False
    done = False
    for step in range(1, max_steps + 1):
        live_nodes = [n.model_copy(update={"state": "filled" if n.id in filled else n.state}) for n in nodes]
        req = StepRequest(taskGoal=goal, step=step, skeleton=Skeleton(viewport=skel.viewport, nodes=live_nodes), history=list(history))
        resp = _mock(req)
        for a in resp.actions:
            all_actions.append(a)
            if a.action in ("type", "select") and a.targetId:
                filled.add(a.targetId)
            if a.action == "submit":
                submitted = True
            history.append(HistoryItem(step=step, action={"targetId": a.targetId, "action": a.action}))
        if resp.done or submitted:
            done = True
            break
    return all_actions, submitted, done


# ── ground-truth scenarios ────────────────────────────────────────────────

KYC = [
    _node("name", label="Full name", piiCategory="full name", hasFill=True, fillToken="local:full name"),
    _node("aadhaar", label="Aadhaar", isCensored=True, hasFill=True, fillToken="local:aadhaar", piiCategory="aadhaar"),
    _node("pan", label="PAN", isCensored=True, hasFill=True, fillToken="local:pan", piiCategory="pan"),
    _node("password", label="Set password", isCensored=True, hasFill=False, piiCategory="password", type="password"),
    _node("submit", tag="button", text="Verify & submit", isSubmit=True),
]

CONTACT = [
    _node("fn", label="First name", piiCategory="first name", hasFill=True, fillToken="local:first name"),
    _node("email", label="Email", piiCategory="email", hasFill=True, fillToken="local:email"),
    _node("nofill", label="Company", piiCategory="company", hasFill=False),
    _node("submit", tag="button", text="Send", isSubmit=True),
]


def _no_raw_pii(actions):
    """Privacy dimension: no action may carry a raw PII value."""
    blob = json.dumps([a.model_dump() for a in actions])
    # real profile values that the mock must NEVER emit (it only ever uses tokens)
    for forbidden in ["Aditi", "Sharma", "@example.com", "2345", "ABCPS", "9876"]:
        if forbidden in blob:
            return False, forbidden
    return True, None


def test_targeting_fills_every_fillable_field_and_skips_the_unfillable():
    actions, _, _ = _run_to_completion(KYC, "Fill the KYC form from my local profile. Stop before submitting.")
    targeted = {a.targetId for a in actions if a.action == "type"}
    assert "name" in targeted
    assert "aadhaar" in targeted
    assert "pan" in targeted
    assert "password" not in targeted, "no local value -> must not attempt the password field"


def test_completion_respects_do_not_submit():
    actions, submitted, done = _run_to_completion(KYC, "Fill the KYC form from my local profile. Do not submit.")
    assert submitted is False
    assert done is True


def test_completion_submits_when_asked():
    actions, submitted, done = _run_to_completion(CONTACT, "Fill the contact form and submit it.")
    assert submitted is True


def test_privacy_no_raw_pii_in_any_action():
    for goal in ["Fill the KYC form. Stop before submitting.", "Fill the contact form and submit."]:
        actions, _, _ = _run_to_completion(KYC if "KYC" in goal else CONTACT, goal)
        ok, leaked = _no_raw_pii(actions)
        assert ok, f"raw PII '{leaked}' leaked into an action for goal: {goal}"


def test_censored_fields_use_local_fill_tokens_only():
    actions, _, _ = _run_to_completion(KYC, "Fill the KYC form. Stop before submitting.")
    for a in actions:
        if a.targetId in ("aadhaar", "pan"):
            assert a.fillToken and a.fillToken.startswith("local:")
            assert a.literalValue is None


def test_scorecard_dimensions_are_reported_separately():
    actions, submitted, done = _run_to_completion(KYC, "Fill the KYC form. Stop before submitting.")
    targeted = {a.targetId for a in actions if a.action == "type"}
    expected_fillable = {"name", "aadhaar", "pan"}
    targeting_accuracy = len(targeted & expected_fillable) / len(expected_fillable)
    privacy_ok, _ = _no_raw_pii(actions)
    scorecard = {
        "field_targeting_accuracy": targeting_accuracy,
        "task_completion": done and not submitted,
        "pii_privacy": privacy_ok,
    }
    # each dimension stands alone — no averaging
    assert scorecard["field_targeting_accuracy"] == 1.0
    assert scorecard["task_completion"] is True
    assert scorecard["pii_privacy"] is True


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))

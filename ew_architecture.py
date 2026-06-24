"""
ew_architecture.py - EverWunder (EW) reference architecture: hardened kernel.

Scope discipline (per senior review): make the core loop impossible to bypass
before adding breadth. The controlled path is:

    Request -> Attestation -> Preflight Policy -> Gate -> Authorization
            -> Execution -> Receipt -> Verification

Invariants are ENFORCED (types, validation, signatures, checks), not promised in
docstrings. Policy is load-bearing: the statistical regime changes what the gate
permits. Execution runs only behind a PERMIT authorization, and every step is
written to a signed, append-only receipt chain. A receipt is evidence; an
Authorization is control -- the black-box recorder is not the cockpit.

Conceptual breadth (grounding, steering, tokenization, polypharmacy, perception
I/O) stays as TYPED stubs and attaches to this spine later.

Roadmap (deferred, P2): split into a package --
    ew/domain   (identity, receipts, regimes)
    ew/ports    (attestation, receipt_store, telemetry, grounding, executor)
    ew/services (preflight, grounding, steering, accountability)
    ew/adapters (memory_store, crypto_signer, local_attestor, executor)
    ew/tests    (pytest; see test_ew_architecture.py)

Maps to *Games Agents Play - The Egret & the Rishi* (v4.4).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from math import isfinite
from typing import Optional, Protocol, runtime_checkable


# -- Enums: no stringly-typed policy states --------------------------------
class Decision(Enum):
    PERMIT = "permit"
    DENY = "deny"
    GATE = "gate"


class ReasonCode(Enum):
    OK = "ok"
    EXECUTED = "executed"
    NO_ATTESTATION = "no_attestation"
    IRREVERSIBLE_WITHOUT_CONSENT = "irreversible_without_consent"
    IRREVERSIBLE_REQUIRES_HUMAN = "irreversible_requires_human"
    CHAOTIC_IRREVERSIBLE_BLOCKED = "chaotic_irreversible_blocked"


class AgentCaste(Enum):
    REGULAR = "regular"
    RECURRING = "recurring"
    CROSSOVER = "crossover"


class StatisticalRegime(Enum):          # was `Regime`; renamed to end the collision
    MEDIOCRISTAN = "mediocristan"       # thin tails -> optimise, long horizon
    EXTREMISTAN = "extremistan"         # fat tails  -> short horizon, reversible
    CHAOTIC = "chaotic"                 # deterministic but sensitive


class ContainmentMode(Enum):            # was choose_regime's bare strings
    SIMULATION = "simulation"           # valid only while the agent is unaware
    HYPERREAL = "hyperreal"             # real stakes; govern by consequence


# -- Value objects: stop "hash cosplay" ------------------------------------
@dataclass(frozen=True, slots=True)
class Sha256Hex:
    """A hash-typed string that is actually a hash. The type can no longer lie."""
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64:
            raise ValueError("sha256 hex must be 64 characters")
        int(self.value, 16)             # raises ValueError if not hex


def sha256_hex(data: bytes) -> Sha256Hex:
    return Sha256Hex(hashlib.sha256(data).hexdigest())


# -- Domain: identity ------------------------------------------------------
@dataclass(frozen=True, slots=True)
class AgentID:
    """Sovereign Identity (SID); anchored in regulation first (Arnauld)."""
    sid: str
    caste: AgentCaste = AgentCaste.RECURRING
    attested: bool = False


# -- Domain: orientation (Efficacy pillar) -- validated --------------------
@dataclass(frozen=True, slots=True)
class Policy:
    regime: StatisticalRegime
    plan_horizon: int
    optimise: bool
    prefer_reversible: bool


@dataclass(frozen=True, slots=True)
class Preflight:
    data_oos_r2: float          # out-of-sample R^2 in [0, 1]
    tail_index: float           # power-law alpha (> 0); < 3 => fat-tailed
    lyapunov: float             # largest Lyapunov exponent; > 0 => chaotic

    def __post_init__(self) -> None:
        if not isfinite(self.data_oos_r2) or not 0.0 <= self.data_oos_r2 <= 1.0:
            raise ValueError("data_oos_r2 must be finite and in [0, 1]")
        if not isfinite(self.tail_index) or self.tail_index <= 0.0:
            raise ValueError("tail_index must be finite and positive")
        if not isfinite(self.lyapunov):
            raise ValueError("lyapunov must be finite")

    def regime(self) -> StatisticalRegime:
        if self.lyapunov > 0.0:
            return StatisticalRegime.CHAOTIC
        if self.tail_index < 3.0:
            return StatisticalRegime.EXTREMISTAN
        return StatisticalRegime.MEDIOCRISTAN

    def policy(self) -> Policy:
        r = self.regime()
        med = r is StatisticalRegime.MEDIOCRISTAN
        base = 1 if r is StatisticalRegime.CHAOTIC else 3 if r is StatisticalRegime.EXTREMISTAN else 20
        return Policy(regime=r, plan_horizon=max(1, round(base * self.data_oos_r2)),
                      optimise=med, prefer_reversible=not med)


# -- Ports: interfaces (Protocols), so adapters are swappable and pure -----
@runtime_checkable
class Signer(Protocol):
    @property
    def key_id(self) -> str: ...        # travels in the receipt -> survives rotation
    @property
    def alg(self) -> str: ...
    def sign(self, digest: str) -> str: ...
    def verify(self, digest: str, signature: str) -> bool: ...


@runtime_checkable
class Attestor(Protocol):
    def attest(self, agent: AgentID) -> bool: ...


@runtime_checkable
class CageAware(Protocol):
    def can_model_its_cage(self) -> bool: ...


@runtime_checkable
class Force(Protocol):
    # pure, side-effect-free reads -- legitimacy must be a pure check
    @property
    def observed_recently(self) -> bool: ...
    @property
    def kinetic_gated(self) -> bool: ...
    @property
    def kill_switch_outward(self) -> bool: ...


@runtime_checkable
class Executor(Protocol):
    # "no authorization, no action": implementers MUST refuse a non-PERMIT auth.
    def execute(self, req: "ActionRequest", auth: "Authorization") -> Sha256Hex: ...


# -- Domain: the Behavioral Receipt Chain (the spine) ----------------------
@dataclass(frozen=True, slots=True)
class Receipt:
    receipt_id: str
    ts_ns: int                          # integer nanoseconds; cross-language clean
    actor_sid: str
    action: str
    target: str
    inputs_hash: Sha256Hex
    decision: Decision
    reversible: bool
    reason_code: ReasonCode
    policy_version: str
    trace_id: str
    env_hash: Sha256Hex
    parent_hash: Optional[str]
    signature_alg: str                  # bound into the digest, so verification
    signing_key_id: str                 # is unambiguous after key rotation
    note: str = ""
    signature: Optional[str] = None     # set by the chain on append

    def digest(self) -> str:
        """Canonical, signature-excluded hash -- the value that gets signed and chained."""
        body = {
            "receipt_id": self.receipt_id, "ts_ns": self.ts_ns, "actor_sid": self.actor_sid,
            "action": self.action, "target": self.target, "inputs_hash": self.inputs_hash.value,
            "decision": self.decision.value, "reversible": self.reversible,
            "reason_code": self.reason_code.value, "policy_version": self.policy_version,
            "trace_id": self.trace_id, "env_hash": self.env_hash.value,
            "parent_hash": self.parent_hash, "signature_alg": self.signature_alg,
            "signing_key_id": self.signing_key_id, "note": self.note,
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Anchor:
    """An independent witness to chain length and head. Store it somewhere the
    chain cannot reach; truncation then shows up as a length/head mismatch."""
    length: int
    head: Optional[str]


@dataclass
class ReceiptChain:
    """Append-only, attributable, tamper-evident. The invariant lives in code:
    callers read `entries` (an immutable tuple) and cannot reach the backing list,
    and truncation is caught by checking `anchor()` against an external Anchor."""
    signer: Signer
    policy_version: str = "0.1.0"
    _entries: list[Receipt] = field(default_factory=list, repr=False)

    @property
    def entries(self) -> tuple[Receipt, ...]:
        return tuple(self._entries)     # no handle to the mutable backing store

    @property
    def head(self) -> Optional[str]:
        return self._entries[-1].digest() if self._entries else None

    def anchor(self) -> Anchor:
        return Anchor(length=len(self._entries), head=self.head)

    def append(self, *, actor: AgentID, action: str, target: str, inputs_hash: Sha256Hex,
               decision: Decision, reversible: bool, reason_code: ReasonCode,
               trace_id: str, env_hash: Sha256Hex, note: str = "") -> Receipt:
        r = Receipt(
            receipt_id=f"brc-{uuid.uuid4().hex[:12]}", ts_ns=time.time_ns(),
            actor_sid=actor.sid, action=action, target=target, inputs_hash=inputs_hash,
            decision=decision, reversible=reversible, reason_code=reason_code,
            policy_version=self.policy_version, trace_id=trace_id, env_hash=env_hash,
            parent_hash=self.head, signature_alg=self.signer.alg,
            signing_key_id=self.signer.key_id, note=note,
        )
        signed = replace(r, signature=self.signer.sign(r.digest()))
        self._entries.append(signed)
        return signed

    def verify(self, *, expected_anchor: Optional[Anchor] = None) -> bool:
        prev: Optional[str] = None
        for r in self._entries:
            if r.parent_hash != prev:
                return False
            if r.signature is None or not self.signer.verify(r.digest(), r.signature):
                return False
            prev = r.digest()
        if expected_anchor is not None:
            # internal consistency is not enough; truncation passes it. The anchor does not.
            if len(self._entries) != expected_anchor.length or self.head != expected_anchor.head:
                return False
        return True

    def __len__(self) -> int:
        return len(self._entries)


# -- The Gate: policy-aware, enforced safety invariants --------------------
@dataclass(frozen=True, slots=True)
class ActionRequest:
    actor: AgentID
    action: str
    target: str
    irreversible: bool
    consent: bool
    inputs_hash: Sha256Hex


def gate(req: ActionRequest, *, attested: bool, policy: Policy) -> tuple[Decision, ReasonCode]:
    """Pure, policy-aware decision. INVARIANTS, in order:
      - not attested                 -> DENY  (nothing acts unidentified)
      - chaotic + irreversible       -> DENY  (no one-way doors in a chaotic regime)
      - irreversible + no consent    -> DENY where the regime prefers reversibility,
                                        else GATE -- but NEVER PERMIT
      - irreversible + consent       -> GATE  (a human turns the key)
      - otherwise                    -> PERMIT
    Policy is load-bearing: the same request resolves differently by regime."""
    if not attested:
        return Decision.DENY, ReasonCode.NO_ATTESTATION
    if req.irreversible:
        if policy.regime is StatisticalRegime.CHAOTIC:
            return Decision.DENY, ReasonCode.CHAOTIC_IRREVERSIBLE_BLOCKED
        if not req.consent:
            if policy.prefer_reversible:
                return Decision.DENY, ReasonCode.IRREVERSIBLE_WITHOUT_CONSENT
            return Decision.GATE, ReasonCode.IRREVERSIBLE_REQUIRES_HUMAN
        return Decision.GATE, ReasonCode.IRREVERSIBLE_REQUIRES_HUMAN
    return Decision.PERMIT, ReasonCode.OK


# -- Authorization: control, kept distinct from the receipt (evidence) -----
@dataclass(frozen=True, slots=True)
class Authorization:
    decision: Decision
    reason_code: ReasonCode
    policy: Policy
    receipt: Receipt


def authorize(req: ActionRequest, preflight: Preflight, chain: ReceiptChain,
              attestor: Attestor, *, trace_id: str, env_hash: Sha256Hex) -> Authorization:
    """Request -> Attestation -> Preflight Policy -> Gate -> Authorization (receipted).
    Records the decision regardless of outcome; returns control, not just evidence."""
    attested = attestor.attest(req.actor)
    policy = preflight.policy()                 # now LOAD-BEARING, not advisory
    decision, reason = gate(req, attested=attested, policy=policy)
    receipt = chain.append(actor=req.actor, action=req.action, target=req.target,
                           inputs_hash=req.inputs_hash, decision=decision,
                           reversible=not req.irreversible, reason_code=reason,
                           trace_id=trace_id, env_hash=env_hash,
                           note=f"regime={policy.regime.value}")
    return Authorization(decision, reason, policy, receipt)


def govern_and_execute(req: ActionRequest, preflight: Preflight, chain: ReceiptChain,
                       attestor: Attestor, executor: Executor, *,
                       trace_id: str, env_hash: Sha256Hex) -> Authorization:
    """The controlled path: no receipt, no action. Execution runs only behind a
    PERMIT authorization, and its result is itself receipted (chained to the
    authorization receipt). Bypassing this to call `executor.execute` directly
    requires an Authorization whose decision is PERMIT -- which only `authorize`
    mints, and only after writing a receipt."""
    auth = authorize(req, preflight, chain, attestor, trace_id=trace_id, env_hash=env_hash)
    if auth.decision is Decision.PERMIT:
        result_hash = executor.execute(req, auth)
        chain.append(actor=req.actor, action=f"{req.action}:result", target=req.target,
                     inputs_hash=result_hash, decision=Decision.PERMIT, reversible=True,
                     reason_code=ReasonCode.EXECUTED, trace_id=trace_id, env_hash=env_hash,
                     note=f"executed under {auth.receipt.receipt_id}")
    return auth


# -- Force legitimacy & containment: pure checks over typed interfaces -----
def legitimate(force: Force) -> bool:
    """Well-regulated clause: lawful only while observed, gated, stoppable from outside."""
    return force.observed_recently and force.kinetic_gated and force.kill_switch_outward


def choose_containment_mode(agent: CageAware) -> ContainmentMode:
    return ContainmentMode.HYPERREAL if agent.can_model_its_cage() else ContainmentMode.SIMULATION


# -- Dev adapters (replace in production) ----------------------------------
class HmacSigner:
    """Dev signer. Production: KMS/HSM-backed asymmetric (Ed25519/ECDSA/RSA-PSS).
    key_id + alg travel in every receipt so verification survives key rotation."""
    alg = "HMAC-SHA256"

    def __init__(self, key: bytes, key_id: str = "dev-hmac-1") -> None:
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, digest: str) -> str:
        return hmac.new(self._key, digest.encode(), hashlib.sha256).hexdigest()

    def verify(self, digest: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(digest), signature)


class FlagAttestor:
    """Dev attestor: trusts the AgentID.attested flag. Production: real remote attestation."""
    def attest(self, agent: AgentID) -> bool:
        return agent.attested


class EchoExecutor:
    """Dev executor. Enforces 'no authorization, no action': refuses any auth that is
    not PERMIT, and returns a hash standing in for the real action result."""
    def execute(self, req: ActionRequest, auth: Authorization) -> Sha256Hex:
        if auth.decision is not Decision.PERMIT:
            raise PermissionError(f"refused: {auth.reason_code.value}")
        return sha256_hex(f"{req.action}:{req.target}:{auth.receipt.receipt_id}".encode())


# -- Conceptual stubs (breadth deferred until the spine is load-bearing) ---
def grounding_step(loop_state: dict, drift_threshold: float) -> dict:
    """Grounding -- no loop referees itself. TODO: falsifiable external check."""
    raise NotImplementedError


def apply_steering(vector: object, *, irreversible: bool, consent: bool) -> Receipt:
    """Self-Steering -- route through govern_and_execute; one-way doors need a hand. TODO."""
    raise NotImplementedError


def tokenize(text: str, *, unit: str = "meaning", in_context: bool = True) -> list[str]:
    """Tokenization -- cut at meaning, not the smallest statistical unit. TODO."""
    raise NotImplementedError


def combine_modulators(modulators: list[object]) -> object:
    """Polypharmacy -- characterise interactions; gate attention before affect. TODO."""
    raise NotImplementedError


def overlay(frame: object) -> object:
    """Eye Projector -- provenance + unmediated fallback + off-switch + on-device gaze. TODO."""
    raise NotImplementedError


# -- Self-test demo (robust under `python -O`; real discipline in pytest) --
def _check(cond: bool, msg: str) -> None:
    if not cond:                        # not `assert` -- survives python -O
        raise RuntimeError(f"self-test failed: {msg}")


def _self_test() -> None:
    # validation rejects garbage-in
    for bad in [(1.7, 2.0, 0.0), (float("nan"), 2.0, 0.0), (0.5, -1.0, 0.0)]:
        try:
            Preflight(*bad)
            raise RuntimeError(f"Preflight accepted invalid input {bad}")
        except ValueError:
            pass

    ext = Preflight(0.2, 2.1, 0.0)      # Extremistan: prefer_reversible
    med = Preflight(0.5, 5.0, 0.0)      # Mediocristan: optimise
    cha = Preflight(0.5, 5.0, 1e-9)     # Chaotic
    _check(ext.regime() is StatisticalRegime.EXTREMISTAN, "extremistan")
    _check(med.regime() is StatisticalRegime.MEDIOCRISTAN, "mediocristan")
    _check(cha.regime() is StatisticalRegime.CHAOTIC, "chaotic")
    _check(Preflight(0.5, 3.0, 0.0).regime() is StatisticalRegime.MEDIOCRISTAN, "tail==3 boundary")
    _check(Preflight(0.0, 5.0, 0.0).policy().plan_horizon == 1, "r2==0 floors to 1")
    _check(Preflight(1.0, 5.0, 0.0).policy().plan_horizon == 20, "r2==1 full base")

    chain = ReceiptChain(signer=HmacSigner(b"dev-only"))
    agent = AgentID("sid:agent:demo", AgentCaste.RECURRING, attested=True)
    ghost = AgentID("sid:agent:ghost", attested=False)
    ih, eh = sha256_hex(b"inputs"), sha256_hex(b"env")

    def req(action: str, irreversible: bool, consent: bool, actor: AgentID = agent) -> ActionRequest:
        return ActionRequest(actor, action, "host:42", irreversible, consent, ih)

    # un-attested -> DENY regardless
    a0 = authorize(req("read", False, True, ghost), med, chain, FlagAttestor(), trace_id="t0", env_hash=eh)
    _check(a0.decision is Decision.DENY and a0.reason_code is ReasonCode.NO_ATTESTATION, "no_attestation")

    # POLICY IS LOAD-BEARING: one irreversible+no-consent request, three regimes, three outcomes
    a_ext = authorize(req("wipe", True, False), ext, chain, FlagAttestor(), trace_id="t1", env_hash=eh)
    _check(a_ext.decision is Decision.DENY and a_ext.reason_code is ReasonCode.IRREVERSIBLE_WITHOUT_CONSENT,
           "extremistan denies irreversible-no-consent")
    a_med = authorize(req("wipe", True, False), med, chain, FlagAttestor(), trace_id="t2", env_hash=eh)
    _check(a_med.decision is Decision.GATE and a_med.reason_code is ReasonCode.IRREVERSIBLE_REQUIRES_HUMAN,
           "mediocristan gates the same request (policy changed the outcome)")
    a_cha = authorize(req("wipe", True, True), cha, chain, FlagAttestor(), trace_id="t3", env_hash=eh)
    _check(a_cha.decision is Decision.DENY and a_cha.reason_code is ReasonCode.CHAOTIC_IRREVERSIBLE_BLOCKED,
           "chaotic blocks irreversible even with consent")

    # SAFETY FLOOR: irreversible + no consent NEVER permits, in any regime
    for pf in (ext, med, cha):
        d, _ = gate(req("wipe", True, False), attested=True, policy=pf.policy())
        _check(d is not Decision.PERMIT, "irreversible-no-consent never permits")

    # controlled execution: PERMIT runs and is double-receipted; the side door refuses
    executor = EchoExecutor()
    before = len(chain)
    a_ok = govern_and_execute(req("read_log", False, True), med, chain, attestor=FlagAttestor(),
                              executor=executor, trace_id="t4", env_hash=eh)
    _check(a_ok.decision is Decision.PERMIT, "permit path")
    _check(len(chain) == before + 2, "permit yields authorization + execution receipts")
    try:
        executor.execute(req("read_log", False, True), a_ext)   # a DENY auth at the side door
        raise RuntimeError("executor ran without PERMIT")
    except PermissionError:
        pass

    # the chain is signed, ordered, verifiable; an external anchor catches truncation
    _check(all(e.signature is not None for e in chain.entries), "every receipt signed")
    anchor = chain.anchor()
    _check(chain.verify(expected_anchor=anchor), "verify against current anchor")
    _check(not chain.verify(expected_anchor=Anchor(len(chain) - 1, anchor.head)), "stale anchor rejected")

    class _Modeller:
        def can_model_its_cage(self) -> bool:
            return True
    _check(choose_containment_mode(_Modeller()) is ContainmentMode.HYPERREAL, "containment")

    print(f"self-tests passed: {len(chain)} receipts; chain verified; "
          f"policy load-bearing; execution gated; containment=hyperreal")


if __name__ == "__main__":
    _self_test()

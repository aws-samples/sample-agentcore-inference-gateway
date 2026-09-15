"""Offline test of the cost RESERVATION/REFUND symmetry in the REQUEST interceptor.

The bug this guards against: CONTROL 3 reserves prompt cost plus worst-case output cost,
and then CONTROL 4, the request-shape checks, Cedar and the deadline can all still deny.
Every one of those paths used to leave the caller charged for a request that produced no
output at all — and `cost_budget_exceeded` charged them a second time for being over
budget, pushing them further over and extending their own lockout.

Two things are checked, and the second is the one that keeps this from rotting:

  1. `_refund_reservation` writes the exact negative of the reservation, to the same
     window counter the charge went to.
  2. STRUCTURALLY, by reading the AST: every `return` inside `_govern` funnels through
     `_finish` (or a replay / an early pre-charge exit). That is what makes the refund
     impossible for the NEXT new control to forget — a per-deny-path refund would be
     forgotten the first time someone adds a control.

No AWS calls: `_ddb` is replaced with a recorder.
"""
import ast
import importlib.util
import os
import pathlib
import sys

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("COST_TABLE", "test-ledger")

SRC = pathlib.Path("pilot/lambda/guardrail/index.py")
spec = importlib.util.spec_from_file_location("gr", SRC)
gr = importlib.util.module_from_spec(spec)
sys.modules["gr"] = gr
spec.loader.exec_module(gr)

fails = 0


class Recorder:
    """Stands in for the DynamoDB client and remembers what it was asked to do."""

    def __init__(self):
        self.calls = []

    def update_item(self, **kw):
        self.calls.append(kw)
        return {"Attributes": {"spend": {"N": "0"}}}


# --- 1. the refund is the exact reverse of the charge ------------------------
print("--- refund arithmetic ---")
rec = Recorder()
gr._ddb = rec
gr._COST_TABLE = "test-ledger"

STATE = {"charged": 0.01234, "sub": "user-sub-abc", "bucket": 471234, "total": 0.5}
gr._refund_reservation(STATE, "guardrail_blocked")

checks = []
if len(rec.calls) != 1:
    checks.append((f"exactly one ledger write (got {len(rec.calls)})", False))
else:
    call = rec.calls[0]
    amount = float(call["ExpressionAttributeValues"][":d"]["N"])
    checks.append(("refund is negative", amount < 0))
    checks.append((f"refund magnitude == charge ({amount})",
                   abs(amount + STATE["charged"]) < 1e-12))
    checks.append(("targets the same window counter as the charge",
                   call["Key"]["pk"]["S"] == "user-sub-abc#471234"))
    checks.append(("uses ADD, not SET (concurrent requests share the counter)",
                   "ADD spend" in call["UpdateExpression"]))

# A refund must never be invented from an incomplete reservation: a missing sub or bucket
# would address the WRONG counter, and a zero charge has nothing to reverse.
for label, bad in (("no charge", {"charged": 0.0, "sub": "s", "bucket": 1}),
                   ("no sub", {"charged": 1.0, "sub": "", "bucket": 1}),
                   ("no bucket", {"charged": 1.0, "sub": "s", "bucket": None}),
                   ("empty state", {})):
    rec.calls.clear()
    gr._refund_reservation(bad, "x")
    checks.append((f"no write for an incomplete reservation ({label})",
                   not rec.calls))

for label, ok in checks:
    if not ok:
        fails += 1
    print(f"  {label:58} {'PASS' if ok else 'FAIL'}")


# --- 2. every deny path funnels through the one refund seam ------------------
print("\n--- structural: no return in _govern can skip _finish ---")
tree = ast.parse(SRC.read_text(encoding="utf-8"))
govern = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "_govern"), None)
if govern is None:
    print("  FAIL could not find _govern")
    fails += 1
else:
    # Returns lexically inside the nested _finish/_unwind helpers are not _govern's own.
    nested = {n for h in ast.walk(govern)
              if isinstance(h, ast.FunctionDef) and h is not govern
              for n in ast.walk(h)}

    # `_charge_and_check` is what mutates the ledger; a return BEFORE it lexically appears
    # has nothing to refund, so it does not need the seam.
    charge_line = next(
        (n.lineno for n in ast.walk(govern)
         if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_charge_and_check"),
        None)
    if charge_line is None:
        print("  FAIL could not locate the _charge_and_check call")
        fails += 1
        charge_line = 10 ** 9

    SEAMS = {"_finish", "_replay"}
    bad = []
    post_charge = 0
    for node in ast.walk(govern):
        if not isinstance(node, ast.Return) or node in nested:
            continue
        if node.lineno < charge_line:
            continue          # pre-reservation: nothing has been charged yet
        post_charge += 1
        val = node.value
        name = getattr(getattr(val, "func", None), "id", "") if isinstance(
            val, ast.Call) else ""
        if name not in SEAMS:
            bad.append((node.lineno, name or ast.dump(val)[:60]))

    ok = not bad and post_charge > 0
    if not ok:
        fails += 1
    print(f"  {post_charge} returns after the reservation, all via "
          f"{'/'.join(sorted(SEAMS))}   {'PASS' if ok else 'FAIL'}")
    for line, what in bad:
        print(f"    line {line}: returns {what} -- bypasses the refund seam")

    # And the seam itself must actually refund. Cheap, but it is the assertion that would
    # have caught the original bug, where the refund existed on the response side only.
    fin = next((n for n in ast.walk(govern)
                if isinstance(n, ast.FunctionDef) and n.name == "_finish"), None)
    ok = fin is not None and any(
        isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_refund_reservation"
        for n in ast.walk(fin))
    if not ok:
        fails += 1
    print(f"  _finish calls _refund_reservation{'':26} {'PASS' if ok else 'FAIL'}")

    # The raise paths cannot reach _finish at all, so `handler` is the last chance to
    # unwind a charge that was taken and then abandoned.
    h = next((n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "handler"), None)
    ok = h is not None and any(
        isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_unwind"
        for n in ast.walk(h))
    if not ok:
        fails += 1
    print(f"  handler unwinds a stranded reservation on the raise paths  "
          f"{'PASS' if ok else 'FAIL'}")


# --- 3. the response side settles rather than silently releasing ------------
print("\n--- response interceptor: settle, don't release ---")
usrc = pathlib.Path("pilot/lambda/usage/index.py").read_text(encoding="utf-8")
utree = ast.parse(usrc)
names = {n.name for n in ast.walk(utree) if isinstance(n, ast.FunctionDef)}
for label, ok in (
    ("_settle_reservation exists (replaced _release_reservation)",
     "_settle_reservation" in names),
    ("the old unconditional release is gone",
     "_release_reservation" not in names),
    ("cost math is a pure, testable function",
     "_price_usage" in names),
):
    if not ok:
        fails += 1
    print(f"  {label:58} {'PASS' if ok else 'FAIL'}")

print(f"\n{'PASS' if fails == 0 else f'FAIL ({fails})'}")
sys.exit(1 if fails else 0)

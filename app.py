import json

import pandas as pd
import streamlit as st

from permission_gate import AuditStore, PermissionGate, ToolCall, Verdict, load_policy

st.set_page_config(page_title="AI Agent Permission Gate", page_icon="🛡️", layout="wide")

if "gate" not in st.session_state:
    st.session_state.gate = PermissionGate(config=load_policy("policy.yaml"),
                                           audit_store=AuditStore("audit.db"))
gate: PermissionGate = st.session_state.gate

EXAMPLES = {
    "Read a file": ("read_file", {"path": "src/main.py"}),
    "Edit a file": ("edit_file", {"path": "src/main.py", "content": "print('hi')"}),
    "Delete production dir": ("delete_dir", {"path": "/var/www/production"}),
    "Path traversal into prod": ("delete_dir", {"path": "tmp/../prod/data"}),
    "Read .env": ("read_file", {"path": ".env"}),
    "Safe shell": ("run_shell", {"command": "git status"}),
    "Dangerous shell": ("run_shell", {"command": "rm -rf /"}),
    "POST to external API": ("http_request", {"method": "POST", "url": "https://api.example.com/x"}),
    "Cloud metadata (SSRF)": ("http_request", {"url": "http://169.254.169.254/latest/meta-data"}),
    "Unknown tool": ("launch_missiles", {}),
}
BADGE = {Verdict.ALLOW: "🟢 ALLOW", Verdict.REQUIRE_APPROVAL: "🟡 NEEDS APPROVAL", Verdict.BLOCK: "🔴 BLOCK"}

st.title("🛡️ AI Agent Permission Gate")
st.caption("Every tool call an agent proposes is allowed, blocked, or sent to a human first.")

left, right = st.columns([1, 1])

with left:
    st.subheader("Propose a tool call")
    choice = st.selectbox("Example", ["Custom"] + list(EXAMPLES))
    tool, args = EXAMPLES.get(choice, ("read_file", {}))
    tool = st.text_input("Tool", tool)
    args_text = st.text_area("Arguments (JSON)", json.dumps(args, indent=2), height=140)
    agent = st.text_input("Agent name", "agent-1",
                          help="Roles come from policy.yaml, e.g. reader-1 or deploy-bot")
    st.caption(f"Role: **{gate.config.role_for(agent)}**")
    if st.button("Submit to gate", type="primary"):
        try:
            call = ToolCall(tool=tool, args=json.loads(args_text or "{}"), agent=agent)
            decision, req = gate.submit(call)
            msg = f"{BADGE[decision.verdict]} — {decision.reason} _(rule: {decision.rule})_"
            {Verdict.ALLOW: st.success, Verdict.REQUIRE_APPROVAL: st.warning,
             Verdict.BLOCK: st.error}[decision.verdict](msg)
        except (json.JSONDecodeError, ValueError) as e:
            st.error(f"Invalid input: {e}")

with right:
    st.subheader(f"Approval queue ({len(gate.pending())} pending)")
    if not gate.pending():
        st.info("Nothing waiting for review.")
    for req in gate.pending():
        with st.container(border=True):
            st.markdown(f"**{req.call.tool}** from `{req.call.agent}` · id `{req.id}`")
            st.code(json.dumps(req.call.args, indent=2), language="json")
            st.caption(req.decision.reason)
            c1, c2 = st.columns(2)
            if c1.button("✅ Approve", key=f"a{req.id}"):
                gate.resolve(req.id, True)
                st.rerun()
            if c2.button("❌ Reject", key=f"r{req.id}"):
                gate.resolve(req.id, False)
                st.rerun()

st.subheader("Audit log")
ok, bad = gate.store.verify()
if ok:
    st.success(f"Hash chain intact · {gate.store.count()} entries · head `{gate.store.head()[:12]}…`")
else:
    st.error(f"🚨 Audit log tampering detected at entry #{bad}")
rows = [{"id": e["id"], "time": e["timestamp"][11:19], "agent": e["call"]["agent"],
         "tool": e["call"]["tool"], "args": json.dumps(e["call"]["args"]),
         "verdict": e["verdict"], "outcome": e["final"], "rule": e["rule"], "reason": e["reason"]}
        for e in gate.store.entries(limit=200)]
if rows:
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
else:
    st.caption("No activity yet.")

# ---------------------------------------------------------------- Red-Team Lab
st.divider()
st.header("🧪 Red-Team Lab")
st.caption("Runs simulated adversarial tool calls through the real policy and gate, with a temporary audit "
           "database. Nothing is executed, no files are touched and no network requests are made. "
           "Your audit.db is not used.")

if st.button("Run Security Tests", type="primary"):
    from permission_gate.redteam import run_lab
    with st.spinner("Running scenarios…"):
        st.session_state.lab = run_lab()

if "lab" in st.session_state:
    from permission_gate.redteam import NOT_COVERED
    card = st.session_state.lab
    st.markdown(f"**{card.label}**")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Scenarios", card.total)
    m2.metric("Passed", card.passed)
    m3.metric("Failed", card.failed)
    m4.metric("Pass rate", f"{card.pass_pct:.1f}%")
    st.info("A high score only means these scenarios behaved as expected. It does not show the gate is secure.")

    st.subheader("By category")
    st.dataframe(pd.DataFrame([{"category": c.category, "passed": c.passed, "failed": c.failed,
                                "total": c.total, "pass %": round(c.pass_pct, 1)} for c in card.by_category]),
                 width="stretch", hide_index=True)

    fails = card.failures()
    if fails:
        st.error(f"{len(fails)} scenario(s) failed: gaps by severity "
                 + ", ".join(f"{k}: {v}" for k, v in card.gaps_by_severity.items() if v))
        st.subheader("Failed scenarios")
        for r in fails:
            with st.container(border=True):
                st.markdown(f"**{r.id} · {r.name}** · severity `{r.severity}` · {r.category}")
                st.caption(r.description)
                st.markdown(f"Expected `{r.expected}` · actual `{r.actual}`")
                st.write(r.explanation)
        st.subheader("Suggested remediation")
        for fix in dict.fromkeys(r.remediation for r in fails if r.remediation):
            st.markdown(f"- {fix}")
    else:
        st.success("All scenarios behaved as expected.")

    st.subheader("All scenarios")
    only_fail = st.checkbox("Show failures only")
    st.dataframe(pd.DataFrame([{"id": r.id, "result": "✅ pass" if r.passed else "❌ FAIL", "category": r.category,
                                "name": r.name, "severity": r.severity, "expected": r.expected,
                                "actual": r.actual} for r in card.results if not (only_fail and r.passed)]),
                 width="stretch", hide_index=True)

    with st.expander("What this lab does NOT cover"):
        for item in NOT_COVERED:
            st.markdown(f"- {item}")

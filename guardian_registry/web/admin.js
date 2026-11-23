"use strict";
// Operator console for the registry's /v1/admin API. Same rules as the people's app: no
// third-party code, no inline script or style, and server data only ever goes into the page
// as text. The operator's credential (a token, or an ID token from your SSO) is kept in
// sessionStorage, so it is gone when the tab closes. Four-eyes stays on the server: this page
// can't approve your own requests, it just shows you what waits for someone else.

const CRED_KEY = "gr-operator-credential";
const state = { tab: "queue" };

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function credential() {
  try { return JSON.parse(sessionStorage.getItem(CRED_KEY) || "null"); } catch (e) { return null; }
}

async function api(method, path, body) {
  const c = credential();
  const headers = { Accept: "application/json" };
  if (c && c.kind === "token") headers["X-Admin-Token"] = c.value;
  if (c && c.kind === "sso") headers.Authorization = `Bearer ${c.value}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  const data = text ? JSON.parse(text) : {};
  if (!r.ok) {
    const err = new Error(data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `HTTP ${r.status}`);
    err.status = r.status;
    throw err;
  }
  return data;
}

function toast(text) {
  const t = document.getElementById("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 5000);
}

async function act(button, fn, done) {
  button.disabled = true;
  try {
    await fn();
    toast(done);
    await render();
  } catch (e) {
    toast(e.message);
    if (e.status === 401) signOut();
  } finally {
    button.disabled = false;
  }
}

function when(t) { return t ? new Date(t).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : ""; }
function pill(text, kind) { return h("span", { class: `pill ${kind || ""}` }, text); }
function statusPill(s) { return pill(s, { active: "ok", pending: "warn", suspended: "bad", offboarded: "" }[s] || ""); }
function ask(question) { const v = window.prompt(question); return v && v.trim() ? v.trim() : null; }

// ------------------------------------------------------------------ sign-in
function signInView() {
  const kind = h("select", { id: "kind" }, h("option", { value: "token" }, "Operator token"),
    h("option", { value: "sso" }, "SSO ID token (from your identity provider)"));
  const value = h("input", { id: "cred", type: "password", autocomplete: "off", required: true });
  return [h("h1", {}, "Operator sign-in"),
    h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      sessionStorage.setItem(CRED_KEY, JSON.stringify({ kind: kind.value, value: value.value.trim() }));
      try { await api("GET", "/v1/admin/register"); start(); }
      catch (err) { sessionStorage.removeItem(CRED_KEY); toast(err.message); }
    } },
    h("label", { for: "kind" }, "Sign in with"), kind,
    h("label", { for: "cred" }, "Credential"), value,
    h("p", { class: "muted small" }, "Kept only in this tab. Approvals need a second operator."),
    h("div", { class: "row mt" }, h("button", { type: "submit" }, "Sign in")))];
}

function signOut() {
  sessionStorage.removeItem(CRED_KEY);
  document.getElementById("nav").hidden = true;
  show(signInView());
}

// ------------------------------------------------------------------ waiting (four-eyes)
async function queueView() {
  const [parts, feeds] = await Promise.all([api("GET", "/v1/admin/participants"), api("GET", "/v1/admin/register-feeds")]);
  const pendingParts = parts.filter((p) => p.pending_request);
  const certLists = await Promise.all(parts.filter((p) => p.status !== "offboarded").map(async (p) =>
    ({ p, certs: await api("GET", `/v1/admin/participants/${p.participant_id}/certificates`) })));
  const pendingCerts = certLists.flatMap(({ p, certs }) => certs.filter((c) => c.status === "pending").map((c) => ({ p, c })));
  const pendingFeeds = feeds.filter((f) => f.status === "pending");
  const held = feeds.filter((f) => f.held);
  const total = pendingParts.length + pendingCerts.length + pendingFeeds.length + held.length;
  const badge = document.getElementById("queue-count");
  badge.textContent = String(total);
  badge.hidden = total === 0;

  const out = [h("h1", {}, "Waiting for a decision")];
  if (!total) out.push(h("p", { class: "card empty" }, "Nothing is waiting."));
  if (pendingParts.length) out.push(h("section", { class: "card alert-warn" }, h("h2", {}, "Participant requests"),
    h("ul", { class: "list" }, pendingParts.map((p) => h("li", {},
      h("p", {}, h("strong", {}, p.name), ` (${p.kind}, ${p.regulator_ref || "no ref"}): `,
        `${p.pending_request.action}`, p.pending_request.capabilities ? ` ${p.pending_request.capabilities.join(", ")}` : ""),
      h("p", { class: "muted small" }, `asked by ${p.pending_request.requested_by}, ${when(p.pending_request.requested_at)}`,
        p.register_match ? ` · on the register as "${p.register_match.name}"` : " · not on a loaded register"),
      h("div", { class: "row" },
        h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/participants/${p.participant_id}/approve`), "Approved.") }, "Approve"),
        h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/participants/${p.participant_id}/reject`), "Rejected.") }, "Reject")))))));
  if (pendingCerts.length) out.push(h("section", { class: "card alert-warn" }, h("h2", {}, "Certificate pins"),
    h("ul", { class: "list" }, pendingCerts.map(({ p, c }) => h("li", {},
      h("p", {}, h("strong", {}, p.name), `: ${c.subject || "certificate"}`),
      h("p", { class: "muted small" }, `SHA-256 ${c.fingerprint}`, c.added_by ? ` · asked by ${c.added_by}` : "",
        c.not_after ? ` · valid until ${when(c.not_after)}` : ""),
      h("div", { class: "row" },
        h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/participants/${p.participant_id}/certificates/${c.fingerprint}/approve`), "Pinned.") }, "Approve pin"),
        h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("DELETE", `/v1/admin/participants/${p.participant_id}/certificates/${c.fingerprint}`), "Removed.") }, "Remove")))))));
  if (pendingFeeds.length) out.push(h("section", { class: "card alert-warn" }, h("h2", {}, "Register feeds"),
    h("ul", { class: "list" }, pendingFeeds.map((f) => h("li", {},
      h("p", {}, h("strong", {}, f.kind), ` from ${f.url} (${f.format}${f.signed ? ", signed" : ", NOT signed"})`),
      h("p", { class: "muted small" }, `configured by ${f.configured_by} · suspends on removal: ${f.auto_suspend ? "yes" : "no"} · holds if more than ${f.max_drop_pct}% vanish`),
      h("div", { class: "row" }, h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/register-feeds/${f.kind}/approve`), "Feed approved.") }, "Approve feed")))))));
  if (held.length) out.push(h("section", { class: "card alert-bad" }, h("h2", {}, "Held register refreshes"),
    h("ul", { class: "list" }, held.map((f) => h("li", {},
      h("p", {}, h("strong", {}, f.kind), `: ${f.held.reason}`),
      h("p", { class: "muted small" }, `${f.held.entities} entities in the new list · would remove: ${f.held.removes.slice(0, 15).join(", ")}${f.held.removes.length > 15 ? " ..." : ""}`),
      h("div", { class: "row" },
        h("button", { class: "danger", onclick: (e) => { if (window.confirm(`Apply it? Participants whose licence vanished will be suspended.`)) act(e.target, () => api("POST", `/v1/admin/register-feeds/${f.kind}/held/apply`), "Applied."); } }, "Apply"),
        h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("DELETE", `/v1/admin/register-feeds/${f.kind}/held`), "Discarded.") }, "Discard")))))));
  return out;
}

// ------------------------------------------------------------------ participants
async function participantsView() {
  const parts = await api("GET", "/v1/admin/participants");
  const name = h("input", { id: "p-name", required: true, maxlength: 120 });
  const kind = h("select", { id: "p-kind" }, ["bank", "small_finance_bank", "payments_bank", "nbfc", "ppi_issuer", "tpap", "telecom"].map((k) => h("option", { value: k }, k)));
  const ref = h("input", { id: "p-ref", required: true, maxlength: 60 });
  const keyBox = h("div");
  return [h("h1", {}, "Participants"),
    h("section", { class: "card" }, h("ul", { class: "list" }, parts.length ? parts.map((p) => h("li", {},
      h("div", { class: "row space" }, h("strong", {}, p.name), statusPill(p.status)),
      h("p", { class: "small" }, `${p.kind} · ${p.regulator_ref || "no ref"} · ${p.capabilities.join(", ") || "no capabilities"}`),
      h("p", { class: "muted small" }, p.register_match ? `register: ${p.register_match.name} (${p.register_match.as_of})` : "not on a loaded register",
        ` · pinned certificates: ${p.mtls.pinned_certificates}`, p.status_reason ? ` · ${p.status_reason}` : ""),
      h("div", { class: "row" },
        p.status === "active" ? h("button", { class: "danger", onclick: (e) => { const why = ask(`Suspend ${p.name}? Reason:`); if (why) act(e.target, () => api("POST", `/v1/admin/participants/${p.participant_id}/suspend`, { reason: why }), "Suspended."); } }, "Suspend") : null,
        p.status === "suspended" ? h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/participants/${p.participant_id}/reinstate`), "Reinstatement requested; another operator approves it.") }, "Request reinstatement") : null,
        p.status !== "offboarded" ? h("button", { class: "secondary", onclick: (e) => { const why = ask(`Offboard ${p.name} for good? Reason:`); if (why) act(e.target, () => api("POST", `/v1/admin/participants/${p.participant_id}/offboard`, { reason: why }), "Offboarded."); } }, "Offboard") : null))) : h("li", { class: "empty" }, "No participants yet."))),
    h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      const btn = e.target.querySelector("button");
      btn.disabled = true;
      try {
        const out = await api("POST", "/v1/admin/participants", { name: name.value.trim(), kind: kind.value, regulator_ref: ref.value.trim() });
        keyBox.replaceChildren(h("div", { class: "card alert-warn" }, h("p", {}, h("strong", {}, "API key (shown once): ")),
          h("input", { readonly: true, value: out.api_key, onfocus: (ev) => ev.target.select() }),
          h("p", { class: "muted small" }, `Status ${out.status}. Send the key to the participant over a secure channel; a second operator must approve.`)));
      } catch (err) { toast(err.message); } finally { btn.disabled = false; }
    } }, h("h2", {}, "Register a participant"),
      h("label", { for: "p-name" }, "Name"), name, h("label", { for: "p-kind" }, "Kind"), kind,
      h("label", { for: "p-ref" }, "Regulator reference (licence number)"), ref,
      h("div", { class: "row mt" }, h("button", { type: "submit" }, "Register")), keyBox)];
}

// ------------------------------------------------------------------ fraud payees
async function watchlistView() {
  const list = await api("GET", "/v1/admin/watchlist");
  const decide = (p, what) => (e) => {
    const why = ask(what === "confirm" ? `Confirm fraud for ${p.payee}? Payments to it will be blocked. Reason:` :
      `Clear ${p.payee}? Earlier reports stop counting. Reason:`);
    if (why) act(e.target, () => api("POST", `/v1/admin/watchlist/${encodeURIComponent(p.payee)}/${what}`, { reason: why }),
      what === "confirm" ? "Confirmed: payments to it are blocked." : "Cleared.");
  };
  return [h("h1", {}, "Fraud payees"),
    h("p", { class: "muted" }, "Payees banks reported after confirming a fraud. One bank's report holds payments for a guardian; two banks, or your confirmation, block them."),
    h("section", { class: "card" }, list.length ? h("ul", { class: "list" }, list.map((p) => h("li", {},
      h("div", { class: "row space" }, h("strong", {}, p.payee),
        pill(p.status, p.status === "confirmed" ? "bad" : p.status === "reported" ? "warn" : "")),
      p.reports.map((r) => h("p", { class: "small" }, `${r.name}: ${r.reason}`, r.evidence_ref ? ` (case ${r.evidence_ref})` : "",
        h("span", { class: "muted" }, ` · ${when(r.reported_at)}`))),
      p.operator_decision ? h("p", { class: "muted small" }, `${p.operator_decision.decision} by ${p.operator_decision.operator}: ${p.operator_decision.reason}`) : null,
      h("div", { class: "row" },
        p.status !== "confirmed" ? h("button", { class: "danger", onclick: decide(p, "confirm") }, "Confirm fraud") : null,
        p.status !== "none" ? h("button", { class: "secondary", onclick: decide(p, "clear") }, "Clear (reported by mistake)") : null))))
      : h("p", { class: "empty" }, "No payee has been reported."))];
}

// ------------------------------------------------------------------ scam-signal tuning
const pct = (x) => (x === null || x === undefined ? "–" : `${Math.round(x * 1000) / 10}%`);
const SETTING_LABELS = {
  large_multiple: "Much larger than usual (× largest in 90 days)", large_min: "Size that counts (paise)",
  min_prior: "Earlier payments needed", burst_count: "New payees in 24 h", night_start: "Night from (hour)",
  night_end: "Night until (hour)",
};

async function signalsView() {
  const [rep, settings] = await Promise.all([api("GET", "/v1/admin/signals/report?days=90"), api("GET", "/v1/admin/signals/settings")]);
  const row = (label, m) => h("tr", {}, h("td", {}, label), h("td", {}, String(m.held)), h("td", {}, pct(m.hold_rate)),
    h("td", {}, pct(m.precision)), h("td", {}, pct(m.recall)));
  const table = (rows) => h("table", { class: "grid" },
    h("thead", {}, h("tr", {}, ["Signal", "Held", "Hold rate", "Precision", "Recall"].map((x) => h("th", {}, x)))), h("tbody", {}, rows));
  const p = settings.pending;
  return [h("h1", {}, "Scam signals"),
    h("p", { class: "muted" }, `Last ${rep.days} days: ${rep.checks} protected payments, ${rep.labelled} labelled by banks, ${rep.confirmed_fraud} confirmed fraud.`),
    rep.note ? h("p", { class: "card alert-warn" }, rep.note) : null,
    h("section", { class: "card" }, h("h2", {}, "How each signal does"),
      table([row("Any signal", rep.all_signals), ...Object.entries(rep.per_signal).map(([k, m]) => row(k, m))])),
    h("section", { class: "card" }, h("h2", {}, "Thresholds"),
      h("dl", { class: "rules" }, Object.entries(settings.active).map(([k, v]) => [h("dt", {}, SETTING_LABELS[k] || k), h("dd", {}, String(v))])),
      p ? h("div", { class: "card alert-warn mt" },
        h("p", {}, `Waiting for a second operator: ${Object.entries(p.settings).filter(([k, v]) => v !== settings.active[k]).map(([k, v]) => `${k} → ${v}`).join(", ") || "no change"}`),
        h("p", { class: "muted small" }, `proposed by ${p.proposed_by}: ${p.reason || ""}`),
        h("div", { class: "row" },
          h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", "/v1/admin/signals/settings/approve"), "Approved.") }, "Approve"),
          h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", "/v1/admin/signals/settings/reject"), "Rejected.") }, "Reject"))) : null),
    h("section", { class: "card" }, h("h2", {}, "Suggestions"),
      rep.suggestions.length ? h("ul", { class: "list" }, rep.suggestions.map((s) => h("li", {},
        h("p", {}, h("strong", {}, SETTING_LABELS[s.setting] || s.setting), `: ${s.from} → ${s.to}`),
        h("p", { class: "muted small" }, `precision ${pct(s.precision)}, recall ${pct(s.recall)}, hold rate ${pct(s.hold_rate)}`),
        h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("PUT", "/v1/admin/signals/settings",
          { [s.setting]: s.to, reason: `tuning report: precision ${pct(s.precision)}, recall ${pct(s.recall)}` }), "Proposed; a second operator approves it.") }, "Propose this"))))
        : h("p", { class: "empty" }, "No change suggested.")),
    h("section", { class: "card" }, h("h2", {}, "Impact"),
      h("dl", { class: "rules" },
        h("dt", {}, "Held for review"), h("dd", {}, String(rep.impact.held_for_review)),
        h("dt", {}, "Stopped"), h("dd", {}, String(rep.impact.stopped)),
        h("dt", {}, "Amount stopped (₹)"), h("dd", {}, (rep.impact.amount_stopped / 100).toLocaleString("en-IN")),
        h("dt", {}, "Confirmed fraud stopped"), h("dd", {}, String(rep.impact.confirmed_fraud_stopped)),
        h("dt", {}, "Confirmed fraud that went through"), h("dd", {}, String(rep.impact.confirmed_fraud_that_went_through))))];
}

// ------------------------------------------------------------------ personal-data incidents
const CATS = ["mobile_numbers", "names", "dates_of_birth", "payment_history", "sign_in_sessions", "device_data"];

async function incidentsView() {
  const list = await api("GET", "/v1/admin/incidents");
  const out = h("pre", { class: "card small", hidden: true });
  const field = (id, label, type) => [h("label", { for: id }, label), h(type || "input", { id, required: true })];
  const form = h("form", { class: "card", onsubmit: async (e) => {
    e.preventDefault();
    const v = (id) => document.getElementById(id).value.trim();
    const cats = CATS.filter((c) => document.getElementById(`cat-${c}`).checked);
    const iso = (id) => new Date(v(id)).toISOString();
    try {
      await api("POST", "/v1/admin/incidents", { title: v("i-title"), description: v("i-desc"), detected_at: iso("i-detected"),
        occurred_from: iso("i-from"), occurred_to: iso("i-to"), categories: cats, cause: v("i-cause"), containment: v("i-contain") });
      toast("Recorded. The Board report is due within 72 hours of detection.");
      await render();
    } catch (err) { toast(err.message); }
  } }, h("h2", {}, "Record an incident"),
    field("i-title", "Title"), field("i-desc", "What happened", "textarea"),
    h("label", { for: "i-detected" }, "Detected at"), h("input", { id: "i-detected", type: "datetime-local", required: true }),
    h("label", { for: "i-from" }, "Exposure from"), h("input", { id: "i-from", type: "datetime-local", required: true }),
    h("label", { for: "i-to" }, "Exposure until"), h("input", { id: "i-to", type: "datetime-local", required: true }),
    h("p", { class: "small" }, "Data that may be affected:"),
    CATS.map((c) => h("label", { class: "small" }, h("input", { type: "checkbox", id: `cat-${c}` }), ` ${c.replace(/_/g, " ")}`)),
    h("label", { for: "i-cause" }, "Cause (so far)"), h("textarea", { id: "i-cause" }),
    h("label", { for: "i-contain" }, "Containment (so far)"), h("textarea", { id: "i-contain" }),
    h("div", { class: "row mt" }, h("button", { type: "submit", class: "danger" }, "Record incident")));
  return [h("h1", {}, "Personal-data incidents"),
    h("p", { class: "muted" }, "DPDP Act: tell affected people without delay; send the Data Protection Board a detailed report within 72 hours."),
    h("section", { class: "card" }, list.length ? h("ul", { class: "list" }, list.map((i) => h("li", {},
      h("div", { class: "row space" }, h("strong", {}, i.title), pill(i.status, i.status === "open" ? "warn" : "ok")),
      h("p", { class: "small" }, `${i.categories.join(", ")} · ${i.affected_people} people · detected ${when(i.detected_at)}`),
      h("p", { class: `small ${i.board.overdue ? "" : "muted"}` }, i.board.reported_at ? `Board report filed: ${i.board.reference}` :
        `${i.board.overdue ? "OVERDUE: " : ""}Board report due ${when(i.board.deadline)}`),
      h("div", { class: "row" },
        !i.notify.sent_at && !i.notify.proposed_by ? h("button", { class: "danger", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/incidents/${i.id}/notify`), "Proposed; a second operator sends it.") }, "Propose notifying people") : null,
        !i.notify.sent_at && i.notify.proposed_by ? h("button", { class: "danger", onclick: (e) => { if (window.confirm(`Send the notice to ${i.affected_people} people now?`)) act(e.target, () => api("POST", `/v1/admin/incidents/${i.id}/notify/approve`), "Sent."); } }, `Approve and send (proposed by ${i.notify.proposed_by})`) : null,
        h("button", { class: "secondary", onclick: async () => { out.textContent = JSON.stringify(await api("GET", `/v1/admin/incidents/${i.id}/board-report`), null, 2); out.hidden = false; } }, "Board report"),
        !i.board.reported_at ? h("button", { class: "secondary", onclick: (e) => { const ref = ask("The Board's acknowledgement number:"); if (ref) act(e.target, () => api("POST", `/v1/admin/incidents/${i.id}/board-report`, { reference: ref }), "Filing recorded."); } }, "Record filing") : null))))
      : h("p", { class: "empty" }, "No incidents recorded.")),
    out, form];
}

// ------------------------------------------------------------------ registers
async function registersView() {
  const [regs, feeds] = await Promise.all([api("GET", "/v1/admin/register"), api("GET", "/v1/admin/register-feeds")]);
  return [h("h1", {}, "Official registers"),
    h("section", { class: "card" }, h("h2", {}, "Loaded lists"), regs.length ? h("ul", { class: "list" }, regs.map((r) =>
      h("li", {}, h("div", { class: "row space" }, h("strong", {}, r.kind), h("span", {}, `${r.entities} entities`)),
        h("p", { class: "muted small" }, `${r.source} · as of ${r.as_of}`)))) : h("p", { class: "empty" }, "No register loaded.")),
    h("section", { class: "card" }, h("h2", {}, "Automatic feeds"), feeds.length ? h("ul", { class: "list" }, feeds.map((f) =>
      h("li", {}, h("div", { class: "row space" }, h("strong", {}, f.kind),
          f.status === "pending" ? pill("awaiting approval", "warn") : f.held ? pill("held", "bad") : f.last_error ? pill("error", "bad") : pill("ok", "ok")),
        h("p", { class: "small" }, `${f.url} · ${f.format}${f.sheet ? ` (sheet ${f.sheet})` : ""}${f.signed ? " · signed" : ""}`),
        h("p", { class: "muted small" }, f.last_checked_at ? `checked ${when(f.last_checked_at)}` : "never checked",
          f.last_changed_at ? ` · changed ${when(f.last_changed_at)}` : "", f.last_error ? ` · ${f.last_error}` : ""),
        f.status === "active" ? h("div", { class: "row" }, h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", `/v1/admin/register-feeds/${f.kind}/refresh`), "Checked.") }, "Check now")) : null))) :
      h("p", { class: "muted" }, "No feeds. Configure one with PUT /v1/admin/register-feeds/{kind} (see the README)."))];
}

// ------------------------------------------------------------------ system
async function systemView() {
  const out = h("pre", { class: "card small" });
  out.textContent = "Results appear here.";
  const run = (label, fn) => h("button", { class: "secondary", onclick: async (e) => {
    e.target.disabled = true;
    try { out.textContent = JSON.stringify(await fn(), null, 2); toast(`${label}: done.`); }
    catch (err) { out.textContent = err.message; toast(err.message); }
    finally { e.target.disabled = false; }
  } }, label);
  return [h("h1", {}, "System"),
    h("section", { class: "card" }, h("p", {}, "Checks and maintenance. Each action is recorded in the audit log."),
      h("div", { class: "row" },
        run("Verify the audit chain", () => api("GET", "/v1/admin/audit/verify")),
        run("Run the worker once", () => api("POST", "/v1/admin/sweep")),
        run("Re-encrypt under the newest data key", () => api("POST", "/v1/admin/data-key/rotate")))),
    out,
    h("div", { class: "row" }, h("button", { class: "secondary", onclick: signOut }, "Sign out"))];
}

// ------------------------------------------------------------------ shell
const VIEWS = { queue: queueView, participants: participantsView, watchlist: watchlistView, signals: signalsView, incidents: incidentsView, registers: registersView, system: systemView };

function show(nodes) {
  const v = document.getElementById("view");
  v.replaceChildren(...nodes);
  v.focus();
}

async function render() {
  state.tab = (location.hash || "#queue").slice(1);
  if (!VIEWS[state.tab]) state.tab = "queue";
  for (const a of document.querySelectorAll("nav a")) {
    if (a.dataset.tab === state.tab) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  try { show(await VIEWS[state.tab]()); }
  catch (e) { if (e.status === 401 || e.status === 403) signOut(); else show([h("p", { class: "card alert-bad" }, e.message)]); }
}

function start() {
  document.getElementById("nav").hidden = false;
  render();
}

window.addEventListener("hashchange", () => { if (credential()) render(); });
document.addEventListener("DOMContentLoaded", () => { if (credential()) start(); else show(signInView()); });

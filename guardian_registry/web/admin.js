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
const VIEWS = { queue: queueView, participants: participantsView, watchlist: watchlistView, registers: registersView, system: systemView };

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

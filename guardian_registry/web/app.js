"use strict";
/*
 * Guardian Registry web app.
 *
 * Talks only to this registry (same origin). Every piece of text that came from a person
 * (names, payees, alert bodies) is inserted with textContent, never as HTML.
 *
 * Sign-in: SMS code + a device key. The key is an ECDSA P-256 key made with WebCrypto as
 * NON-EXTRACTABLE and kept in IndexedDB, so page script can use it to sign but can't read
 * it out. It signs the server's one-time challenge, which lets the registry recognise this
 * browser as the same device later (see devicekeys.py), for example after a SIM swap.
 */

const TOKEN_KEY = "gr.token";
const REFRESH_MS = 20000;

// ------------------------------------------------------------------ DOM helpers
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

/** A view's list of children, without the empty slots left by `cond ? node : null`. */
const nodes = (list) => list.flat(Infinity).filter((n) => n !== null && n !== undefined && n !== false);

const $ = (sel) => document.querySelector(sel);
const view = () => $("#view");

function toast(msg, ms = 4000) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, ms);
}

function rupees(paise) {
  if (paise === null || paise === undefined) return "No limit";
  return (paise / 100).toLocaleString("en-IN", { style: "currency", currency: "INR", maximumFractionDigits: 0 });
}

function when(isoText) {
  if (!isoText) return "";
  return new Date(isoText).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" });
}

// ------------------------------------------------------------------ API
class ApiError extends Error {
  constructor(status, body) {
    super(ApiError.message(body) || `Request failed (${status})`);
    this.status = status;
    this.body = body;
  }

  static message(body) {
    if (!body) return "";
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return body.detail.map((d) => d.msg).join("; ");
    return "";
  }
}

async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) {
    if (r.status === 401 && token && !path.startsWith("/v1/auth/")) {
      localStorage.removeItem(TOKEN_KEY);
      route();
    }
    throw new ApiError(r.status, data);
  }
  return data;
}

/** Run an action from a button: disable it, show the result or the error. */
async function act(button, fn, okMessage) {
  button.disabled = true;
  try {
    const out = await fn();
    if (okMessage) toast(typeof okMessage === "function" ? okMessage(out) : okMessage);
    await refresh();
    return out;
  } catch (e) {
    toast(e.message || "Something went wrong", 7000);
  } finally {
    button.disabled = false;
  }
}

// ------------------------------------------------------------------ device key
const DeviceKey = {
  async open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open("guardian-registry", 1);
      req.onupgradeneeded = () => req.result.createObjectStore("keys");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },

  async get() {
    const db = await this.open();
    const existing = await new Promise((resolve, reject) => {
      const r = db.transaction("keys").objectStore("keys").get("device");
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    if (existing) return existing;
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    await new Promise((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      tx.objectStore("keys").put(pair, "device");
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
    return pair;
  },

  async publicKey() {
    const pair = await this.get();
    return b64(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
  },

  async keyId() {
    const spki = await crypto.subtle.exportKey("spki", (await this.get()).publicKey);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
    return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  },

  /** Sign 'guardian-registry/v1:' + challenge; the registry expects a DER signature. */
  async prove() {
    const { challenge } = await api("POST", "/v1/auth/challenge");
    const pair = await this.get();
    const msg = new TextEncoder().encode("guardian-registry/v1:" + challenge);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, msg));
    return { device_key: await this.publicKey(), challenge, device_proof: b64(rawToDer(raw)), platform: "web" };
  },
};

function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** WebCrypto gives r||s (64 bytes); ASN.1 DER wants SEQUENCE { INTEGER r, INTEGER s }. */
function rawToDer(raw) {
  const int = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) v = Uint8Array.of(0, ...v);
    return Uint8Array.of(0x02, v.length, ...v);
  };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

// ------------------------------------------------------------------ labels
const RULE_LABELS = [
  ["per_txn_limit", "Most per payment", rupees],
  ["daily_limit", "Most per day (all banks)", rupees],
  ["approval_threshold", "Guardian approves from", rupees],
  ["new_payee_delay_threshold", "Wait on new payees from", rupees],
  ["cooling_off_minutes", "Wait time", (m) => `${m} min`],
  ["approval_timeout_minutes", "Time for guardian to answer", (m) => `${m} min`],
  ["blocked_channels", "Blocked channels", (c) => (c && c.length ? c.join(", ").toUpperCase() : "None")],
  ["require_verified_guardian", "Only bank-verified guardians approve", (b) => (b ? "Yes" : "No")],
  ["sim_swap_hold", "Hold payments after a SIM change", (b) => (b ? "Yes" : "No")],
];

const CHANGE_LABELS = {
  update_rules: "Loosen payment limits",
  kill_switch_off: "Switch payments back on",
  remove_guardian: "Remove a guardian",
  change_mobile: "Move to a new number",
};

const STATUS = {
  allowed: ["Allowed", "ok"], approved: ["Approved", "ok"], released: ["Released", "ok"],
  pending_approval: ["Waiting for approval", "warn"], cooling_off: ["On hold", "warn"],
  blocked: ["Blocked", "bad"], denied: ["Denied", "bad"], expired: ["Expired", "bad"],
  cancelled: ["Cancelled", ""], failed: ["Failed", ""],
};

function statusPill(status) {
  const [text, cls] = STATUS[status] || [status, ""];
  return h("span", { class: `pill ${cls}` }, text);
}

// ------------------------------------------------------------------ sign-in
function signInView() {
  $("#nav").hidden = true;
  $("#banner").hidden = true;
  const state = { mobile: "", needName: false };
  const root = h("section", { class: "card" });

  const step1 = () => {
    root.replaceChildren(
      h("h1", {}, "Sign in"),
      h("p", { class: "muted" }, "We'll send a 6-digit code to your mobile number."),
      h("form", { onsubmit: async (e) => {
        e.preventDefault();
        const btn = e.target.querySelector("button");
        btn.disabled = true;
        try {
          state.mobile = e.target.mobile.value.trim();
          const out = await api("POST", "/v1/auth/otp", { mobile: state.mobile });
          step2(out.dev_code);
        } catch (err) {
          toast(err.message, 7000);
        } finally {
          btn.disabled = false;
        }
      } },
        h("label", { for: "mobile" }, "Mobile number"),
        h("input", { id: "mobile", name: "mobile", type: "tel", inputmode: "tel", autocomplete: "tel",
                     placeholder: "98765 43210", required: true }),
        h("div", { class: "row mt" }, h("button", { type: "submit" }, "Send code"))));
    root.querySelector("input").focus();
  };

  const step2 = (devCode) => {
    root.replaceChildren(
      h("h1", {}, "Enter the code"),
      h("p", { class: "muted" }, `Sent to ${state.mobile}. It works for 5 minutes.`),
      devCode ? h("p", { class: "pill warn" }, `Development mode code: ${devCode}`) : null,
      h("form", { onsubmit: async (e) => {
        e.preventDefault();
        const f = e.target;
        const btn = f.querySelector("button[type=submit]");
        btn.disabled = true;
        try {
          const proof = await DeviceKey.prove();
          const out = await api("POST", "/v1/auth/verify", {
            mobile: state.mobile, code: f.code.value.trim(),
            display_name: f.name && f.name.value.trim() ? f.name.value.trim() : null, ...proof,
          });
          localStorage.setItem(TOKEN_KEY, out.token);
          if (out.new_user) toast("Welcome! Your account is set up.");
          else if (out.restricted) toast("Signed in. This device is restricted for now; see the note at the top.", 7000);
          location.hash = "#me";
          route();
        } catch (err) {
          if (/send display_name/.test(err.message)) {
            state.needName = true;
            step2(devCode);
            toast("This number is new here. Add your name to create your account.", 7000);
          } else {
            toast(err.message, 7000);
          }
        } finally {
          btn.disabled = false;
        }
      } },
        h("label", { for: "code" }, "6-digit code"),
        h("input", { id: "code", name: "code", class: "code", inputmode: "numeric", autocomplete: "one-time-code",
                     maxlength: 6, required: true, value: devCode || "" }),
        state.needName ? [
          h("label", { for: "name" }, "Your name"),
          h("input", { id: "name", name: "name", autocomplete: "name", required: true, maxlength: 80 }),
        ] : null,
        h("div", { class: "row mt" },
          h("button", { type: "submit" }, state.needName ? "Create account" : "Sign in"),
          h("button", { type: "button", class: "secondary", onclick: step1 }, "Use another number"))));
    root.querySelector(state.needName ? "#name" : "#code").focus();
  };

  step1();
  return [
    h("h1", {}, "Protect payments for the people you care about"),
    h("p", { class: "muted" },
      "Set limits once and every bank checks them. Ask someone you trust to approve large payments."),
    root,
  ];
}

// ------------------------------------------------------------------ my protection
async function meView() {
  const [me, rules, security, guardians, changes, payments, presets] = await Promise.all([
    api("GET", "/v1/me"), api("GET", "/v1/me/rules"), api("GET", "/v1/me/security"),
    api("GET", "/v1/me/guardians"), api("GET", "/v1/me/changes"), api("GET", "/v1/me/payments?limit=10"),
    api("GET", "/v1/presets"),
  ]);
  setBanner(security.this_session);
  const paused = rules.kill_switch;
  const pending = changes.filter((c) => c.status === "pending");

  const killButton = paused
    ? h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", "/v1/me/kill-switch/off"),
        (out) => (out.applied ? "Payments are back on." : "Your request is held for 24 hours. Your guardians can approve it sooner.")) },
        "Switch payments back on")
    : h("button", { class: "danger", onclick: (e) => act(e.target, () => api("POST", "/v1/me/kill-switch/on"),
        "All payments are paused.") }, "Pause all payments");

  const presetSelect = h("select", { id: "preset", "aria-label": "Preset" },
    Object.entries(presets).map(([name, p]) => h("option", { value: name }, p.label)));

  const inviteForm = h("form", { onsubmit: (e) => {
    e.preventDefault();
    const mobile = e.target.gmobile.value.trim();
    act(e.target.querySelector("button"), () => api("POST", "/v1/me/guardians", { mobile }),
      "Invitation sent. They need to accept it in their app.").then(() => { e.target.reset(); });
  } },
    h("label", { for: "gmobile" }, "Invite a guardian by mobile number"),
    h("div", { class: "row" },
      h("input", { id: "gmobile", name: "gmobile", type: "tel", required: true, class: "grow" }),
      h("button", { type: "submit" }, "Invite")));

  return [
    h("h1", {}, `Hello, ${me.display_name}`),
    h("p", { class: "muted small" }, `Identity: ${identityText(me.identity_level)}`),

    h("section", { class: `card ${paused ? "alert-bad" : "alert-ok"}` },
      h("div", { class: "big-status" }, h("span", { class: `dot ${paused ? "bad" : "ok"}` }),
        paused ? "Payments are paused" : "Payments are on"),
      h("p", { class: "muted" }, paused
        ? "No bank will send money from your accounts until payments are switched back on."
        : "If someone is pressuring you to pay, pause everything. You can switch back on later."),
      h("div", { class: "row" }, killButton)),

    security.sim_swap_window_open ? h("section", { class: "card alert-warn" },
      h("h2", {}, "Your SIM card was reported changed"),
      h("p", {}, `Until ${when(security.window_ends_at)}, larger payments are held and new sign-ins can't approve anything.`),
      h("p", { class: "muted" }, "If you changed your SIM yourself, confirm it from this phone. If you didn't, call your mobile operator now."),
      h("div", { class: "row" },
        h("button", { onclick: (e) => act(e.target, () => api("POST", "/v1/me/security/confirm-sim-change"),
          "Thanks. Normal protection applies again.") }, "Yes, I changed my SIM"))) : null,

    pending.length ? h("section", { class: "card alert-warn" },
      h("h2", {}, "Changes waiting"),
      h("ul", { class: "list" }, pending.map((c) => h("li", {},
        h("strong", {}, CHANGE_LABELS[c.kind] || c.kind),
        h("p", { class: "muted small" }, `Takes effect ${when(c.effective_at)} unless a guardian stops it.`))))) : null,

    h("section", { class: "card" },
      h("h2", {}, "My rules"),
      h("dl", { class: "rules" }, RULE_LABELS.map(([k, label, fmt]) => [h("dt", {}, label), h("dd", {}, fmt(rules[k]))])),
      h("label", { for: "preset" }, "Use a ready-made set"),
      h("div", { class: "row" }, presetSelect,
        h("button", { class: "secondary", onclick: (e) => act(e.target,
          () => api("POST", `/v1/me/rules/preset/${encodeURIComponent(presetSelect.value)}`),
          (out) => (out.held ? "Stricter parts apply now; looser parts wait 24 hours." : "Applied.")) }, "Apply")),
      h("p", { class: "muted small" }, "Making rules stricter works at once. Loosening them waits 24 hours, and your guardians can stop it.")),

    h("section", { class: "card" },
      h("h2", {}, "My guardians"),
      guardians.length ? h("ul", { class: "list" }, guardians.map((g) => h("li", { class: "row space" },
        h("span", {}, h("strong", {}, g.guardian_name), " ", h("span", { class: "muted small" }, identityText(g.guardian_identity_level))),
        h("span", { class: `pill ${g.status === "active" ? "ok" : g.status === "invited" ? "warn" : ""}` }, g.status))))
        : h("p", { class: "muted" }, "No guardians yet. A guardian can approve large payments and pause payments for you."),
      inviteForm),

    h("section", { class: "card" },
      h("h2", {}, "Recent payments"),
      payments.length ? h("ul", { class: "list" }, payments.map(paymentItem)) : h("p", { class: "empty" }, "No payments checked yet.")),

    h("section", { class: "card" },
      h("h2", {}, "Lost your phone?"),
      h("p", { class: "muted" }, "This signs you out everywhere and holds larger payments for 72 hours."),
      h("button", { class: "danger", onclick: (e) => {
        if (!confirm("Sign out of every device and hold larger payments for 72 hours?")) return;
        act(e.target, () => api("POST", "/v1/me/security/lost-phone"), "Done. Every device is signed out.");
      } }, "Report lost phone")),
  ];
}

function identityText(level) {
  return { bank_verified: "verified by a bank", bank_min_kyc: "basic bank check", otp: "phone number only" }[level] || level;
}

function paymentItem(p, extra) {
  return h("li", {},
    h("div", { class: "row space" }, h("span", { class: "amount" }, rupees(p.amount)), statusPill(p.status)),
    h("p", {}, `To ${p.payee}`, extra ? [" · ", extra] : null),
    h("p", { class: "muted small" }, when(p.created_at), p.reasons && p.reasons.length ? ` · ${p.reasons.join("; ")}` : ""));
}

// ------------------------------------------------------------------ guardian
async function guardianView() {
  const [inbox, wards] = await Promise.all([api("GET", "/v1/guardian/inbox"), api("GET", "/v1/guardian/wards")]);
  const names = Object.fromEntries(wards.map((w) => [w.principal_id, w.principal_name]));
  const active = wards.filter((w) => w.status === "active");
  const out = [h("h1", {}, "People I protect")];

  if (inbox.invitations.length) {
    out.push(h("section", { class: "card alert-warn" }, h("h2", {}, "Guardian requests"),
      h("ul", { class: "list" }, inbox.invitations.map((g) => h("li", {},
        h("p", {}, h("strong", {}, g.principal_name), " asked you to be their payment guardian."),
        h("div", { class: "row" },
          h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/invitations/${g.id}/accept`), `You now protect ${g.principal_name}.`) }, "Accept"),
          h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/invitations/${g.id}/decline`), "Declined.") }, "Decline")))))));
  }

  const waiting = inbox.held_payments;
  out.push(h("section", { class: `card ${waiting.length ? "alert-warn" : ""}` }, h("h2", {}, "Payments waiting"),
    waiting.length ? h("ul", { class: "list" }, waiting.map((p) => {
      const li = paymentItem(p, names[p.principal_id] ? `from ${names[p.principal_id]}` : null);
      const buttons = p.status === "pending_approval"
        ? [h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/payments/${p.check_id}/approve`), "Approved.") }, "Approve"),
           h("button", { class: "danger", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/payments/${p.check_id}/deny`), "Denied. The payment will not go through.") }, "Deny")]
        : [h("button", { class: "danger", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/payments/${p.check_id}/cancel`), "Cancelled.") }, "Stop this payment")];
      if (p.approval_expires_at) li.append(h("p", { class: "muted small" }, `Answer by ${when(p.approval_expires_at)}`));
      if (p.release_at) li.append(h("p", { class: "muted small" }, `Goes through at ${when(p.release_at)} unless stopped`));
      li.append(h("p", { class: "muted small" }, "Not sure? Call them on a number you know before approving."), h("div", { class: "row" }, buttons));
      return li;
    })) : h("p", { class: "empty" }, "Nothing is waiting for you.")));

  if (inbox.pending_changes.length) {
    out.push(h("section", { class: "card alert-warn" }, h("h2", {}, "Protection changes waiting"),
      h("ul", { class: "list" }, inbox.pending_changes.map((c) => h("li", {},
        h("p", {}, h("strong", {}, names[c.principal_id] || "Someone"), ` wants to: ${CHANGE_LABELS[c.kind] || c.kind}`),
        h("p", { class: "muted small" }, `Happens ${when(c.effective_at)} unless you stop it. Scammers often ask people to do this.`),
        h("div", { class: "row" },
          h("button", { class: "danger", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/changes/${c.id}/veto`), "Stopped.") }, "Stop it"),
          h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/changes/${c.id}/approve`), "Approved.") }, "Approve now")))))));
  }

  if (inbox.recoveries && inbox.recoveries.length) {
    out.push(h("section", { class: "card alert-bad" }, h("h2", {}, "Account recovery requests"),
      h("ul", { class: "list" }, inbox.recoveries.map((r) => h("li", {},
        h("p", {}, h("strong", {}, r.person_name), ` wants to move their account to ${r.new_number}.`),
        h("p", { class: "muted small" }, "Only approve if you have spoken to them yourself, on a call YOU placed or in person. If in doubt, deny."),
        r.status === "pending" && new Date(r.vouching_opens_at) > new Date()
          ? h("p", { class: "muted small" }, `You can approve from ${when(r.vouching_opens_at)}.`) : null,
        h("div", { class: "row" },
          r.status === "pending" ? h("button", { class: "ok", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/recoveries/${r.recovery_id}/approve`), "Thank you. Your vouch is recorded.") }, "I spoke to them: approve") : null,
          h("button", { class: "danger", onclick: (e) => act(e.target, () => api("POST", `/v1/guardian/recoveries/${r.recovery_id}/deny`), "Stopped.") }, "Deny")))))));
  }

  out.push(h("section", { class: "card" }, h("h2", {}, "People I protect"),
    active.length ? h("ul", { class: "list" }, active.map((w) => h("li", { class: "row space" },
      h("strong", {}, w.principal_name),
      h("button", { class: "danger", onclick: (e) => {
        if (!confirm(`Pause all payments for ${w.principal_name}?`)) return;
        act(e.target, () => api("POST", `/v1/guardian/wards/${w.principal_id}/kill-switch/on`), `Payments paused for ${w.principal_name}.`);
      } }, "Pause their payments"))))
      : h("p", { class: "muted" }, "You don't protect anyone yet. Someone has to invite you from their app.")));
  return out;
}

// ------------------------------------------------------------------ alerts
async function alertsView() {
  const items = await api("GET", "/v1/me/notifications?limit=50");
  const unread = items.filter((n) => !n.read).length;
  return [
    h("div", { class: "row space" }, h("h1", {}, "Alerts"),
      unread ? h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("POST", "/v1/me/notifications/read", {}), "All marked as read.") }, "Mark all read") : null),
    h("section", { class: "card" }, items.length ? h("ul", { class: "list" }, items.map((n) => h("li", {},
      h("div", { class: "row space" }, h("strong", {}, n.title), n.read ? null : h("span", { class: "pill warn" }, "New")),
      h("p", {}, n.body),
      h("p", { class: "muted small" }, when(n.created_at))))) : h("p", { class: "empty" }, "No alerts yet.")),
  ];
}

// ------------------------------------------------------------------ devices
async function devicesView() {
  const [devices, security, mine] = await Promise.all([api("GET", "/v1/me/devices"), api("GET", "/v1/me/security"), DeviceKey.keyId()]);
  setBanner(security.this_session);
  return [
    h("h1", {}, "Devices"),
    h("section", { class: "card" },
      h("p", { class: "muted" }, "Each phone or browser you sign in on has its own key. A new one can't approve payments for 24 hours."),
      devices.length ? h("ul", { class: "list" }, devices.map((d) => h("li", { class: "row space" },
        h("span", {}, h("strong", {}, d.key_id === mine ? "This device" : `Device ${d.key_id.slice(0, 8)}`),
          h("br"), h("span", { class: "muted small" }, `Added ${when(d.created_at)}${d.last_used_at ? ` · last used ${when(d.last_used_at)}` : ""}`)),
        h("span", { class: "row" },
          h("span", { class: `pill ${d.status === "trusted" ? "ok" : d.status === "probation" ? "warn" : ""}` }, d.status),
          d.status !== "revoked" && d.key_id !== mine
            ? h("button", { class: "secondary", onclick: (e) => act(e.target, () => api("DELETE", `/v1/me/devices/${d.key_id}`), "Removed and signed out.") }, "Remove")
            : null))))
        : h("p", { class: "empty" }, "No device keys yet.")),
    h("section", { class: "card" }, h("h2", {}, "Sign out"),
      h("div", { class: "row" },
        h("button", { class: "secondary", onclick: () => signOut(false) }, "Sign out here"),
        h("button", { class: "secondary", onclick: () => signOut(true) }, "Sign out everywhere"))),
  ];
}

async function signOut(everywhere) {
  try { await api("POST", "/v1/auth/logout", { everywhere }); } catch (e) { /* already signed out */ }
  localStorage.removeItem(TOKEN_KEY);
  location.hash = "";
  route();
}

// ------------------------------------------------------------------ chrome
function setBanner(session) {
  const b = $("#banner");
  if (session && session.restricted) {
    b.textContent = "This sign-in is restricted for now: " + session.reasons.join("; ") +
      ". You can still pause payments, deny or stop payments, and make rules stricter.";
    b.hidden = false;
  } else {
    b.hidden = true;
  }
}

async function updateBadges() {
  try {
    const [inbox, alerts] = await Promise.all([api("GET", "/v1/guardian/inbox"), api("GET", "/v1/me/notifications?unread_only=true&limit=100")]);
    const n = inbox.held_payments.length + inbox.pending_changes.length + inbox.invitations.length + (inbox.recoveries || []).length;
    const ib = $("#inbox-count"), ab = $("#alert-count");
    ib.textContent = n; ib.hidden = !n;
    ab.textContent = alerts.length; ab.hidden = !alerts.length;
  } catch (e) { /* badges are best effort */ }
}

const VIEWS = { me: meView, guardian: guardianView, alerts: alertsView, devices: devicesView };

async function route() {
  const signedIn = !!localStorage.getItem(TOKEN_KEY);
  if (!signedIn) {
    view().replaceChildren(...nodes(signInView()));
    return;
  }
  $("#nav").hidden = false;
  const tab = (location.hash || "#me").slice(1);
  const render = VIEWS[tab] || meView;
  document.querySelectorAll("#nav a").forEach((a) => a.toggleAttribute("aria-current", a.dataset.tab === tab));
  if (route.current !== tab) { route.current = tab; view().replaceChildren(h("p", { class: "empty" }, "Loading…")); }
  try {
    view().replaceChildren(...nodes(await render()));
  } catch (e) {
    if (localStorage.getItem(TOKEN_KEY)) view().replaceChildren(h("section", { class: "card alert-bad" }, h("p", {}, e.message)));
  }
  updateBadges();
}

async function refresh() {
  if (localStorage.getItem(TOKEN_KEY)) await route();
}

window.addEventListener("hashchange", () => { route(); view().focus(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
setInterval(() => {
  // don't redraw while someone is typing
  if (!document.hidden && !(document.activeElement && /INPUT|SELECT/.test(document.activeElement.tagName))) refresh();
}, REFRESH_MS);
route();

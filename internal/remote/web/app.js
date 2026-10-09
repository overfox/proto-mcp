"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const msg = (text, cls) => { const m = $("msg"); m.textContent = text || ""; m.className = cls || ""; };

  // base64url <-> ArrayBuffer for the WebAuthn JSON the server speaks.
  const b64uToBuf = (s) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
  };
  const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const creationOptions = (o) => {
    const pk = o.publicKey;
    pk.challenge = b64uToBuf(pk.challenge);
    pk.user.id = b64uToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    return { publicKey: pk };
  };
  const requestOptions = (o) => {
    const pk = o.publicKey;
    pk.challenge = b64uToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach((c) => { c.id = b64uToBuf(c.id); });
    return { publicKey: pk };
  };
  const credJSON = (c) => {
    const r = c.response, out = { id: c.id, rawId: bufToB64u(c.rawId), type: c.type, response: {
      clientDataJSON: bufToB64u(r.clientDataJSON) } };
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64u(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64u(r.authenticatorData);
      out.response.signature = bufToB64u(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
    }
    out.clientExtensionResults = c.getClientExtensionResults ? c.getClientExtensionResults() : {};
    return out;
  };

  const post = async (path, body) => {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  };

  // Passkey-verified action: approve one request, or turn Remote mode on.
  const verify = async (purpose, id) => {
    const begin = await post("/api/auth/begin", { purpose, id });
    const cred = await navigator.credentials.get(requestOptions(begin.options));
    return post("/api/auth/finish?sid=" + encodeURIComponent(begin.sid), credJSON(cred));
  };

  const hash = new URLSearchParams(location.hash.slice(1));
  const enrollToken = hash.get("enroll");
  const highlight = hash.get("a");

  // ---- enrolment ----------------------------------------------------
  if (enrollToken) {
    $("enroll").hidden = false;
    const ua = navigator.userAgent;
    $("devname").value = /SM-S928|S24 Ultra/i.test(ua) ? "Galaxy S24 Ultra"
      : /iPad|Macintosh.*Mobile/.test(ua) ? "iPad" : /iPhone/.test(ua) ? "iPhone"
      : /Android/.test(ua) ? "Android phone" : "Device";
    $("enrollBtn").onclick = async () => {
      $("enrollBtn").disabled = true;
      try {
        const opts = await post("/api/enroll/begin", { token: enrollToken, name: $("devname").value });
        const cred = await navigator.credentials.create(creationOptions(opts));
        const r = await fetch("/api/enroll/finish?t=" + encodeURIComponent(enrollToken), {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(credJSON(cred)) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
        history.replaceState(null, "", "/");
        $("enroll").hidden = true;
        msg("✓ " + j.name + " added. Bookmark this page or add it to your home screen.", "ok");
        start();
      } catch (e) {
        msg("Could not add this device: " + e.message, "bad");
        $("enrollBtn").disabled = false;
      }
    };
  }

  // ---- main view ----------------------------------------------------
  const busy = new Set();
  const render = (st) => {
    $("main").hidden = false;
    const conn = $("conn");
    const connected = st.connector === "unlocked";
    conn.textContent = connected ? "Connected" : st.connector === "locked" ? "Locked" : (st.connector || "Unknown");
    conn.className = "pill " + (connected ? "ok" : st.connector === "locked" ? "warn" : "muted");
    const note = $("connNote");
    note.hidden = connected;
    note.textContent = connected ? "" : (st.reason ? st.reason + ". " : "") +
      "Reconnecting needs Touch ID at the Mac.";
    $("remote").textContent = st.remote ? "On" : "Off";
    $("remote").className = "pill " + (st.remote ? "ok" : "muted");
    $("remoteOn").hidden = st.remote;
    $("remoteOff").hidden = !st.remote;

    $("ntfy").hidden = !st.ntfy_topic;
    $("ntfyServer").textContent = st.ntfy_server;
    $("ntfyTopic").textContent = st.ntfy_topic;
    const host = (st.ntfy_server || "").replace(/^https?:\/\//, "");
    $("ntfyLink").href = "ntfy://" + host + "/" + st.ntfy_topic;

    const list = $("pending");
    const ids = new Set(st.pending.map((p) => p.id));
    [...list.children].forEach((el) => { if (!ids.has(el.dataset.id)) el.remove(); });
    st.pending.forEach((p) => {
      if (list.querySelector('[data-id="' + p.id + '"]')) return;
      const card = document.createElement("div");
      card.className = "card approval" + (p.id === highlight ? " hl" : "");
      card.dataset.id = p.id;
      const h = document.createElement("div"); h.style.fontWeight = "600"; h.textContent = p.title;
      const body = document.createElement("pre"); body.textContent = p.body;
      const exp = document.createElement("div"); exp.className = "muted"; exp.style.marginTop = "8px";
      const left = Math.max(0, Math.round((new Date(p.expires) - Date.now()) / 1000));
      exp.textContent = "Expires in about " + left + "s";
      const btns = document.createElement("div"); btns.className = "btns";
      const ok = document.createElement("button"); ok.className = "primary"; ok.textContent = "Approve (fingerprint)";
      const no = document.createElement("button"); no.className = "danger"; no.textContent = "Decline";
      ok.onclick = async () => {
        if (busy.has(p.id)) return; busy.add(p.id); ok.disabled = no.disabled = true;
        try { await verify("approve", p.id); msg("✓ Approved", "ok"); card.remove(); }
        catch (e) { msg("Not approved: " + e.message, "bad"); ok.disabled = no.disabled = false; }
        busy.delete(p.id);
      };
      no.onclick = async () => {
        ok.disabled = no.disabled = true;
        try { await post("/api/decline", { id: p.id }); msg("Declined", "muted"); card.remove(); }
        catch (e) { msg(e.message, "bad"); }
      };
      btns.append(ok, no);
      card.append(h, body, exp, btns);
      list.append(card);
      if (p.id === highlight) card.scrollIntoView({ block: "center" });
    });
    $("none").hidden = st.pending.length > 0;
  };

  const refresh = async () => {
    try {
      const r = await fetch("/api/state", { cache: "no-store" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      render(await r.json());
    } catch (e) {
      msg("Can't reach your Mac (" + e.message + "). Is it on and connected to Tailscale?", "bad");
    }
  };

  $("remoteOn").onclick = async () => {
    try { await verify("remote_on"); msg("✓ Remote mode on", "ok"); } catch (e) { msg(e.message, "bad"); }
    refresh();
  };
  $("remoteOff").onclick = async () => {
    try { await post("/api/remote_off"); msg("Remote mode off — approvals go back to the Mac", "muted"); }
    catch (e) { msg(e.message, "bad"); }
    refresh();
  };
  $("lockBtn").onclick = async () => {
    if (!confirm("Lock the connector? Reconnecting will need Touch ID at the Mac.")) return;
    try { await post("/api/lock"); msg("Connector locked", "warn"); } catch (e) { msg(e.message, "bad"); }
    refresh();
  };

  let timer;
  function start() {
    refresh();
    clearInterval(timer);
    timer = setInterval(() => { if (!document.hidden) refresh(); }, 2000);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && timer) refresh(); });
  if (!enrollToken) start();
})();

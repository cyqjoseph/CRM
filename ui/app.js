(function () {
  "use strict";

  const cfg = window.CRM_CONFIG;
  const poolData = { UserPoolId: cfg.userPoolId, ClientId: cfg.userPoolClientId };
  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  let currentUser = null;
  let idToken = null;
  let pendingSignUpEmail = null;
  let mode = "signIn"; // signIn | signUp | confirm

  const el = (id) => document.getElementById(id);
  const show = (id) => el(id).classList.remove("hidden");
  const hide = (id) => el(id).classList.add("hidden");

  function setError(id, message) {
    if (!message) { hide(id); el(id).textContent = ""; return; }
    el(id).textContent = message;
    show(id);
  }

  // --- Auth ---

  function renderAuthMode() {
    setError("authError", null);
    setError("authMsg", null);
    if (mode === "signIn") {
      el("authTitle").textContent = "Sign in";
      el("authSubmit").textContent = "Sign in";
      el("authToggle").textContent = "Need an account? Sign up";
      hide("authCode");
    } else if (mode === "signUp") {
      el("authTitle").textContent = "Create account";
      el("authSubmit").textContent = "Sign up";
      el("authToggle").textContent = "Already have an account? Sign in";
      hide("authCode");
    } else {
      el("authTitle").textContent = "Verify email";
      el("authSubmit").textContent = "Confirm";
      el("authToggle").textContent = "Back to sign in";
      show("authCode");
    }
  }

  el("authToggle").addEventListener("click", () => {
    mode = mode === "signIn" ? "signUp" : "signIn";
    renderAuthMode();
  });

  el("authSubmit").addEventListener("click", () => {
    const email = el("authEmail").value.trim();
    const password = el("authPassword").value;
    if (mode === "signIn") signIn(email, password);
    else if (mode === "signUp") signUp(email, password);
    else confirmSignUp(email, el("authCode").value.trim());
  });

  function signUp(email, password) {
    setError("authError", null);
    userPool.signUp(
      email,
      password,
      [new AmazonCognitoIdentity.CognitoUserAttribute({ Name: "email", Value: email })],
      null,
      (err, result) => {
        if (err) return setError("authError", err.message || String(err));
        pendingSignUpEmail = email;
        mode = "confirm";
        renderAuthMode();
        setError("authMsg", "Check your email for a verification code.");
      }
    );
  }

  function confirmSignUp(email, code) {
    const target = email || pendingSignUpEmail;
    const user = new AmazonCognitoIdentity.CognitoUser({ Username: target, Pool: userPool });
    user.confirmRegistration(code, true, (err) => {
      if (err) return setError("authError", err.message || String(err));
      mode = "signIn";
      renderAuthMode();
      setError("authMsg", "Verified — you can sign in now.");
    });
  }

  function signIn(email, password) {
    setError("authError", null);
    const authDetails = new AmazonCognitoIdentity.AuthenticationDetails({
      Username: email,
      Password: password,
    });
    const user = new AmazonCognitoIdentity.CognitoUser({ Username: email, Pool: userPool });
    user.authenticateUser(authDetails, {
      onSuccess: (session) => {
        currentUser = user;
        idToken = session.getIdToken().getJwtToken();
        el("userEmail").textContent = email;
        show("userBar");
        hide("authView");
        show("appView");
        loadCerts();
      },
      onFailure: (err) => setError("authError", err.message || String(err)),
    });
  }

  el("signOutLink").addEventListener("click", () => {
    if (currentUser) currentUser.signOut();
    idToken = null;
    hide("appView");
    hide("userBar");
    show("authView");
  });

  // --- API helpers ---

  async function apiFetch(path, options) {
    const response = await fetch(cfg.apiUrl.replace(/\/$/, "") + path, {
      ...options,
      headers: { ...(options && options.headers), Authorization: idToken },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.message || `request failed (${response.status})`);
    return body;
  }

  // --- Tabs ---

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      ["certs", "ad", "audit"].forEach((t) => {
        el(`tab-${t}`).classList.toggle("hidden", t !== btn.dataset.tab);
      });
      if (btn.dataset.tab === "certs") loadCerts();
      if (btn.dataset.tab === "ad") loadAdAccounts();
    });
  });

  // --- Certificates ---

  function statusClass(daysLeft) {
    if (daysLeft <= 7) return "status-danger";
    if (daysLeft <= 30) return "status-warn";
    return "status-ok";
  }

  async function loadCerts() {
    setError("certsError", null);
    try {
      const data = await apiFetch("/certs", { method: "GET" });
      const rows = (data.items || [])
        .map((c) => {
          const days = Math.ceil((new Date(c.ExpiryDate) - new Date()) / 86400000);
          return `<tr>
            <td>${c.CertId}</td>
            <td>${c.Domain || ""}</td>
            <td class="${statusClass(days)}">${c.ExpiryDate} (${days}d)</td>
            <td>${c.Status || ""}</td>
            <td><button class="action" data-cert="${c.CertId}">Renew</button></td>
          </tr>`;
        })
        .join("");
      el("certsBody").innerHTML = rows || `<tr><td colspan="5">No certificates found.</td></tr>`;
      el("certsBody").querySelectorAll("button[data-cert]").forEach((b) => {
        b.addEventListener("click", () => renewCert(b.dataset.cert, b));
      });
    } catch (err) {
      setError("certsError", err.message);
    }
  }

  async function renewCert(certId, button) {
    button.disabled = true;
    try {
      await apiFetch(`/certs/${encodeURIComponent(certId)}/renew`, { method: "POST" });
      button.textContent = "Renewal started";
    } catch (err) {
      setError("certsError", err.message);
      button.disabled = false;
    }
  }

  // --- AD accounts ---

  async function loadAdAccounts() {
    setError("adError", null);
    try {
      const data = await apiFetch("/ad-accounts", { method: "GET" });
      const rows = (data.items || [])
        .map(
          (a) => `<tr>
            <td>${a.AccountIdHash}</td>
            <td>${a.NextRotationDate || ""}</td>
            <td>${a.RotationStatus || ""}</td>
            <td><button class="action" data-account="${a.AccountIdHash}">Rotate</button></td>
          </tr>`
        )
        .join("");
      el("adBody").innerHTML = rows || `<tr><td colspan="4">No AD accounts found.</td></tr>`;
      el("adBody").querySelectorAll("button[data-account]").forEach((b) => {
        b.addEventListener("click", () => rotateAccount(b.dataset.account, b));
      });
    } catch (err) {
      setError("adError", err.message);
    }
  }

  async function rotateAccount(accountId, button) {
    button.disabled = true;
    try {
      await apiFetch(`/ad-accounts/${encodeURIComponent(accountId)}/rotate`, { method: "POST" });
      button.textContent = "Rotation started";
    } catch (err) {
      setError("adError", err.message);
      button.disabled = false;
    }
  }

  // --- Audit ---

  // Detail is a DynamoDB map (crm_common.put_audit_event writes a dict, and the
  // Step Functions putItem states write one too), so interpolating it directly
  // renders the literal string "[object Object]" for every row.
  function formatDetail(detail) {
    if (!detail) return "";
    if (typeof detail === "string") return detail;
    return Object.entries(detail)
      .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`)
      .join(", ");
  }

  el("auditSearch").addEventListener("click", async () => {
    setError("auditError", null);
    const entityId = el("auditEntityId").value.trim();
    if (!entityId) return setError("auditError", "Enter an entity ID first.");
    try {
      const data = await apiFetch(`/audit?entityId=${encodeURIComponent(entityId)}`, { method: "GET" });
      const rows = (data.items || [])
        .map(
          (e) => `<tr>
            <td>${e.EventTimestamp}</td>
            <td>${e.EventType}</td>
            <td>${e.Outcome}</td>
            <td>${formatDetail(e.Detail)}</td>
          </tr>`
        )
        .join("");
      el("auditBody").innerHTML = rows || `<tr><td colspan="4">No audit events found.</td></tr>`;
    } catch (err) {
      setError("auditError", err.message);
    }
  });

  renderAuthMode();
})();

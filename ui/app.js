(function () {
  "use strict";

  const cfg = window.CRM_CONFIG;
  const poolData = { UserPoolId: cfg.userPoolId, ClientId: cfg.userPoolClientId };
  const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

  let currentUser = null;
  let idToken = null;
  let pendingSignUpEmail = null;
  let mode = "signIn"; // signIn | signUp | confirm
  let isAdmin = false;
  let modalAccountId = null;

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
        const groups = session.getIdToken().decodePayload()["cognito:groups"] || [];
        isAdmin = Array.isArray(groups) ? groups.includes("admins") : String(groups).split(",").includes("admins");
        el("passwordResetsTab").classList.toggle("hidden", !isAdmin);
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
    isAdmin = false;
    el("passwordResetsTab").classList.add("hidden");
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
      ["certs", "iam", "audit", "password-resets"].forEach((t) => {
        el(`tab-${t}`).classList.toggle("hidden", t !== btn.dataset.tab);
      });
      if (btn.dataset.tab === "certs") loadCerts();
      if (btn.dataset.tab === "iam") loadIamAccounts();
      if (btn.dataset.tab === "password-resets") loadPasswordResets();
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

  // --- IAM accounts ---

  async function loadIamAccounts() {
    setError("iamError", null);
    try {
      const data = await apiFetch("/iam/accounts", { method: "GET" });
      const rows = (data.items || [])
        .map(
          (a) => `<tr>
            <td>${a.UserName || ""}</td>
            <td>${a.AccountIdHash}</td>
            <td>${a.NextRotationDate || ""}</td>
            <td>${a.Status || ""}</td>
            <td>
              <button class="action" data-account="${a.AccountIdHash}">Rotate</button>
              <button class="action" data-details="${a.AccountIdHash}">Details</button>
            </td>
          </tr>`
        )
        .join("");
      el("iamBody").innerHTML = rows || `<tr><td colspan="5">No IAM accounts found.</td></tr>`;
      el("iamBody").querySelectorAll("button[data-account]").forEach((b) => {
        b.addEventListener("click", () => rotateAccount(b.dataset.account, b));
      });
      el("iamBody").querySelectorAll("button[data-details]").forEach((b) => {
        b.addEventListener("click", () => openAccountModal(b.dataset.details));
      });
    } catch (err) {
      setError("iamError", err.message);
    }
  }

  async function rotateAccount(accountId, button) {
    button.disabled = true;
    try {
      await apiFetch(`/iam/accounts/${encodeURIComponent(accountId)}/rotate`, { method: "POST" });
      button.textContent = "Rotation started";
    } catch (err) {
      setError("iamError", err.message);
      button.disabled = false;
    }
  }

  // --- Account detail modal + password reset requests ---

  function openAccountModal(accountId) {
    modalAccountId = accountId;
    el("accountModalBody").innerHTML = `<p>Account: <strong>${accountId}</strong></p>`;
    setError("resetRequestError", null);
    setError("resetRequestStatus", null);
    el("resetReason").value = "";
    el("requestResetBtn").disabled = false;
    el("requestResetBtn").textContent = "Request Password Reset";
    show("accountModal");
  }

  el("accountModalClose").addEventListener("click", () => hide("accountModal"));
  el("accountModal").addEventListener("click", (e) => {
    if (e.target.id === "accountModal") hide("accountModal");
  });

  el("requestResetBtn").addEventListener("click", async () => {
    if (!modalAccountId) return;
    setError("resetRequestError", null);
    el("requestResetBtn").disabled = true;
    try {
      const reason = el("resetReason").value.trim();
      await apiFetch("/password-resets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accountId: modalAccountId, reason }),
      });
      el("requestResetBtn").textContent = "Reset Requested";
      setError(
        "resetRequestStatus",
        "Reset Requested — pending admin review. Estimated review time: within 1 business day."
      );
    } catch (err) {
      setError("resetRequestError", err.message);
      el("requestResetBtn").disabled = false;
    }
  });

  // --- Password reset admin dashboard ---

  async function loadPasswordResets() {
    setError("passwordResetsError", null);
    try {
      const status = el("resetStatusFilter").value;
      const from = el("resetFromDate").value;
      const to = el("resetToDate").value;
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      if (from) params.set("from", from);
      if (to) params.set("to", to);
      const query = params.toString();
      const data = await apiFetch(`/password-resets${query ? `?${query}` : ""}`, { method: "GET" });
      const rows = (data.items || [])
        .map((r) => {
          const actions =
            r.Status === "pending"
              ? `<button class="action" data-approve="${r.RequestId}">Approve</button>
                 <button class="action" data-reject="${r.RequestId}">Reject</button>`
              : "";
          return `<tr>
            <td>${r.RequestId}</td>
            <td>${r.AccountId}</td>
            <td>${r.RequestedBy}</td>
            <td>${r.Reason || ""}</td>
            <td>${r.Timestamp}</td>
            <td>${r.Status}</td>
            <td>${actions}</td>
          </tr>`;
        })
        .join("");
      el("passwordResetsBody").innerHTML = rows || `<tr><td colspan="7">No password reset requests found.</td></tr>`;
      el("passwordResetsBody").querySelectorAll("button[data-approve]").forEach((b) => {
        b.addEventListener("click", () => decidePasswordReset(b.dataset.approve, "approve", b));
      });
      el("passwordResetsBody").querySelectorAll("button[data-reject]").forEach((b) => {
        b.addEventListener("click", () => decidePasswordReset(b.dataset.reject, "reject", b));
      });
    } catch (err) {
      setError("passwordResetsError", err.message);
    }
  }

  async function decidePasswordReset(requestId, action, button) {
    button.disabled = true;
    try {
      await apiFetch(`/password-resets/${encodeURIComponent(requestId)}/${action}`, { method: "POST" });
      loadPasswordResets();
    } catch (err) {
      setError("passwordResetsError", err.message);
      button.disabled = false;
    }
  }

  el("resetFilterSearch").addEventListener("click", loadPasswordResets);

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

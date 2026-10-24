import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Company = { id: number; name: string; role: "admin" | "member" | "viewer"; active?: boolean; is_owner?: boolean };
type User = { id: number; email: string; role: string; active_company_id: number | null; companies: Company[] };
type DocumentItem = {
  id: number; title: string; category: string; description: string; owner_id: number;
  access: "OWNER" | "READ" | "EDIT"; has_file: boolean; original_filename?: string | null;
  file_size?: number | null; created_at: string; updated_at: string;
};
type AuditEvent = {
  id: number; actor_email: string | null; action: string; outcome: string;
  document_id: number | null; created_at: string; details: Record<string, unknown>;
};
type Member = { user_id: number; email: string; workspace_role: string; joined_at: string };
type JoinRequest = { id: number; email: string; role: string; created_at: string; expires_at: string };
type InvitationInfo = { email: string; company_name: string; role: string };
type Tab = "documents" | "members" | "audit";

let csrfToken = "";
async function getCsrfToken() {
  // Fetch a token for the current Flask session on every state-changing request.
  // Login OTP verification clears/rebuilds the session, so a cached token can
  // become stale and cause CSRF 400 responses for logout/member removal.
  const response = await fetch("/csrf-token", { credentials: "include", cache: "no-store" });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Could not obtain CSRF token");
  csrfToken = data.csrf_token as string;
  return csrfToken;
}

async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method || "GET").toUpperCase();
  const headers = new Headers(init.headers || {});
  headers.set("Accept", "application/json");
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    headers.set("X-CSRFToken", await getCsrfToken());
  }
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...init, headers, credentials: "include" });
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) throw new Error(data?.error || data?.description || `Request failed (${response.status})`);
  return data as T;
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [authStep, setAuthStep] = useState<"credentials" | "login-otp" | "forgot" | "reset">("credentials");
  const [challengeId, setChallengeId] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [requestedRole, setRequestedRole] = useState<"admin" | "member" | "viewer">("member");
  const [companies, setCompanies] = useState<Company[]>([]);
  const [activeCompanyId, setActiveCompanyId] = useState<number | null>(null);
  const [tab, setTab] = useState<Tab>("documents");
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [selectedDoc, setSelectedDoc] = useState<DocumentItem | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [titleFilter, setTitleFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState("General");
  const [newDescription, setNewDescription] = useState("");
  const [grantEmail, setGrantEmail] = useState("");
  const [grantLevel, setGrantLevel] = useState<"READ" | "EDIT">("READ");
  const [revokeEmail, setRevokeEmail] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState<"member" | "viewer">("member");
  const [joinRequests, setJoinRequests] = useState<JoinRequest[]>([]);
  const [deleteCompanyConfirm, setDeleteCompanyConfirm] = useState("");
  const [inviteToken, setInviteToken] = useState(() => new URLSearchParams(window.location.search).get("token") || "");
  const [inviteInfo, setInviteInfo] = useState<InvitationInfo | null>(null);
  const [invitePassword, setInvitePassword] = useState("");
  const [workspaceRequestPending, setWorkspaceRequestPending] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const activeCompany = useMemo(
    () => companies.find((company) => company.id === activeCompanyId) || null,
    [companies, activeCompanyId]
  );

  const refreshMe = useCallback(async () => {
    const me = await api<User>("/me");
    setUser(me);
    setCompanies(me.companies || []);
    setActiveCompanyId(me.active_company_id);
  }, []);

  const refreshDocuments = useCallback(async () => {
    if (!activeCompanyId) { setDocuments([]); setSelectedDoc(null); return; }
    const params = new URLSearchParams();
    if (titleFilter.trim()) params.set("title", titleFilter.trim());
    if (categoryFilter.trim()) params.set("category", categoryFilter.trim());
    const query = params.toString();
    const result = await api<{ documents: DocumentItem[] }>(`/documents${query ? `?${query}` : ""}`);
    setDocuments(result.documents);
    setSelectedDoc((previous) => previous ? result.documents.find((doc) => doc.id === previous.id) || null : null);
  }, [activeCompanyId, titleFilter, categoryFilter]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("oauth") === "success") setMessage("Google sign-in successful.");
    if (params.get("oauth_error")) setError(`Google sign-in could not complete: ${params.get("oauth_error")}. You can still use email and password.`);
    if (inviteToken) {
      api<InvitationInfo>(`/invites/validate?token=${encodeURIComponent(inviteToken)}`)
        .then(setInviteInfo)
        .catch((e: Error) => setError(e.message));
    }
    if (params.has("oauth") || params.has("oauth_error") || params.has("setup_workspace")) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, [inviteToken]);

  useEffect(() => {
    api<User>("/me").then((me) => {
      setUser(me); setCompanies(me.companies || []); setActiveCompanyId(me.active_company_id);
    }).catch(() => setUser(null));
  }, []);

  useEffect(() => {
    if (user && activeCompanyId) {
      refreshDocuments().catch((e: Error) => setError(e.message));
    } else {
      setDocuments([]);
      setSelectedDoc(null);
    }
  }, [user, activeCompanyId, refreshDocuments]);

  useEffect(() => {
    if (!user || !activeCompanyId || tab === "documents") return;
    if (tab === "members" && activeCompany?.role === "admin") {
      api<{ members: Member[] }>("/admin/members")
        .then((result) => setMembers(result.members))
        .catch((e: Error) => setError(e.message));
      api<{ requests: JoinRequest[] }>("/admin/join-requests")
        .then((result) => setJoinRequests(result.requests))
        .catch((e: Error) => setError(e.message));
    } else if (tab === "audit" && activeCompany?.role === "admin") {
      api<{ events: AuditEvent[] }>("/admin/audit-logs?page=1&per_page=100")
        .then((result) => setAuditEvents(result.events))
        .catch((e: Error) => setError(e.message));
    }
  }, [user, activeCompanyId, tab, activeCompany?.role]);

  async function runAction(action: () => Promise<void>) {
    setBusy(true); setError(""); setMessage("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : "Something went wrong"); }
    finally { setBusy(false); }
  }

  async function submitAuth(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      if (authMode === "register") {
        const result = await api<{ message: string; status?: string; notification_sent?: boolean }>("/register", { method: "POST", body: JSON.stringify({ email, password, company_name: companyName, requested_role: requestedRole }) });
        setMessage(result.notification_sent === false ? `${result.message} Email notification was not delivered; the administrator must be contacted until SMTP is configured.` : (result.message || "Registration request submitted."));
        setAuthMode("login");
        setPassword("");
        return;
      }
      const result = await api<{ message: string; challenge_id: string }>("/login", { method: "POST", body: JSON.stringify({ email, password }) });
      setChallengeId(result.challenge_id);
      setOtp("");
      setPassword("");
      setAuthStep("login-otp");
      setMessage("We sent a verification code to your email. It expires in 5 minutes.");
    });
  }

  async function verifyLoginOtp(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      await api("/login/verify-otp", { method: "POST", body: JSON.stringify({ challenge_id: challengeId, otp }) });
      setOtp(""); setChallengeId(""); setAuthStep("credentials");
      await refreshMe(); setMessage("Signed in securely.");
    });
  }

  async function resendLoginOtp() {
    await runAction(async () => {
      const result = await api<{ challenge_id: string; message: string }>("/login/resend-otp", { method: "POST", body: JSON.stringify({ challenge_id: challengeId }) });
      setChallengeId(result.challenge_id); setOtp(""); setMessage(result.message);
    });
  }

  async function requestPasswordReset(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      const result = await api<{ challenge_id: string; message: string }>("/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
      setChallengeId(result.challenge_id); setOtp(""); setAuthStep("reset"); setMessage(result.message);
      // The same next step is shown regardless of whether the email is registered.
    });
  }

  async function completePasswordReset(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      await api("/reset-password", { method: "POST", body: JSON.stringify({ challenge_id: challengeId, otp, new_password: newPassword }) });
      setAuthStep("credentials"); setAuthMode("login"); setOtp(""); setNewPassword(""); setChallengeId("");
      setMessage("Password updated. Sign in with your new password.");
    });
  }

  async function selectCompany(companyId: number) {
    await runAction(async () => {
      await api("/companies/active", { method: "POST", body: JSON.stringify({ company_id: companyId }) });
      await refreshMe();
      setSelectedDoc(null);
      setTab("documents");
      setMessage("Active workspace changed.");
    });
  }

  async function logout() {
    await runAction(async () => {
      await api("/logout", { method: "POST", body: JSON.stringify({}) });
      csrfToken = "";
      setUser(null); setCompanies([]); setActiveCompanyId(null);
      setDocuments([]); setSelectedDoc(null);
    });
  }

  async function createDocument(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      const created = await api<DocumentItem>("/documents", { method: "POST", body: JSON.stringify({
        title: newTitle, category: newCategory, description: newDescription
      }) });
      setNewTitle(""); setNewCategory("General"); setNewDescription("");
      await refreshDocuments();
      setSelectedDoc(created);
      setMessage("Document created.");
    });
  }

  async function saveDocument(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedDoc) return;
    const form = new FormData(event.currentTarget);
    await runAction(async () => {
      const updated = await api<DocumentItem>(`/documents/${selectedDoc.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          title: String(form.get("title") || ""),
          category: String(form.get("category") || ""),
          description: String(form.get("description") || "")
        })
      });
      setSelectedDoc(updated);
      await refreshDocuments();
      setMessage("Changes saved.");
    });
  }

  async function uploadFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedDoc) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}/upload`, { method: "POST", body: form });
      await refreshDocuments();
      setMessage("File uploaded.");
      formElement.reset();
    });
  }

  async function downloadFile() {
    if (!selectedDoc) return;
    await runAction(async () => {
      const response = await fetch(`/documents/${selectedDoc.id}/download`, { credentials: "include" });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || `Download failed (${response.status})`);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = selectedDoc.original_filename || selectedDoc.title;
      link.click();
      URL.revokeObjectURL(url);
      setMessage("Download started.");
    });
  }

  async function deleteDocument() {
    if (!selectedDoc || !window.confirm(`Delete "${selectedDoc.title}" permanently?`)) return;
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}`, { method: "DELETE", body: JSON.stringify({}) });
      setSelectedDoc(null);
      await refreshDocuments();
      setMessage("Document deleted.");
    });
  }

  async function grantPermission(event: FormEvent) {
    event.preventDefault();
    if (!selectedDoc) return;
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}/permissions`, {
        method: "POST", body: JSON.stringify({ email: grantEmail, permission_level: grantLevel })
      });
      setGrantEmail("");
      setMessage(`Granted ${grantLevel} access.`);
    });
  }

  async function revokePermission(event: FormEvent) {
    event.preventDefault();
    if (!selectedDoc) return;
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}/permissions/by-email`, {
        method: "DELETE", body: JSON.stringify({ email: revokeEmail })
      });
      setRevokeEmail("");
      setMessage("Permission revoked.");
    });
  }

  async function deleteCompanyPermanently() {
    if (!user || !activeCompanyId) return;
    const active = user.companies.find((c) => c.id === activeCompanyId);
    if (!active || active.role !== "admin") return;
    const confirmed = window.confirm("This permanently deletes the company, documents, memberships, invitations and workspace data. Personal user accounts remain. Continue?");
    if (!confirmed) return;
    await runAction(async () => {
      await api("/company", { method: "DELETE", body: JSON.stringify({ confirm_name: active.name }) });
      setDeleteCompanyConfirm("");
      setMessage("Company and all workspace data permanently deleted.");
      await refreshMe();
    });
  }

  async function addMember(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      const result = await api<{ message: string }>("/admin/members", { method: "POST", body: JSON.stringify({ email: memberEmail, role: memberRole }) });
      setMemberEmail("");
      const membersResult = await api<{ members: Member[] }>("/admin/members");
      setMembers(membersResult.members);
      setMessage(result.message || "Invitation sent.");
    });
  }

  async function removeMember(member: Member) {
    if (!window.confirm(`Remove ${member.email} from this workspace? Their account and other workspace memberships will remain.`)) return;
    await runAction(async () => {
      await api(`/admin/members/${member.user_id}`, { method: "DELETE", body: JSON.stringify({}) });
      setMembers((current) => current.filter((item) => item.user_id !== member.user_id));
      setMessage(`${member.email} was removed from this workspace.`);
    });
  }

  async function decideJoinRequest(requestId: number, decision: "approve" | "reject") {
    if (!window.confirm(`${decision === "approve" ? "Approve" : "Reject"} this administrator request?`)) return;
    await runAction(async () => {
      const result = await api<{ message: string }>(`/admin/join-requests/${requestId}/decision`, { method: "POST", body: JSON.stringify({ decision }) });
      setJoinRequests((current) => current.filter((item) => item.id !== requestId));
      setMessage(result.message);
    });
  }

  async function acceptInvitation(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      await api("/invites/accept", { method: "POST", body: JSON.stringify({ token: inviteToken, password: invitePassword }) });
      setInviteToken(""); setInviteInfo(null); setInvitePassword("");
      window.history.replaceState({}, document.title, window.location.pathname);
      await refreshMe();
      setMessage("Invitation accepted. Welcome to TrustVault!");
    });
  }

  async function createWorkspace(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      const result = await api<{ message: string; status?: string; notification_sent?: boolean }>("/companies", { method: "POST", body: JSON.stringify({ name: companyName, requested_role: requestedRole }) });
      if (result.status === "pending" || result.message?.toLowerCase().includes("approval")) {
        setWorkspaceRequestPending(true);
        setMessage(result.notification_sent === false ? `${result.message} Administrator email was not delivered; SMTP configuration is required.` : result.message);
        return;
      }
      await refreshMe();
      setMessage(result.message || "Workspace created.");
    });
  }

  if (inviteToken && inviteInfo) {
    return (
      <main className="auth-shell"><section className="auth-card">
        <div className="brand-mark">TV</div><p className="eyebrow">WORKSPACE INVITATION</p><h1>Join {inviteInfo.company_name}</h1>
        <p className="muted">Invitation for {inviteInfo.email} · Role: {inviteInfo.role}</p>
        <form onSubmit={acceptInvitation} className="stack">
          <label>Create password<input type="password" minLength={12} autoComplete="new-password" value={invitePassword} onChange={(e) => setInvitePassword(e.target.value)} required /></label>
          <button className="primary" disabled={busy}>{busy ? "Please wait…" : "Accept invitation"}</button>
        </form>
        {error && <p className="notice error">{error}</p>}{message && <p className="notice success">{message}</p>}
      </section></main>
    );
  }

  if (!user) {
    return (
      <main className="auth-shell">
        <section className="auth-card auth-card-modern">
          <div className="auth-brand-row"><div className="brand-mark">TV</div><span className="security-pill"><span className="status-dot" /> Secure by design</span></div>
          <p className="eyebrow">PRIVATE DOCUMENT WORKSPACE</p>
          <h1>{authStep === "login-otp" ? "Check your inbox" : authStep === "forgot" ? "Recover your account" : authStep === "reset" ? "Reset your password" : "Your files. Your control."}</h1>
          <p className="muted">{authStep === "login-otp" ? `Enter the 6-digit code sent to ${email}.` : authStep === "forgot" ? "Enter your account email and we’ll send reset instructions if an account exists." : authStep === "reset" ? "Enter the code from your email and choose a strong new password." : "Share important files with confidence, clear permissions, and a verifiable audit trail."}</p>
          {authStep === "credentials" && <>
            <div className="auth-toggle"><button type="button" className={authMode === "login" ? "active" : ""} onClick={() => { setAuthMode("login"); setError(""); setMessage(""); }}>Sign in</button><button type="button" className={authMode === "register" ? "active" : ""} onClick={() => { setAuthMode("register"); setError(""); setMessage(""); }}>Create account</button></div>
            <button className="secondary google-button" type="button" onClick={() => { window.location.href = "/auth/google"; }}>Continue with Google</button>
            <p className="muted auth-separator">or continue with email</p>
            <form onSubmit={submitAuth} className="stack">
              <label>Email address<input type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="you@company.com" /></label>
              <label>Password<input type="password" autoComplete={authMode === "login" ? "current-password" : "new-password"} minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required placeholder="At least 12 characters" /></label>
              {authMode === "register" && <><label>Company / workspace name<input value={companyName} onChange={(e) => setCompanyName(e.target.value)} maxLength={200} required placeholder="Your organization" /></label><label>Access type if this company already exists<select value={requestedRole} onChange={(e) => setRequestedRole(e.target.value as "admin" | "member" | "viewer")}><option value="member">Member</option><option value="viewer">Viewer</option><option value="admin">Administrator (requires approval)</option></select></label><small className="muted">If the company does not exist, you'll become its first administrator. If it exists, its administrators must approve your selected role.</small></>}
              <button className="primary auth-submit" disabled={busy}>{busy ? "Please wait…" : authMode === "login" ? "Continue securely →" : "Create workspace →"}</button>
            </form>
            {authMode === "login" && <button className="text-button" type="button" onClick={() => { setAuthStep("forgot"); setError(""); setMessage(""); }}>Forgot password?</button>}
          </>}
          {authStep === "login-otp" && <form onSubmit={verifyLoginOtp} className="stack auth-flow-form"><label>6-digit verification code<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))} required placeholder="000000" className="otp-input" /></label><button className="primary auth-submit" disabled={busy || otp.length !== 6}>{busy ? "Verifying…" : "Verify and sign in →"}</button><button className="text-button" type="button" onClick={resendLoginOtp} disabled={busy}>Send a new code</button><button className="text-button muted-action" type="button" onClick={() => { setAuthStep("credentials"); setChallengeId(""); setOtp(""); }}>Back to sign in</button></form>}
          {authStep === "forgot" && <form onSubmit={requestPasswordReset} className="stack auth-flow-form"><label>Email address<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="you@company.com" /></label><button className="primary auth-submit" disabled={busy}>{busy ? "Sending…" : "Send reset code →"}</button><button className="text-button muted-action" type="button" onClick={() => setAuthStep("credentials")}>Back to sign in</button></form>}
          {authStep === "reset" && <form onSubmit={completePasswordReset} className="stack auth-flow-form"><label>6-digit reset code<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))} required placeholder="000000" className="otp-input" /></label><label>New password<input type="password" autoComplete="new-password" minLength={12} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required placeholder="At least 12 characters" /></label><button className="primary auth-submit" disabled={busy || otp.length !== 6}>{busy ? "Updating…" : "Update password →"}</button><button className="text-button muted-action" type="button" onClick={() => setAuthStep("credentials")}>Back to sign in</button></form>}
          {error && <p className="notice error" role="alert">{error}</p>}{message && <p className="notice success" role="status">{message}</p>}
          <p className="auth-footnote">Protected with secure sessions · Email verification · Workspace-level access controls</p>
        </section>
      </main>
    );
  }

  if (user && companies.length === 0) {
    return (
      <main className="auth-shell"><section className="auth-card">
        <div className="brand-mark">TV</div><p className="eyebrow">WORKSPACE SETUP</p><h1>Welcome to TrustVault</h1>
        <p className="muted">Signed in as {user.email}. Create a new workspace or request administrator approval for an existing company.</p>
        {workspaceRequestPending ? <><p className="notice success">Your request is pending. The company's current administrators must approve it before you can access the workspace.</p><button className="secondary" onClick={() => runAction(async () => { const me = await api<User>("/me"); setUser(me); setCompanies(me.companies || []); setActiveCompanyId(me.active_company_id); if (me.companies.length) setWorkspaceRequestPending(false); else setMessage("No approval yet. Please check again later."); })}>Check approval status</button></> : <form onSubmit={createWorkspace} className="stack"><label>Company / workspace name<input value={companyName} onChange={(e) => setCompanyName(e.target.value)} maxLength={200} required /></label><label>Requested role if the company already exists<select value={requestedRole} onChange={(e) => setRequestedRole(e.target.value as "admin" | "member" | "viewer")}><option value="member">Member</option><option value="viewer">Viewer</option><option value="admin">Administrator (requires approval)</option></select></label><small className="muted">If the company does not exist, you become its original administrator. If it exists, its administrators receive an email and must approve your requested role.</small><button className="primary" disabled={busy}>{busy ? "Please wait…" : "Create workspace / Request access"}</button></form>}
        <button className="secondary" onClick={logout}>Sign out</button>
        {error && <p className="notice error">{error}</p>}{message && <p className="notice success">{message}</p>}
      </section></main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row"><div className="brand-mark small">TV</div><div><strong>TrustVault</strong><small>Secure workspace</small></div></div>
        <div className="workspace-picker">
          <label htmlFor="workspace">ACTIVE WORKSPACE</label>
          <select id="workspace" value={activeCompanyId ?? ""} onChange={(e) => selectCompany(Number(e.target.value))}>
            <option value="" disabled>Select workspace</option>
            {companies.map((company) => <option key={company.id} value={company.id}>{company.name} · {company.role}</option>)}
          </select>
          {!activeCompany && companies.length > 1 && <small>Select a workspace to continue.</small>}
        </div>
        <nav className="nav-tabs">
          <button className={tab === "documents" ? "selected" : ""} onClick={() => setTab("documents")}>▤ <span>Documents</span></button>
          {activeCompany?.role === "admin" && <button className={tab === "members" ? "selected" : ""} onClick={() => setTab("members")}>♙ <span>Members</span></button>}
          {activeCompany?.role === "admin" && <button className={tab === "audit" ? "selected" : ""} onClick={() => setTab("audit")}>◷ <span>Audit trail</span></button>}
        </nav>
        <div className="sidebar-bottom">
          <div className="avatar">{user.email.slice(0, 1).toUpperCase()}</div>
          <div className="user-info"><strong>{user.email}</strong><small>{activeCompany?.role || "Choose workspace"}</small></div>
          <button className="icon-button" title="Sign out" onClick={logout}>↪</button>
        </div>
      </aside>

      <main className="main-content">
        <header className="page-header">
          <div>
            <p className="eyebrow">{activeCompany?.name || "WORKSPACE NOT SELECTED"}</p>
            <h1>{tab === "documents" ? "Documents" : tab === "members" ? "Workspace members" : "Audit trail"}</h1>
            <p className="muted">{tab === "documents" ? "Find, manage and share files securely." : tab === "members" ? "Manage who belongs to this workspace." : "Review successful and denied security events."}</p>
          </div>
          <div className="header-chip"><span className="status-dot" /> Access checks enabled</div>
        </header>

        {error && <div className="notice error top-notice">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
        {message && <div className="notice success top-notice">{message}<button onClick={() => setMessage("")}>Dismiss</button></div>}

        {!activeCompany ? (
          <section className="empty-state"><div className="empty-icon">⌂</div><h2>Select a workspace</h2><p>Choose a workspace you belong to from the sidebar to access its documents and audit information.</p></section>
        ) : tab === "documents" ? (
          <div className="document-layout">
            <section className="panel document-list-panel">
              <div className="panel-heading"><div><h2>Your documents</h2><p>{documents.length} accessible item{documents.length === 1 ? "" : "s"}</p></div></div>
              <div className="filter-row">
                <input aria-label="Search by title" placeholder="Search title…" value={titleFilter} onChange={(e) => setTitleFilter(e.target.value)} />
                <input aria-label="Filter category" placeholder="Category…" value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} />
              </div>
              <div className="document-list">
                {documents.map((doc) => <button key={doc.id} className={`document-item ${selectedDoc?.id === doc.id ? "current" : ""}`} onClick={() => setSelectedDoc(doc)}>
                  <div className="file-icon">▤</div><div className="doc-item-copy"><strong>{doc.title}</strong><small>{doc.category} · {doc.access}</small><small>{new Date(doc.updated_at).toLocaleDateString()}</small></div>
                  {doc.has_file && <span className="attachment-dot" title="File attached">●</span>}
                </button>)}
                {documents.length === 0 && <div className="small-empty">No accessible documents yet. Create one to get started.</div>}
              </div>
              {activeCompany.role !== "viewer" && <form className="create-form" onSubmit={createDocument}>
                <h3>Create a document</h3>
                <label>Title<input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} maxLength={255} required /></label>
                <div className="two-col">
                  <label>Category<input value={newCategory} onChange={(e) => setNewCategory(e.target.value)} maxLength={100} required /></label>
                </div>
                <label>Description<textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} maxLength={5000} rows={2} /></label>
                <button className="primary" disabled={busy}>＋ Create document</button>
              </form>}
            </section>

            <section className="panel detail-panel">
              {selectedDoc ? <>
                <div className="panel-heading detail-heading"><div><span className="tag">{selectedDoc.access}</span><h2>{selectedDoc.title}</h2><p>Document ID #{selectedDoc.id} · Updated {new Date(selectedDoc.updated_at).toLocaleString()}</p></div></div>
                {selectedDoc.access === "OWNER" || selectedDoc.access === "EDIT" ? (
                  <form className="stack edit-form" onSubmit={saveDocument}>
                    <label>Document title<input name="title" defaultValue={selectedDoc.title} maxLength={255} required key={`title-${selectedDoc.id}-${selectedDoc.updated_at}`} /></label>
                    <label>Category<input name="category" defaultValue={selectedDoc.category} maxLength={100} required key={`cat-${selectedDoc.id}-${selectedDoc.updated_at}`} /></label>
                    <label>Description<textarea name="description" defaultValue={selectedDoc.description} rows={4} maxLength={5000} key={`desc-${selectedDoc.id}-${selectedDoc.updated_at}`} /></label>
                    <button className="primary" disabled={busy}>Save changes</button>
                  </form>
                ) : <p className="description-text">{selectedDoc.description || "No description provided."}</p>}
                <div className="file-section">
                  <h3>Attached file</h3>
                  {selectedDoc.has_file ? <div className="attached-file"><span className="file-icon">▤</span><div><strong>{selectedDoc.original_filename}</strong><small>{selectedDoc.file_size ? `${(selectedDoc.file_size / 1024).toFixed(1)} KB` : "File attached"}</small></div><button className="secondary" onClick={downloadFile}>Download</button></div> : <p className="muted">No file has been uploaded.</p>}
                  {(selectedDoc.access === "OWNER" || selectedDoc.access === "EDIT") && <form className="upload-form" onSubmit={uploadFile}><input type="file" name="file" accept=".pdf,.doc,.docx,.txt,.csv,.xlsx,.png,.jpg,.jpeg" required /><button className="secondary" disabled={busy}>Upload file</button></form>}
                </div>
                {selectedDoc.access === "OWNER" && <>
                  <div className="permission-section">
                    <h3>Share access</h3>
                    <form className="inline-form" onSubmit={grantPermission}>
                      <input type="email" placeholder="Registered member email" value={grantEmail} onChange={(e) => setGrantEmail(e.target.value)} required />
                      <select value={grantLevel} onChange={(e) => setGrantLevel(e.target.value as "READ" | "EDIT")}><option value="READ">Read</option><option value="EDIT">Edit</option></select>
                      <button className="secondary" disabled={busy}>Grant</button>
                    </form>
                    <form className="inline-form revoke-form" onSubmit={revokePermission}>
                      <input type="email" placeholder="Email address to revoke" value={revokeEmail} onChange={(e) => setRevokeEmail(e.target.value)} required />
                      <button className="secondary danger-outline" disabled={busy}>Revoke access</button>
                    </form>
                    <small className="muted">The target account must already be a member of this workspace. Use the member list to find the user ID.</small>
                  </div>
                  <div className="danger-zone"><div><strong>Delete document</strong><small>This permanently removes its metadata, grants and stored file.</small></div><button className="danger-button" onClick={deleteDocument} disabled={busy}>Delete</button></div>
                </>}
              </> : <div className="empty-state detail-empty"><div className="empty-icon">▤</div><h2>Select a document</h2><p>Choose an item from the list to view its details and available actions.</p></div>}
            </section>
          </div>
        ) : tab === "members" ? (
          <section className="panel wide-panel">
            <div className="panel-heading"><div><h2>Members</h2><p>Membership and role are specific to this workspace.</p></div>{activeCompany?.is_owner && <button className="danger" type="button" onClick={deleteCompanyPermanently}>Delete company permanently</button>}</div>
            <form className="inline-form add-member-form" onSubmit={addMember}>
              <input type="email" placeholder="Invite by email address" value={memberEmail} onChange={(e) => setMemberEmail(e.target.value)} required />
              <select value={memberRole} onChange={(e) => setMemberRole(e.target.value as "member" | "viewer")}><option value="member">Member</option><option value="viewer">Viewer</option></select>
              <button className="primary" disabled={busy}>＋ Send invitation</button>
            </form>
            <p className="muted">New users receive a one-time email link to set a password. Administrator access is handled through approval requests.</p>
            <div className="table-wrap"><table><thead><tr><th>Member</th><th>User ID</th><th>Workspace role</th><th>Joined</th><th>Actions</th></tr></thead><tbody>
              {members.map((member) => <tr key={member.user_id}><td>{member.email}</td><td>{member.user_id}</td><td><span className={`role-pill ${member.workspace_role}`}>{member.workspace_role}</span></td><td>{new Date(member.joined_at).toLocaleDateString()}</td><td>{member.user_id !== user.id && <button className="danger-button" onClick={() => removeMember(member)} disabled={busy}>Remove</button>}</td></tr>)}
            </tbody></table></div>
            {!members.length && <p className="muted">No member data loaded.</p>}
            <div className="panel-heading section-subheading"><div><h2>Pending administrator requests</h2><p>Approve only people you recognize and expect to join this workspace as administrators.</p></div></div>
            {joinRequests.length ? <div className="table-wrap"><table><thead><tr><th>Email</th><th>Requested</th><th>Expires</th><th>Decision</th></tr></thead><tbody>{joinRequests.map((item) => <tr key={item.id}><td>{item.email}</td><td>{new Date(item.created_at).toLocaleDateString()}</td><td>{new Date(item.expires_at).toLocaleString()}</td><td><button className="primary" onClick={() => decideJoinRequest(item.id, "approve")} disabled={busy}>Approve</button> <button className="danger-button" onClick={() => decideJoinRequest(item.id, "reject")} disabled={busy}>Reject</button></td></tr>)}</tbody></table></div> : <p className="muted">No pending administrator requests.</p>}
          </section>
        ) : (
          <section className="panel wide-panel">
            <div className="panel-heading"><div><h2>Security activity</h2><p>Latest 100 events for the active workspace.</p></div><button className="secondary" onClick={() => api<{events: AuditEvent[]}>("/admin/audit-logs?page=1&per_page=100").then((r) => setAuditEvents(r.events)).catch((e: Error) => setError(e.message))}>Refresh</button></div>
            <div className="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>Outcome</th><th>Document</th></tr></thead><tbody>
              {auditEvents.map((event) => <tr key={event.id}><td>{new Date(event.created_at).toLocaleString()}</td><td>{event.actor_email || "System"}</td><td><code>{event.action}</code></td><td><span className={`outcome ${event.outcome.toLowerCase()}`}>{event.outcome}</span></td><td>{event.document_id ?? "—"}</td></tr>)}
            </tbody></table></div>
            {!auditEvents.length && <p className="muted">No audit events loaded. This view is available to workspace administrators.</p>}
          </section>
        )}
        <footer className="footer-note"><span>TrustVault</span><span>Server-side permissions · Workspace isolation · Audit history</span></footer>
      </main>
    </div>
  );
}

export default App;

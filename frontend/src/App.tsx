import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Company = { id: number; name: string; role: "admin" | "member"; active?: boolean };
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
type Tab = "documents" | "members" | "audit";

let csrfToken = "";
async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const response = await fetch("/csrf-token", { credentials: "include" });
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
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [companyName, setCompanyName] = useState("");
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
  const [revokeUserId, setRevokeUserId] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
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
    if (tab === "members") {
      api<{ members: Member[] }>("/admin/members")
        .then((result) => setMembers(result.members))
        .catch((e: Error) => setError(e.message));
    } else {
      api<{ events: AuditEvent[] }>("/admin/audit-logs?page=1&per_page=100")
        .then((result) => setAuditEvents(result.events))
        .catch((e: Error) => setError(e.message));
    }
  }, [user, activeCompanyId, tab]);

  async function runAction(action: () => Promise<void>) {
    setBusy(true); setError(""); setMessage("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : "Something went wrong"); }
    finally { setBusy(false); }
  }

  async function submitAuth(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      if (authMode === "register") {
        await api("/register", { method: "POST", body: JSON.stringify({ email, password, company_name: companyName }) });
        setMessage("Account created. Sign in with your new account.");
        setAuthMode("login");
        setPassword("");
        return;
      }
      await api("/login", { method: "POST", body: JSON.stringify({ email, password }) });
      await refreshMe();
      setPassword("");
      setMessage("Signed in successfully.");
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
      await api(`/documents/${selectedDoc.id}/permissions/${Number(revokeUserId)}`, {
        method: "DELETE", body: JSON.stringify({})
      });
      setRevokeUserId("");
      setMessage("Permission revoked.");
    });
  }

  async function addMember(event: FormEvent) {
    event.preventDefault();
    await runAction(async () => {
      await api("/admin/members", { method: "POST", body: JSON.stringify({ email: memberEmail }) });
      setMemberEmail("");
      const result = await api<{ members: Member[] }>("/admin/members");
      setMembers(result.members);
      await refreshMe();
      setMessage("Workspace member added.");
    });
  }

  if (!user) {
    return (
      <main className="auth-shell">
        <section className="auth-card">
          <div className="brand-mark">TV</div>
          <p className="eyebrow">PRIVATE DOCUMENT WORKSPACE</p>
          <h1>TrustVault</h1>
          <p className="muted">Share important files with clear permissions and an audit trail.</p>
          <div className="auth-toggle">
            <button className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>Sign in</button>
            <button className={authMode === "register" ? "active" : ""} onClick={() => setAuthMode("register")}>Create account</button>
          </div>
          <form onSubmit={submitAuth} className="stack">
            <label>Email<input type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
            <label>Password<input type="password" autoComplete={authMode === "login" ? "current-password" : "new-password"} minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
            {authMode === "register" && <label>Company / workspace name<input value={companyName} onChange={(e) => setCompanyName(e.target.value)} maxLength={200} required /></label>}
            <button className="primary" disabled={busy}>{busy ? "Please wait…" : authMode === "login" ? "Sign in" : "Create workspace"}</button>
          </form>
          {error && <p className="notice error">{error}</p>}
          {message && <p className="notice success">{message}</p>}
        </section>
      </main>
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
          <button className={tab === "members" ? "selected" : ""} onClick={() => setTab("members")}>♙ <span>Members</span></button>
          <button className={tab === "audit" ? "selected" : ""} onClick={() => setTab("audit")}>◷ <span>Audit trail</span></button>
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
              <form className="create-form" onSubmit={createDocument}>
                <h3>Create a document</h3>
                <label>Title<input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} maxLength={255} required /></label>
                <div className="two-col">
                  <label>Category<input value={newCategory} onChange={(e) => setNewCategory(e.target.value)} maxLength={100} required /></label>
                </div>
                <label>Description<textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} maxLength={5000} rows={2} /></label>
                <button className="primary" disabled={busy}>＋ Create document</button>
              </form>
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
                      <input inputMode="numeric" placeholder="User ID to revoke" value={revokeUserId} onChange={(e) => setRevokeUserId(e.target.value)} required />
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
            <div className="panel-heading"><div><h2>Members</h2><p>Membership and role are specific to this workspace.</p></div></div>
            <form className="inline-form add-member-form" onSubmit={addMember}>
              <input type="email" placeholder="Add existing account by email" value={memberEmail} onChange={(e) => setMemberEmail(e.target.value)} required />
              <button className="primary" disabled={busy}>＋ Add member</button>
            </form>
            <div className="table-wrap"><table><thead><tr><th>Member</th><th>User ID</th><th>Workspace role</th><th>Joined</th></tr></thead><tbody>
              {members.map((member) => <tr key={member.user_id}><td>{member.email}</td><td>{member.user_id}</td><td><span className={`role-pill ${member.workspace_role}`}>{member.workspace_role}</span></td><td>{new Date(member.joined_at).toLocaleDateString()}</td></tr>)}
            </tbody></table></div>
            {!members.length && <p className="muted">No member data loaded. This view is available to workspace administrators.</p>}
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

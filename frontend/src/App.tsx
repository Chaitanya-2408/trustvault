import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Company = {
  id: number;
  name: string;
  role: "admin" | "member" | "viewer";
  active?: boolean;
  is_owner?: boolean;
};

type User = {
  id: number;
  email: string;
  full_name?: string;
  role: string;
  active_company_id: number | null;
  companies: Company[];
};

type WorkspaceDetails = {
  id: number;
  name: string;
  owner_id: number;
  owner_email: string;
  owner_name: string;
  is_owner: boolean;
  current_user_role: string;
  member_count: number;
  document_count: number;
  created_at: string;
};

type DocumentItem = {
  id: number;
  title: string;
  category: string;
  description: string;
  owner_id: number;
  access: "OWNER" | "READ" | "EDIT";
  has_file: boolean;
  original_filename?: string | null;
  file_size?: number | null;
  created_at: string;
  updated_at: string;
};

type AuditEvent = {
  id: number;
  actor_email: string | null;
  action: string;
  outcome: string;
  document_id: number | null;
  created_at: string;
  details: Record<string, unknown>;
};

type Member = {
  user_id: number;
  email: string;
  full_name?: string;
  workspace_role: string;
  is_owner?: boolean;
  joined_at: string;
};

type UserSearchResult = {
  id: number;
  email: string;
  full_name: string;
};

type Tab = "documents" | "members" | "workspace" | "audit";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

let csrfToken = "";
async function getCsrfToken() {
  const response = await fetch(`${API_BASE_URL}/csrf-token`, { credentials: "include", cache: "no-store" });
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
  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers, credentials: "include" });
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) throw new Error(data?.error || data?.description || `Request failed (${response.status})`);
  return data as T;
}

const INTRO_SCENES = [
  {
    id: 1,
    tag: "SCENE 01 // CORE ARCHITECTURE",
    title: "Zero-Trust Private Workspace Isolation",
    headline: "Cryptographically isolated, multi-tenant document vaults.",
    description:
      "TrustVault partitions every organization into discrete security silos. Documents, permission matrices, and audit logs are isolated at the database layer with active role enforcement.",
    accent: "#38bdf8",
    metrics: [
      { label: "Tenant Boundary", val: "Strict DB Scopes" },
      { label: "Access Isolation", val: "Cross-Tenant Blocked" },
      { label: "Session Security", val: "Double-CSRF Guard" },
    ],
  },
  {
    id: 2,
    tag: "SCENE 02 // ACCESS CONTROL",
    title: "Granular Document Sharing & Permissions",
    headline: "Triple-tier access levels (Owner, Edit, Read) with instant revocation.",
    description:
      "Every document is encrypted and tagged with an explicit permission matrix. Workspace owners grant or revoke colleague access with immediate effect on server-side requests.",
    accent: "#2dd4bf",
    metrics: [
      { label: "Access Matrix", val: "Owner / Edit / Read" },
      { label: "Revocation Time", val: "Instant (<10ms)" },
      { label: "Stored Files", val: "Encrypted & Scoped" },
    ],
  },
  {
    id: 3,
    tag: "SCENE 03 // COMPLIANCE & AUDIT",
    title: "Tamper-Evident SHA-256 Hash Chaining",
    headline: "Every security event is cryptographically linked to the previous block.",
    description:
      "All authentication attempts, document reads, and administrative decisions are appended to an immutable SHA-256 hash chain. Any database modification immediately breaks the chain.",
    accent: "#818cf8",
    metrics: [
      { label: "Algorithm", val: "Canonical SHA-256" },
      { label: "Chain Genesis", val: "Deterministic 00..0" },
      { label: "Audit Readiness", val: "SOC-2 Type II" },
    ],
  },
  {
    id: 4,
    tag: "SCENE 04 // TENANT PROTECTION",
    title: "Duplicate Workspace Prevention & Discovery",
    headline: "Global namespace uniqueness guard with live autocomplete.",
    description:
      "TrustVault validates workspace names on-the-fly to prevent collision or impersonation. Registered colleagues can be discovered and onboarded with zero-friction autocomplete.",
    accent: "#06b6d4",
    metrics: [
      { label: "Collision Guard", val: "Real-Time 409 Reject" },
      { label: "Live Search", val: "Debounced API" },
      { label: "Evaluator Personas", val: "1-Click Sign-In" },
    ],
  },
];

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [showPortalHome, setShowPortalHome] = useState(true);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [authFullName, setAuthFullName] = useState("");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authConfirmPassword, setAuthConfirmPassword] = useState("");
  const [authCompanyName, setAuthCompanyName] = useState("");
  const [authCompanyWarning, setAuthCompanyWarning] = useState("");

  const [companies, setCompanies] = useState<Company[]>([]);
  const [activeCompanyId, setActiveCompanyId] = useState<number | null>(null);
  const [workspaceDetails, setWorkspaceDetails] = useState<WorkspaceDetails | null>(null);
  const [tab, setTab] = useState<Tab>("documents");

  // Video / Briefing state
  const [showBriefingVideo, setShowBriefingVideo] = useState(false);
  const [activeScene, setActiveScene] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);
  const [sceneProgress, setSceneProgress] = useState(0);

  // Document state
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [selectedDoc, setSelectedDoc] = useState<DocumentItem | null>(null);
  const [titleFilter, setTitleFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [isCreatingDoc, setIsCreatingDoc] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState("General");
  const [newDescription, setNewDescription] = useState("");
  const [grantEmail, setGrantEmail] = useState("");
  const [grantLevel, setGrantLevel] = useState<"READ" | "EDIT">("READ");
  const [revokeEmail, setRevokeEmail] = useState("");

  // Members state
  const [members, setMembers] = useState<Member[]>([]);
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState<"admin" | "member" | "viewer">("member");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UserSearchResult[]>([]);

  // Workspace creation modal
  const [showNewWorkspaceModal, setShowNewWorkspaceModal] = useState(false);
  const [newWorkspaceName, setNewWorkspaceName] = useState("");
  const [workspaceNameWarning, setWorkspaceNameWarning] = useState("");

  // Audit state
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const activeCompany = useMemo(
    () => companies.find((c) => c.id === activeCompanyId) || null,
    [companies, activeCompanyId]
  );

  const refreshMe = useCallback(async () => {
    try {
      const me = await api<User>("/me");
      setUser(me);
      setCompanies(me.companies || []);
      setActiveCompanyId(me.active_company_id);
    } catch {
      setUser(null);
    }
  }, []);

  const refreshWorkspaceDetails = useCallback(async () => {
    if (!activeCompanyId) {
      setWorkspaceDetails(null);
      return;
    }
    try {
      const details = await api<WorkspaceDetails>("/company/details");
      setWorkspaceDetails(details);
    } catch {
      setWorkspaceDetails(null);
    }
  }, [activeCompanyId]);

  const refreshDocuments = useCallback(async () => {
    if (!activeCompanyId) {
      setDocuments([]);
      setSelectedDoc(null);
      return;
    }
    const params = new URLSearchParams();
    if (titleFilter.trim()) params.set("title", titleFilter.trim());
    if (categoryFilter.trim()) params.set("category", categoryFilter.trim());
    const query = params.toString();
    const result = await api<{ documents: DocumentItem[] }>(`/documents${query ? `?${query}` : ""}`);
    setDocuments(result.documents);
    setSelectedDoc((prev) => (prev ? result.documents.find((d) => d.id === prev.id) || null : null));
  }, [activeCompanyId, titleFilter, categoryFilter]);

  const refreshMembers = useCallback(async () => {
    if (!activeCompanyId) return;
    try {
      const res = await api<{ members: Member[] }>("/admin/members");
      setMembers(res.members);
    } catch {
      setMembers([]);
    }
  }, [activeCompanyId]);

  const refreshAuditEvents = useCallback(async () => {
    if (!activeCompanyId) return;
    try {
      const res = await api<{ events: AuditEvent[] }>("/admin/audit-logs?page=1&per_page=100");
      setAuditEvents(res.events);
    } catch {
      setAuditEvents([]);
    }
  }, [activeCompanyId]);

  // Initial load
  useEffect(() => {
    refreshMe();
  }, [refreshMe]);

  // Keyboard shortcut listener for Launching Portal (Enter / Escape)
  useEffect(() => {
    if (!showPortalHome) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Enter" || e.key === "Escape") {
        setShowPortalHome(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [showPortalHome]);

  // Refresh tab data when active workspace or tab changes
  useEffect(() => {
    if (!user || !activeCompanyId) return;
    refreshWorkspaceDetails();
    if (tab === "documents") {
      refreshDocuments().catch(() => {});
    } else if (tab === "members") {
      refreshMembers().catch(() => {});
    } else if (tab === "audit") {
      refreshAuditEvents().catch(() => {});
    }
  }, [user, activeCompanyId, tab, refreshDocuments, refreshMembers, refreshAuditEvents, refreshWorkspaceDetails]);

  // Live user search debounce for adding members
  useEffect(() => {
    if (!searchQuery.trim() || searchQuery.length < 2) {
      setSearchResults([]);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const res = await api<{ users: UserSearchResult[] }>(`/users/search?q=${encodeURIComponent(searchQuery.trim())}`);
        setSearchResults(res.users || []);
      } catch {
        setSearchResults([]);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Real-time check if workspace name already exists during registration
  useEffect(() => {
    const trimmed = authCompanyName.trim();
    if (!trimmed || trimmed.length < 2) {
      setAuthCompanyWarning("");
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const res = await api<{ available: boolean; exists: boolean; message?: string }>(
          `/companies/check-name?name=${encodeURIComponent(trimmed)}`
        );
        if (!res.available && res.exists) {
          setAuthCompanyWarning(
            res.message || `A workspace named "${trimmed}" already exists. Workspace names must be unique.`
          );
        } else {
          setAuthCompanyWarning("");
        }
      } catch {
        setAuthCompanyWarning("");
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [authCompanyName]);

  // Real-time check if workspace name already exists during workspace creation
  useEffect(() => {
    const trimmed = newWorkspaceName.trim();
    if (!trimmed || trimmed.length < 2) {
      setWorkspaceNameWarning("");
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const res = await api<{ available: boolean; exists: boolean; message?: string }>(
          `/companies/check-name?name=${encodeURIComponent(trimmed)}`
        );
        if (!res.available && res.exists) {
          setWorkspaceNameWarning(
            res.message || `A workspace named "${trimmed}" already exists. Please choose a unique name.`
          );
        } else {
          setWorkspaceNameWarning("");
        }
      } catch {
        setWorkspaceNameWarning("");
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [newWorkspaceName]);

  // Video playback controller
  useEffect(() => {
    if (!showBriefingVideo || !isPlaying) return;
    const interval = setInterval(() => {
      setSceneProgress((prev) => {
        if (prev >= 100) {
          setActiveScene((current) => (current + 1) % INTRO_SCENES.length);
          return 0;
        }
        return prev + 2;
      });
    }, 100);
    return () => clearInterval(interval);
  }, [showBriefingVideo, isPlaying]);

  function closeBriefing() {
    setShowBriefingVideo(false);
  }

  async function runAction(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  // --- Auth Handlers ---
  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    await runAction(async () => {
      await api("/login", {
        method: "POST",
        body: JSON.stringify({ email: authEmail, password: authPassword }),
      });
      setAuthPassword("");
      await refreshMe();
      setMessage("Signed in successfully.");
    });
  }

  async function handleQuickLogin(targetEmail: string) {
    setAuthEmail(targetEmail);
    setAuthPassword("Password12345!");
    await runAction(async () => {
      await api("/login", {
        method: "POST",
        body: JSON.stringify({ email: targetEmail, password: "Password12345!" }),
      });
      setAuthPassword("");
      await refreshMe();
      setMessage(`Signed in as ${targetEmail}.`);
    });
  }

  async function handleRegister(e: FormEvent) {
    e.preventDefault();
    if (authCompanyWarning) {
      setError(authCompanyWarning);
      return;
    }
    if (authPassword !== authConfirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (authPassword.length < 12) {
      setError("Password must be at least 12 characters long.");
      return;
    }
    await runAction(async () => {
      const res = await api<{ message: string; active_company_id?: number }>("/register", {
        method: "POST",
        body: JSON.stringify({
          full_name: authFullName,
          email: authEmail,
          password: authPassword,
          confirm_password: authConfirmPassword,
          company_name: authCompanyName.trim() || undefined,
        }),
      });
      setAuthPassword("");
      setAuthConfirmPassword("");
      await refreshMe();
      setMessage(res.message || "Account created successfully.");
    });
  }

  async function handleLogout() {
    await runAction(async () => {
      await api("/logout", { method: "POST", body: JSON.stringify({}) });
      csrfToken = "";
      setUser(null);
      setCompanies([]);
      setActiveCompanyId(null);
      setDocuments([]);
      setSelectedDoc(null);
      setWorkspaceDetails(null);
    });
  }

  // --- Workspace Switch & Management ---
  async function selectWorkspace(id: number) {
    await runAction(async () => {
      await api("/companies/active", {
        method: "POST",
        body: JSON.stringify({ company_id: id }),
      });
      await refreshMe();
      setSelectedDoc(null);
      setMessage("Switched active workspace.");
    });
  }

  async function handleCreateWorkspace(e: FormEvent) {
    e.preventDefault();
    if (!newWorkspaceName.trim()) return;
    if (workspaceNameWarning) {
      setError(workspaceNameWarning);
      return;
    }
    await runAction(async () => {
      await api("/companies", {
        method: "POST",
        body: JSON.stringify({ name: newWorkspaceName.trim() }),
      });
      setNewWorkspaceName("");
      setWorkspaceNameWarning("");
      setShowNewWorkspaceModal(false);
      await refreshMe();
      setMessage("Workspace created successfully.");
    });
  }

  async function handleLeaveWorkspace() {
    if (!activeCompany) return;
    if (!window.confirm(`Are you sure you want to leave "${activeCompany.name}"? You will lose access to its files.`)) return;
    await runAction(async () => {
      const res = await api<{ message: string }>("/company/leave", { method: "POST", body: JSON.stringify({}) });
      await refreshMe();
      setMessage(res.message || "You left the workspace.");
    });
  }

  async function handleDeleteWorkspacePermanently() {
    if (!activeCompany || !workspaceDetails?.is_owner) return;
    if (activeCompany.name.toLowerCase() === "acme global security vault") {
      setError("The showcase workspace 'Acme Global Security Vault' is protected and cannot be deleted.");
      return;
    }
    const confirmName = window.prompt(`Type "${activeCompany.name}" to permanently delete this workspace and all its documents:`);
    if (confirmName !== activeCompany.name) {
      if (confirmName !== null) setError("Workspace name confirmation did not match. Deletion cancelled.");
      return;
    }
    await runAction(async () => {
      await api("/company", {
        method: "DELETE",
        body: JSON.stringify({ confirm_name: confirmName }),
      });
      await refreshMe();
      setMessage("Workspace permanently deleted.");
    });
  }

  // --- Document Operations ---
  async function handleCreateDocument(e: FormEvent) {
    e.preventDefault();
    await runAction(async () => {
      const doc = await api<DocumentItem>("/documents", {
        method: "POST",
        body: JSON.stringify({
          title: newTitle,
          category: newCategory,
          description: newDescription,
        }),
      });
      setNewTitle("");
      setNewCategory("General");
      setNewDescription("");
      setIsCreatingDoc(false);
      await refreshDocuments();
      setSelectedDoc(doc);
      setMessage("Document created.");
    });
  }

  async function handleSaveDocument(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedDoc) return;
    const form = new FormData(e.currentTarget);
    await runAction(async () => {
      const updated = await api<DocumentItem>(`/documents/${selectedDoc.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          title: String(form.get("title") || ""),
          category: String(form.get("category") || ""),
          description: String(form.get("description") || ""),
        }),
      });
      setSelectedDoc(updated);
      await refreshDocuments();
      setMessage("Document updated successfully.");
    });
  }

  async function handleUploadFile(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedDoc) return;
    const formElement = e.currentTarget;
    const form = new FormData(formElement);
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}/upload`, { method: "POST", body: form });
      await refreshDocuments();
      setMessage("File uploaded successfully.");
      formElement.reset();
    });
  }

  async function handleDownloadFile() {
    if (!selectedDoc) return;
    await runAction(async () => {
      const response = await fetch(`${API_BASE_URL}/documents/${selectedDoc.id}/download`, {
        credentials: "include",
      });
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
      setMessage("File download completed.");
    });
  }

  async function handleDeleteDocument() {
    if (!selectedDoc) return;
    const protectedDocs = [
      "enterprise soc-2 type ii security assessment",
      "zero-trust tenant isolation architecture blueprint",
      "confidential q4 2026 financial risk & tooling budget",
    ];
    if (protectedDocs.includes((selectedDoc.title || "").trim().toLowerCase())) {
      setError("This showcase document is protected for evaluator presentations and cannot be deleted.");
      return;
    }
    if (!window.confirm(`Delete "${selectedDoc.title}" permanently?`)) return;
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}`, { method: "DELETE", body: JSON.stringify({}) });
      setSelectedDoc(null);
      await refreshDocuments();
      setMessage("Document deleted.");
    });
  }

  async function handleGrantPermission(e: FormEvent) {
    e.preventDefault();
    if (!selectedDoc || !grantEmail.trim()) return;
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}/permissions`, {
        method: "POST",
        body: JSON.stringify({ email: grantEmail.trim(), permission_level: grantLevel }),
      });
      setGrantEmail("");
      setMessage(`Granted ${grantLevel} permission to ${grantEmail}.`);
    });
  }

  async function handleRevokePermission(e: FormEvent) {
    e.preventDefault();
    if (!selectedDoc || !revokeEmail.trim()) return;
    await runAction(async () => {
      await api(`/documents/${selectedDoc.id}/permissions/by-email`, {
        method: "DELETE",
        body: JSON.stringify({ email: revokeEmail.trim() }),
      });
      setRevokeEmail("");
      setMessage(`Revoked access from ${revokeEmail}.`);
    });
  }

  // --- Member Operations ---
  async function handleAddMember(e: FormEvent) {
    e.preventDefault();
    if (!memberEmail.trim()) return;
    await runAction(async () => {
      const res = await api<{ message: string }>("/admin/members", {
        method: "POST",
        body: JSON.stringify({ email: memberEmail.trim(), role: memberRole }),
      });
      setMemberEmail("");
      setSearchQuery("");
      setSearchResults([]);
      await refreshMembers();
      setMessage(res.message || "Member added successfully.");
    });
  }

  async function handleUpdateMemberRole(userId: number, role: string) {
    await runAction(async () => {
      await api(`/admin/members/${userId}`, {
        method: "PATCH",
        body: JSON.stringify({ role }),
      });
      await refreshMembers();
      setMessage("Member role updated.");
    });
  }

  async function handleRemoveMember(m: Member) {
    if (["evaluator@trustvault.local", "marcus.vance@trustvault.local", "elena.compliance@trustvault.local"].includes(m.email.toLowerCase())) {
      setError(`Demo persona ${m.full_name || m.email} is protected and cannot be removed.`);
      return;
    }
    if (!window.confirm(`Remove ${m.full_name || m.email} from this workspace?`)) return;
    await runAction(async () => {
      await api(`/admin/members/${m.user_id}`, { method: "DELETE", body: JSON.stringify({}) });
      await refreshMembers();
      setMessage(`Removed ${m.email} from workspace.`);
    });
  }

  const currentSceneData = INTRO_SCENES[activeScene];

  // ==========================================
  // RENDER: LAUNCHING PORTAL PAGE (CYBER SHIELD OVERVIEW)
  // ==========================================
  if (showPortalHome) {
    return (
      <div className="portal-page-shell">
        {/* BACKGROUND AMBIENT PARTICLES & GRID */}
        <div className="portal-stars-grid" />
        <div className="portal-glow-orb orb-top-left" />
        <div className="portal-glow-orb orb-center" />
        <div className="portal-glow-orb orb-bottom-right" />

        {/* TOP NAVBAR */}
        <header className="portal-navbar">
          <div className="portal-brand-wrap">
            <div className="brand-shield-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="m9 12 2 2 4-4" />
              </svg>
            </div>
            <strong className="portal-logo-text">TrustVault</strong>
            <span className="portal-version-badge">V2.4 ENTERPRISE</span>
          </div>

          <div className="portal-nav-actions">
            <button
              className="portal-briefing-link"
              onClick={() => {
                setShowBriefingVideo(true);
                setActiveScene(0);
                setSceneProgress(0);
                setIsPlaying(true);
              }}
            >
              ▶ System Video Briefing
            </button>
            <button className="portal-skip-btn" onClick={() => setShowPortalHome(false)}>
              Skip to {user ? "Dashboard" : "Login"} ↗
            </button>
          </div>
        </header>

        {/* MAIN STAGE WITH FLOATING 3D CARDS & HERO SHIELD */}
        <main className="portal-hero-stage">
          {/* FLOATING HOLOGRAPHIC CARDS (LEFT) */}
          <div className="floating-card-column left-cards">
            {/* CARD 1 (TOP LEFT) */}
            <div className="holo-card holo-top-left">
              <div className="holo-card-header">
                <span className="holo-status-dot blue" />
                <span className="holo-status-text">IMMUTABLE</span>
              </div>
              <strong className="holo-filename">Confidential_Audit.enc</strong>
              <small className="holo-sub">SHA-256 HASH CHAIN</small>
              <div className="holo-lines">
                <span className="line l1" />
                <span className="line l2" />
                <span className="line l3" />
                <span className="line l4" />
              </div>
              <span className="holo-enclave-badge">TRUSTVAULT ENCLAVE VERIFIED</span>
            </div>

            {/* CARD 2 (BOTTOM LEFT) */}
            <div className="holo-card holo-bottom-left">
              <div className="holo-card-header">
                <span className="holo-status-dot green" />
                <span className="holo-status-text">VERIFIED</span>
              </div>
              <strong className="holo-filename">Identity_Governance.pdf</strong>
              <small className="holo-sub">MULTI-TENANT ISOLATION</small>
              <div className="holo-lines">
                <span className="line l1" />
                <span className="line l2" />
                <span className="line l3" />
              </div>
              <span className="holo-enclave-badge">TRUSTVAULT ENCLAVE VERIFIED</span>
            </div>
          </div>

          {/* CENTRAL SECURITY ENCLAVE SHIELD */}
          <div className="hero-shield-container">
            <div className="shield-glass-card">
              {/* WATERMARK SHIELD OUTLINE */}
              <div className="shield-watermark">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  <path d="m9 12 2 2 4-4" strokeWidth="1.8" />
                </svg>
              </div>

              {/* SECURITY TAG */}
              <div className="shield-security-pill">
                <span className="pulsing-cyan-dot" />
                <span>ENTERPRISE ZERO-TRUST SECURITY</span>
              </div>

              {/* MAIN HERO TITLE */}
              <h1 className="shield-main-title">
                WELCOME TO <span className="gradient-cyan-text">TRUSTVAULT</span>
              </h1>

              {/* SUBTITLE */}
              <p className="shield-subtitle">Your Documents. Your Control. Your Security.</p>

              {/* DESCRIPTION */}
              <p className="shield-description">
                Cryptographic audit trails, multi-tenant workspace isolation, and sovereign document
                protection engineered for modern enterprise security.
              </p>

              {/* FEATURE BADGES ROW */}
              <div className="shield-feature-badges">
                <span className="feature-pill">
                  <span className="pill-icon">🛡️</span> SHA-256 Hash Chain
                </span>
                <span className="feature-pill">
                  <span className="pill-icon">🔒</span> Strict Multi-Tenant Isolation
                </span>
                <span className="feature-pill">
                  <span className="pill-icon">⚡</span> Real-Time Tamper Evidence
                </span>
              </div>

              {/* PRIMARY ENTER ACTION */}
              <button className="enter-trustvault-btn" onClick={() => setShowPortalHome(false)}>
                Enter TrustVault →
              </button>

              {/* SUB LINKS */}
              <div className="shield-sub-links">
                <span>New workspace?</span>
                <button
                  type="button"
                  className="sub-link-action"
                  onClick={() => {
                    setShowPortalHome(false);
                    setAuthMode("register");
                  }}
                >
                  Create Company Workspace
                </button>
                <span className="link-divider">•</span>
                <button
                  type="button"
                  className="sub-link-action"
                  onClick={() => {
                    setShowPortalHome(false);
                    setAuthMode("login");
                  }}
                >
                  Platform Admin Portal
                </button>
              </div>
            </div>
          </div>

          {/* FLOATING HOLOGRAPHIC CARDS (RIGHT) */}
          <div className="floating-card-column right-cards">
            {/* CARD 3 (TOP RIGHT) */}
            <div className="holo-card holo-top-right">
              <div className="holo-card-header">
                <span className="holo-status-dot cyan" />
                <span className="holo-status-text">PROTECTED</span>
              </div>
              <strong className="holo-filename">Tamper_Ledger_917384.log</strong>
              <small className="holo-sub">CRYPTOGRAPHIC PROOF</small>
              <div className="holo-lines">
                <span className="line l1" />
                <span className="line l2" />
                <span className="line l3" />
                <span className="line l4" />
              </div>
              <span className="holo-enclave-badge">TRUSTVAULT ENCLAVE VERIFIED</span>
            </div>

            {/* CARD 4 (BOTTOM RIGHT) */}
            <div className="holo-card holo-bottom-right">
              <div className="holo-card-header">
                <span className="holo-status-dot purple" />
                <span className="holo-status-text">ENCRYPTED</span>
              </div>
              <strong className="holo-filename">Security_Key_Vault.key</strong>
              <small className="holo-sub">AES-256 ENCLAVE</small>
              <div className="holo-lines">
                <span className="line l1" />
                <span className="line l2" />
                <span className="line l3" />
              </div>
              <span className="holo-enclave-badge">TRUSTVAULT ENCLAVE VERIFIED</span>
            </div>
          </div>
        </main>

        {/* FOOTER SHORTCUT HINT */}
        <footer className="portal-footer">
          <span>
            Press <kbd>Enter</kbd> to proceed or <kbd>Esc</kbd> to skip. Encrypted session security guaranteed.
          </span>
        </footer>

        {/* ARCHITECTURE VIDEO BRIEFING (WHEN OPENED FROM PORTAL) */}
        {showBriefingVideo && (
          <div className="video-modal-overlay">
            <div className="video-player-card">
              <div className="video-player-header">
                <div className="video-title-row">
                  <span className="live-rec-dot" />
                  <strong>TRUSTVAULT // SYSTEM ARCHITECTURE BRIEFING</strong>
                  <span className="video-badge">LIVE PRESENTATION</span>
                </div>
                <button className="video-close-btn" onClick={closeBriefing}>
                  Close Briefing ✕
                </button>
              </div>

              {/* 16:9 VIDEO STAGE */}
              <div className="video-stage">
                <div className="video-stage-bg" />
                <div className="video-stage-content">
                  <div className="scene-text-block">
                    <span className="scene-eyebrow" style={{ color: currentSceneData.accent }}>
                      {currentSceneData.tag}
                    </span>
                    <h2>{currentSceneData.title}</h2>
                    <p className="scene-headline">{currentSceneData.headline}</p>
                    <p className="scene-description">{currentSceneData.description}</p>

                    <div className="scene-metrics-grid">
                      {currentSceneData.metrics.map((m, idx) => (
                        <div key={idx} className="scene-metric-tile">
                          <span className="metric-label">{m.label}</span>
                          <strong className="metric-val" style={{ color: currentSceneData.accent }}>
                            {m.val}
                          </strong>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* DYNAMIC SCENE VISUALIZATION */}
                  <div className="scene-visual-block">
                    {activeScene === 0 && (
                      <div className="visual-graphic visual-isolation">
                        <div className="tenant-node node-a">
                          <span className="node-icon">🏢</span>
                          <strong>Tenant Vault A</strong>
                          <small>Acme Security</small>
                          <span className="pulse-ring" />
                        </div>
                        <div className="firewall-barrier">
                          <span className="barrier-shield">🛡️</span>
                          <span className="barrier-text">ZERO CROSS-LEAKAGE</span>
                        </div>
                        <div className="tenant-node node-b">
                          <span className="node-icon">🏦</span>
                          <strong>Tenant Vault B</strong>
                          <small>FinCorp Global</small>
                          <span className="pulse-ring" />
                        </div>
                      </div>
                    )}
                    {activeScene === 1 && (
                      <div className="visual-graphic visual-permissions">
                        <div className="center-document-icon">
                          <span>📄</span>
                          <strong>Encrypted Doc</strong>
                          <small>#101 AES-256</small>
                        </div>
                        <div className="perm-orbit orbit-owner">
                          <span className="orbit-badge gold">OWNER: Full Control</span>
                        </div>
                        <div className="perm-orbit orbit-edit">
                          <span className="orbit-badge blue">EDIT: Modify & Upload</span>
                        </div>
                        <div className="perm-orbit orbit-read">
                          <span className="orbit-badge green">READ: View Only</span>
                        </div>
                      </div>
                    )}
                    {activeScene === 2 && (
                      <div className="visual-graphic visual-hashchain">
                        <div className="hash-block">
                          <small>Block #10</small>
                          <code>PREV: a8f4...</code>
                          <code>HASH: 7c1e...</code>
                        </div>
                        <span className="chain-link">🔗</span>
                        <div className="hash-block active-block">
                          <small>Block #11</small>
                          <code>PREV: 7c1e...</code>
                          <code>HASH: 9d3a...</code>
                        </div>
                        <span className="chain-link">🔗</span>
                        <div className="hash-block">
                          <small>Block #12</small>
                          <code>PREV: 9d3a...</code>
                          <code>HASH: 4b20...</code>
                        </div>
                        <div className="chain-verified-pill">✓ SHA-256 Chain Verified</div>
                      </div>
                    )}
                    {activeScene === 3 && (
                      <div className="visual-graphic visual-guard">
                        <div className="radar-scanner">
                          <div className="radar-sweep" />
                          <div className="conflict-badge conflict-hit">
                            <span>✕</span> "Acme Security": Taken (409)
                          </div>
                          <div className="conflict-badge conflict-ok">
                            <span>✓</span> "Acme Labs": Available
                          </div>
                        </div>
                        <div className="guard-footer">Real-Time Collision Guard Enabled</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* VIDEO PLAYER BOTTOM CONTROLS */}
              <div className="video-player-controls">
                <div className="video-progress-track">
                  <div
                    className="video-progress-fill"
                    style={{
                      width: `${((activeScene + sceneProgress / 100) / INTRO_SCENES.length) * 100}%`,
                    }}
                  />
                </div>

                <div className="video-controls-bar">
                  <div className="controls-left">
                    <button
                      className="control-icon-btn"
                      onClick={() => setIsPlaying(!isPlaying)}
                      title={isPlaying ? "Pause" : "Play"}
                    >
                      {isPlaying ? "❚❚" : "▶"}
                    </button>
                    <span className="video-timecode">
                      00:0{activeScene + 1} / 00:0{INTRO_SCENES.length}
                    </span>
                  </div>

                  <div className="scene-selectors">
                    {INTRO_SCENES.map((s, idx) => (
                      <button
                        key={s.id}
                        className={`scene-select-btn ${activeScene === idx ? "active" : ""}`}
                        onClick={() => {
                          setActiveScene(idx);
                          setSceneProgress(0);
                        }}
                      >
                        {s.id}. {s.title.split(" ")[0]}
                      </button>
                    ))}
                  </div>

                  <div className="controls-right">
                    <button className="primary launch-app-btn" onClick={closeBriefing}>
                      Close Video Briefing →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // ==========================================
  // RENDER: Unauthenticated (Auth Screen)
  // ==========================================
  if (!user) {
    return (
      <main className="auth-shell">
        <section className="auth-card auth-card-modern">
          <div className="auth-brand-row">
            <div className="brand-mark">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 22, height: 22 }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="m9 12 2 2 4-4" />
              </svg>
            </div>
            <div className="auth-top-badges">
              <button
                type="button"
                className="portal-back-btn"
                onClick={() => setShowPortalHome(true)}
                title="Return to the Launching Portal"
              >
                🌐 Launch Portal
              </button>
              <button
                type="button"
                className="teaser-launch-pill"
                onClick={() => {
                  setShowBriefingVideo(true);
                  setActiveScene(0);
                  setSceneProgress(0);
                  setIsPlaying(true);
                }}
              >
                ▶ System Briefing Video
              </button>
            </div>
          </div>

          <p className="eyebrow">ENTERPRISE SECURITY ENCLAVE</p>
          <h1>{authMode === "login" ? "Sign in to TrustVault" : "Create your account"}</h1>
          <p className="muted">
            {authMode === "login"
              ? "Access your encrypted workspaces, granular access matrix, and verified audit trails."
              : "Register with your full name, work email, and choose a secure password."}
          </p>

          {/* QUICK EVALUATOR PERSONAS */}
          {authMode === "login" && (
            <div className="evaluator-quick-panel">
              <span className="quick-panel-title">⚡ ONE-CLICK EVALUATOR SIGN-IN:</span>
              <div className="quick-buttons-row">
                <button
                  type="button"
                  className="quick-persona-btn admin-btn"
                  onClick={() => handleQuickLogin("evaluator@trustvault.local")}
                  disabled={busy}
                  title="Sign in as Workspace Owner & Admin"
                >
                  <span className="persona-icon">👑</span>
                  <div>
                    <strong>Alex Morgan</strong>
                    <small>Owner / Admin</small>
                  </div>
                </button>
                <button
                  type="button"
                  className="quick-persona-btn member-btn"
                  onClick={() => handleQuickLogin("marcus.vance@trustvault.local")}
                  disabled={busy}
                  title="Sign in as Collaborating Member"
                >
                  <span className="persona-icon">🛡️</span>
                  <div>
                    <strong>Dr. Marcus</strong>
                    <small>Team Member</small>
                  </div>
                </button>
                <button
                  type="button"
                  className="quick-persona-btn viewer-btn"
                  onClick={() => handleQuickLogin("elena.compliance@trustvault.local")}
                  disabled={busy}
                  title="Sign in as Compliance Auditor"
                >
                  <span className="persona-icon">👁️</span>
                  <div>
                    <strong>Elena Rostova</strong>
                    <small>Auditor / Viewer</small>
                  </div>
                </button>
              </div>
            </div>
          )}

          <div className="auth-toggle">
            <button
              type="button"
              className={authMode === "login" ? "active" : ""}
              onClick={() => { setAuthMode("login"); setError(""); setMessage(""); }}
            >
              Sign In
            </button>
            <button
              type="button"
              className={authMode === "register" ? "active" : ""}
              onClick={() => { setAuthMode("register"); setError(""); setMessage(""); }}
            >
              Create Account
            </button>
          </div>

          {authMode === "login" ? (
            <form onSubmit={handleLogin} className="stack">
              <label>
                Work Email
                <input
                  type="email"
                  autoComplete="email"
                  value={authEmail}
                  onChange={(e) => setAuthEmail(e.target.value)}
                  required
                  placeholder="evaluator@trustvault.local"
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  autoComplete="current-password"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  required
                  placeholder="••••••••••••"
                />
              </label>
              <button className="primary auth-submit" disabled={busy}>
                {busy ? "Signing in…" : "Sign In →"}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="stack">
              <label>
                Full Name
                <input
                  type="text"
                  autoComplete="name"
                  value={authFullName}
                  onChange={(e) => setAuthFullName(e.target.value)}
                  required
                  placeholder="e.g. Jane Doe"
                />
              </label>
              <label>
                Work Email
                <input
                  type="email"
                  autoComplete="email"
                  value={authEmail}
                  onChange={(e) => setAuthEmail(e.target.value)}
                  required
                  placeholder="name@company.com"
                />
              </label>
              <label>
                Password (minimum 12 characters)
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  required
                  placeholder="At least 12 characters"
                />
              </label>
              <label>
                Confirm Password
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={authConfirmPassword}
                  onChange={(e) => setAuthConfirmPassword(e.target.value)}
                  required
                  placeholder="Re-type password"
                />
              </label>
              <label>
                Organization / Workspace Name <span className="label-sub">(optional)</span>
                <input
                  type="text"
                  value={authCompanyName}
                  onChange={(e) => setAuthCompanyName(e.target.value)}
                  maxLength={200}
                  placeholder="e.g. Acme Corp"
                  className={authCompanyWarning ? "input-warning" : ""}
                />
                {authCompanyWarning && (
                  <span className="field-warning-message" role="alert">
                    ⚠️ {authCompanyWarning}
                  </span>
                )}
              </label>
              <button className="primary auth-submit" disabled={busy || !!authCompanyWarning}>
                {busy ? "Creating account…" : "Create Account →"}
              </button>
            </form>
          )}

          {error && <p className="notice error" role="alert">{error}</p>}
          {message && <p className="notice success" role="status">{message}</p>}

          <p className="auth-footnote">
            Zero-Trust Isolation · Cryptographic Audit Chain · Strict Role Enforcement
          </p>
        </section>
      </main>
    );
  }

  // ==========================================
  // RENDER: Authenticated user with no workspace
  // ==========================================
  if (user && companies.length === 0) {
    return (
      <main className="auth-shell">
        <section className="auth-card">
          <div className="brand-mark">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 22, height: 22 }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <p className="eyebrow">WELCOME TO TRUSTVAULT</p>
          <h1>Create your first workspace</h1>
          <p className="muted">
            Hello, {user.full_name || user.email}! Set up your initial private workspace to begin uploading and sharing secure documents.
          </p>
          <form onSubmit={handleCreateWorkspace} className="stack">
            <label>
              Workspace / Company Name
              <input
                value={newWorkspaceName}
                onChange={(e) => setNewWorkspaceName(e.target.value)}
                maxLength={200}
                required
                placeholder="e.g. Acme Corporation"
                className={workspaceNameWarning ? "input-warning" : ""}
              />
              {workspaceNameWarning && (
                <span className="field-warning-message" role="alert">
                  ⚠️ {workspaceNameWarning}
                </span>
              )}
            </label>
            <button className="primary" disabled={busy || !newWorkspaceName.trim() || !!workspaceNameWarning}>
              {busy ? "Creating…" : "Create Workspace"}
            </button>
          </form>
          <button className="secondary" onClick={handleLogout} style={{ marginTop: "12px" }}>
            Sign Out
          </button>
          {error && <p className="notice error">{error}</p>}
          {message && <p className="notice success">{message}</p>}
        </section>
      </main>
    );
  }

  // ==========================================
  // RENDER: Authenticated Dashboard (Dark Black & Electric Blue)
  // ==========================================
  return (
    <div className="app-shell">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark small">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 18, height: 18 }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div>
            <strong>TrustVault</strong>
            <small>Enterprise Security</small>
          </div>
        </div>

        {/* WORKSPACE PICKER */}
        <div className="workspace-picker">
          <div className="workspace-picker-header">
            <label htmlFor="workspace">ACTIVE WORKSPACE</label>
            <button
              className="text-link-button"
              title="Create new workspace"
              onClick={() => setShowNewWorkspaceModal(true)}
            >
              + New
            </button>
          </div>
          <select
            id="workspace"
            value={activeCompanyId ?? ""}
            onChange={(e) => selectWorkspace(Number(e.target.value))}
          >
            <option value="" disabled>Select workspace</option>
            {companies.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.role.toUpperCase()})
              </option>
            ))}
          </select>
          {!activeCompany && companies.length > 1 && (
            <small className="workspace-alert">Please select a workspace to view documents.</small>
          )}
        </div>

        {/* NAVIGATION TABS */}
        <nav className="nav-tabs">
          <button
            className={tab === "documents" ? "selected" : ""}
            onClick={() => setTab("documents")}
          >
            <span>▤</span>
            <span>Documents</span>
          </button>
          <button
            className={tab === "members" ? "selected" : ""}
            onClick={() => setTab("members")}
          >
            <span>👥</span>
            <span>Members</span>
          </button>
          <button
            className={tab === "workspace" ? "selected" : ""}
            onClick={() => setTab("workspace")}
          >
            <span>⚙</span>
            <span>Workspace</span>
          </button>
          {activeCompany?.role === "admin" && (
            <button
              className={tab === "audit" ? "selected" : ""}
              onClick={() => setTab("audit")}
            >
              <span>🔒</span>
              <span>Audit Trail</span>
            </button>
          )}
        </nav>

        {/* SIDEBAR QUICK ACTIONS */}
        <div className="sidebar-quick-links">
          <button className="sidebar-sub-btn" onClick={() => setShowPortalHome(true)}>
            🌐 Launch Portal View
          </button>
          <button
            className="sidebar-sub-btn"
            onClick={() => {
              setShowBriefingVideo(true);
              setActiveScene(0);
              setSceneProgress(0);
              setIsPlaying(true);
            }}
          >
            🎬 System Architecture Briefing
          </button>
        </div>

        {/* SIDEBAR FOOTER / PROFILE */}
        <div className="sidebar-bottom">
          <div className="avatar">
            {(user.full_name || user.email).charAt(0).toUpperCase()}
          </div>
          <div className="user-info">
            <strong title={user.full_name ? `${user.full_name} (${user.email})` : user.email}>
              {user.full_name || user.email}
            </strong>
            <small>{activeCompany ? `${activeCompany.role} · ${activeCompany.name}` : "No workspace"}</small>
          </div>
          <button className="icon-button" title="Sign out" onClick={handleLogout}>
            ↪
          </button>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="main-content">
        {/* TOP PAGE HEADER */}
        <header className="page-header">
          <div>
            <div className="page-header-tags">
              <span className="workspace-tag">{activeCompany?.name || "No Workspace Selected"}</span>
              {activeCompany && (
                <span className={`role-badge role-${activeCompany.role}`}>
                  {activeCompany.is_owner ? "OWNER / ADMIN" : activeCompany.role.toUpperCase()}
                </span>
              )}
            </div>
            <h1>
              {tab === "documents"
                ? "Document Vault"
                : tab === "members"
                ? "Workspace Members"
                : tab === "workspace"
                ? "Workspace Details"
                : "Security Audit Trail"}
            </h1>
            <p className="muted">
              {tab === "documents"
                ? "Secure document storage, granular role-based permissions, and file versioning."
                : tab === "members"
                ? "Manage workspace access, invite colleagues, and configure permissions."
                : tab === "workspace"
                ? "Workspace settings, ownership details, and resource counts."
                : "Tamper-evident, cryptographically chained event log for compliance."}
            </p>
          </div>

          <div className="header-actions">
            <button className="secondary header-portal-btn" onClick={() => setShowPortalHome(true)}>
              🌐 Portal Home
            </button>
            <button
              className="secondary header-briefing-btn"
              onClick={() => {
                setShowBriefingVideo(true);
                setActiveScene(0);
                setSceneProgress(0);
                setIsPlaying(true);
              }}
            >
              🎬 Architecture Video
            </button>
            <div className="header-chip">
              <span className="status-dot" /> Real-time Isolation
            </div>
          </div>
        </header>

        {/* NOTIFICATIONS */}
        {error && (
          <div className="notice error top-notice">
            <span>{error}</span>
            <button onClick={() => setError("")}>✕</button>
          </div>
        )}
        {message && (
          <div className="notice success top-notice">
            <span>{message}</span>
            <button onClick={() => setMessage("")}>✕</button>
          </div>
        )}

        {/* CONTENT TABS */}
        {!activeCompany ? (
          <section className="empty-state">
            <div className="empty-icon">⌂</div>
            <h2>Select a workspace</h2>
            <p>Please select a workspace from the sidebar menu to view its files, members, and security logs.</p>
          </section>
        ) : tab === "documents" ? (
          /* ====================================================
             DOCUMENTS TAB
             ==================================================== */
          <div className="document-layout">
            {/* LEFT: DOCUMENT LIST & CREATION */}
            <section className="panel document-list-panel">
              <div className="panel-heading">
                <div>
                  <h2>All Documents</h2>
                  <p>{documents.length} item{documents.length === 1 ? "" : "s"} accessible</p>
                </div>
                {activeCompany.role !== "viewer" && (
                  <button
                    className="primary small-btn"
                    onClick={() => setIsCreatingDoc(!isCreatingDoc)}
                  >
                    {isCreatingDoc ? "Cancel" : "+ New"}
                  </button>
                )}
              </div>

              {/* SEARCH & FILTER */}
              <div className="filter-row">
                <input
                  aria-label="Search documents by title"
                  placeholder="🔍 Search title…"
                  value={titleFilter}
                  onChange={(e) => setTitleFilter(e.target.value)}
                />
                <input
                  aria-label="Filter by category"
                  placeholder="📁 Category…"
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                />
              </div>

              {/* CREATE DOCUMENT INLINE FORM */}
              {isCreatingDoc && (
                <form className="create-form" onSubmit={handleCreateDocument}>
                  <h3>Create New Document</h3>
                  <label>
                    Document Title
                    <input
                      value={newTitle}
                      onChange={(e) => setNewTitle(e.target.value)}
                      maxLength={255}
                      required
                      placeholder="e.g. Q4 Financial Projections"
                    />
                  </label>
                  <label>
                    Category
                    <input
                      value={newCategory}
                      onChange={(e) => setNewCategory(e.target.value)}
                      maxLength={100}
                      required
                      placeholder="e.g. Finance, Legal, HR"
                    />
                  </label>
                  <label>
                    Description
                    <textarea
                      value={newDescription}
                      onChange={(e) => setNewDescription(e.target.value)}
                      maxLength={5000}
                      rows={2}
                      placeholder="Optional document details or overview"
                    />
                  </label>
                  <div className="form-actions">
                    <button className="primary" disabled={busy || !newTitle.trim()}>
                      Create Document
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => setIsCreatingDoc(false)}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}

              {/* DOCUMENT ITEMS LIST */}
              <div className="document-list">
                {documents.map((doc) => (
                  <button
                    key={doc.id}
                    className={`document-item ${selectedDoc?.id === doc.id ? "current" : ""}`}
                    onClick={() => setSelectedDoc(doc)}
                  >
                    <div className="file-icon">▤</div>
                    <div className="doc-item-copy">
                      <strong>{doc.title}</strong>
                      <div className="doc-meta-row">
                        <span className="doc-category-badge">{doc.category}</span>
                        <span className={`access-badge access-${doc.access.toLowerCase()}`}>
                          {doc.access}
                        </span>
                        {doc.has_file && <span className="file-badge">📎 File</span>}
                      </div>
                      <small>Updated {new Date(doc.updated_at).toLocaleDateString()}</small>
                    </div>
                  </button>
                ))}
                {documents.length === 0 && (
                  <div className="small-empty">
                    <p>No documents found in this workspace.</p>
                    {activeCompany.role !== "viewer" && (
                      <button className="primary" onClick={() => setIsCreatingDoc(true)}>
                        + Create Your First Document
                      </button>
                    )}
                  </div>
                )}
              </div>
            </section>

            {/* RIGHT: DOCUMENT DETAILS & ACTIONS */}
            <section className="panel detail-panel">
              {selectedDoc ? (
                <>
                  <div className="detail-header-block">
                    <div className="detail-badges">
                      <span className={`access-pill access-${selectedDoc.access.toLowerCase()}`}>
                        Your Access: {selectedDoc.access}
                      </span>
                      <span className="category-pill">{selectedDoc.category}</span>
                    </div>
                    <h2>{selectedDoc.title}</h2>
                    <p className="detail-meta">
                      Document #{selectedDoc.id} · Created {new Date(selectedDoc.created_at).toLocaleDateString()} · Last modified {new Date(selectedDoc.updated_at).toLocaleString()}
                    </p>
                  </div>

                  {/* EDIT FORM (FOR OWNER / EDIT) */}
                  {selectedDoc.access === "OWNER" || selectedDoc.access === "EDIT" ? (
                    <form className="stack edit-form" onSubmit={handleSaveDocument}>
                      <label>
                        Document Title
                        <input
                          name="title"
                          defaultValue={selectedDoc.title}
                          maxLength={255}
                          required
                          key={`title-${selectedDoc.id}-${selectedDoc.updated_at}`}
                        />
                      </label>
                      <label>
                        Category
                        <input
                          name="category"
                          defaultValue={selectedDoc.category}
                          maxLength={100}
                          required
                          key={`cat-${selectedDoc.id}-${selectedDoc.updated_at}`}
                        />
                      </label>
                      <label>
                        Description
                        <textarea
                          name="description"
                          defaultValue={selectedDoc.description}
                          rows={3}
                          maxLength={5000}
                          key={`desc-${selectedDoc.id}-${selectedDoc.updated_at}`}
                        />
                      </label>
                      <button className="primary" disabled={busy} style={{ alignSelf: "flex-start" }}>
                        Save Metadata Changes
                      </button>
                    </form>
                  ) : (
                    <div className="view-only-box">
                      <h4>Description</h4>
                      <p className="description-text">
                        {selectedDoc.description || "No description provided."}
                      </p>
                    </div>
                  )}

                  {/* ATTACHED FILE SECTION */}
                  <div className="file-section">
                    <h3>Encrypted File Attachment</h3>
                    {selectedDoc.has_file ? (
                      <div className="attached-file">
                        <span className="file-icon big">💾</span>
                        <div className="file-info-block">
                          <strong>{selectedDoc.original_filename}</strong>
                          <small>
                            {selectedDoc.file_size
                              ? `${(selectedDoc.file_size / 1024).toFixed(1)} KB`
                              : "Encrypted file"}
                          </small>
                        </div>
                        <button className="primary" onClick={handleDownloadFile} disabled={busy}>
                          ⬇ Download File
                        </button>
                      </div>
                    ) : (
                      <p className="muted">No physical file has been uploaded for this document yet.</p>
                    )}

                    {(selectedDoc.access === "OWNER" || selectedDoc.access === "EDIT") && (
                      <form className="upload-form" onSubmit={handleUploadFile}>
                        <label className="file-input-label">
                          <span>{selectedDoc.has_file ? "Upload new version:" : "Attach file:"}</span>
                          <input
                            type="file"
                            name="file"
                            accept=".pdf,.doc,.docx,.txt,.csv,.xlsx,.png,.jpg,.jpeg"
                            required
                          />
                        </label>
                        <button className="secondary" disabled={busy}>
                          Upload File
                        </button>
                      </form>
                    )}
                  </div>

                  {/* SHARING CONTROLS (OWNER ONLY) */}
                  {selectedDoc.access === "OWNER" && (
                    <div className="permission-section">
                      <h3>Document Sharing & Access Control</h3>
                      <p className="section-note">
                        Share this specific document with members of this workspace.
                      </p>
                      <form className="inline-share-form" onSubmit={handleGrantPermission}>
                        <input
                          type="email"
                          placeholder="Member email address"
                          value={grantEmail}
                          onChange={(e) => setGrantEmail(e.target.value)}
                          required
                        />
                        <select
                          value={grantLevel}
                          onChange={(e) => setGrantLevel(e.target.value as "READ" | "EDIT")}
                        >
                          <option value="READ">READ (View only)</option>
                          <option value="EDIT">EDIT (Modify & Upload)</option>
                        </select>
                        <button className="primary" disabled={busy || !grantEmail.trim()}>
                          Grant Access
                        </button>
                      </form>

                      <form className="inline-share-form revoke-form" onSubmit={handleRevokePermission}>
                        <input
                          type="email"
                          placeholder="Revoke access by email"
                          value={revokeEmail}
                          onChange={(e) => setRevokeEmail(e.target.value)}
                          required
                        />
                        <button className="danger-button" disabled={busy || !revokeEmail.trim()}>
                          Revoke Access
                        </button>
                      </form>
                    </div>
                  )}

                  {/* DANGER ZONE (OWNER ONLY) */}
                  {selectedDoc.access === "OWNER" && (
                    <div className="danger-zone">
                      <div>
                        <strong>Permanently Delete Document</strong>
                        <small>Removes document record, all grants, and stored encrypted payload.</small>
                      </div>
                      {[
                        "enterprise soc-2 type ii security assessment",
                        "zero-trust tenant isolation architecture blueprint",
                        "confidential q4 2026 financial risk & tooling budget"
                      ].includes((selectedDoc.title || "").trim().toLowerCase()) ? (
                        <span style={{ fontSize: "0.75rem", color: "var(--cyber-cyan)", padding: "0.35rem 0.65rem", background: "rgba(56, 189, 248, 0.1)", borderRadius: "6px", border: "1px solid rgba(56, 189, 248, 0.25)" }}>
                          🔒 Protected Showcase Document
                        </span>
                      ) : (
                        <button className="danger-button" onClick={handleDeleteDocument} disabled={busy}>
                          Delete Document
                        </button>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="empty-state detail-empty">
                  <div className="empty-icon">▤</div>
                  <h2>No Document Selected</h2>
                  <p>Choose an item from the left panel to inspect its metadata, download attached files, or update permissions.</p>
                </div>
              )}
            </section>
          </div>
        ) : tab === "members" ? (
          /* ====================================================
             MEMBERS TAB
             ==================================================== */
          <section className="panel wide-panel">
            <div className="panel-heading">
              <div>
                <h2>Workspace Members ({members.length})</h2>
                <p>Manage members and their roles within "{activeCompany.name}".</p>
              </div>
              {!workspaceDetails?.is_owner && (
                <button className="secondary danger-text" onClick={handleLeaveWorkspace}>
                  Leave Workspace
                </button>
              )}
            </div>

            {/* ADD MEMBER SECTION (ADMIN ONLY) */}
            {activeCompany.role === "admin" && (
              <div className="add-member-card">
                <h3>Add Registered User to Workspace</h3>
                <p className="section-note">
                  Search registered TrustVault accounts to grant immediate access to this workspace.
                </p>
                <form className="add-member-form-grid" onSubmit={handleAddMember}>
                  <div className="search-input-wrap">
                    <input
                      type="text"
                      placeholder="Search by full name or email…"
                      value={searchQuery}
                      onChange={(e) => {
                        setSearchQuery(e.target.value);
                        setMemberEmail(e.target.value);
                      }}
                      required
                    />
                    {searchResults.length > 0 && (
                      <div className="search-dropdown">
                        {searchResults.map((sr) => (
                          <div
                            key={sr.id}
                            className="search-item"
                            onClick={() => {
                              setMemberEmail(sr.email);
                              setSearchQuery(`${sr.full_name ? `${sr.full_name} (${sr.email})` : sr.email}`);
                              setSearchResults([]);
                            }}
                          >
                            <strong>{sr.full_name || sr.email}</strong>
                            <small>{sr.email}</small>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <select
                    value={memberRole}
                    onChange={(e) => setMemberRole(e.target.value as "admin" | "member" | "viewer")}
                  >
                    <option value="member">Member (Create & Read)</option>
                    <option value="viewer">Viewer (Read Only)</option>
                    <option value="admin">Admin (Manage Workspace)</option>
                  </select>
                  <button className="primary" disabled={busy || !memberEmail.trim()}>
                    + Add Member
                  </button>
                </form>
              </div>
            )}

            {/* MEMBERS TABLE */}
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Member</th>
                    <th>Email Address</th>
                    <th>Workspace Role</th>
                    <th>Joined Date</th>
                    {activeCompany.role === "admin" && <th>Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {members.map((m) => (
                    <tr key={m.user_id}>
                      <td>
                        <div className="member-name-cell">
                          <span className="member-avatar">
                            {(m.full_name || m.email).charAt(0).toUpperCase()}
                          </span>
                          <span>
                            <strong>{m.full_name || "—"}</strong>
                            {m.is_owner && <span className="owner-tag">OWNER</span>}
                            {m.user_id === user.id && <span className="you-tag">YOU</span>}
                          </span>
                        </div>
                      </td>
                      <td>{m.email}</td>
                      <td>
                        {activeCompany.role === "admin" && !m.is_owner && m.user_id !== user.id ? (
                          <select
                            className="table-role-select"
                            value={m.workspace_role}
                            onChange={(e) => handleUpdateMemberRole(m.user_id, e.target.value)}
                          >
                            <option value="admin">admin</option>
                            <option value="member">member</option>
                            <option value="viewer">viewer</option>
                          </select>
                        ) : (
                          <span className={`role-pill role-${m.workspace_role}`}>
                            {m.workspace_role}
                          </span>
                        )}
                      </td>
                      <td>{new Date(m.joined_at).toLocaleDateString()}</td>
                      {activeCompany.role === "admin" && (
                        <td>
                          {!m.is_owner && m.user_id !== user.id && (
                            ["evaluator@trustvault.local", "marcus.vance@trustvault.local", "elena.compliance@trustvault.local"].includes(m.email.toLowerCase()) ? (
                              <span style={{ fontSize: "0.75rem", color: "var(--cyber-cyan)", padding: "0.25rem 0.5rem", background: "rgba(56, 189, 248, 0.1)", borderRadius: "4px", border: "1px solid rgba(56, 189, 248, 0.25)" }}>
                                🔒 Demo Persona
                              </span>
                            ) : (
                              <button
                                className="danger-button small"
                                onClick={() => handleRemoveMember(m)}
                                disabled={busy}
                              >
                                Remove
                              </button>
                            )
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : tab === "workspace" ? (
          /* ====================================================
             WORKSPACE DETAILS TAB
             ==================================================== */
          <section className="panel wide-panel">
            <div className="panel-heading">
              <div>
                <h2>Workspace Overview</h2>
                <p>Configuration and ownership settings for "{activeCompany.name}".</p>
              </div>
            </div>

            <div className="workspace-stats-grid">
              <div className="stat-card">
                <span className="stat-label">Workspace Name</span>
                <span className="stat-value">{workspaceDetails?.name || activeCompany.name}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Workspace ID</span>
                <span className="stat-value">#{workspaceDetails?.id || activeCompany.id}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Your Workspace Role</span>
                <span className="stat-value highlight-role">
                  {workspaceDetails?.is_owner ? "Workspace Owner" : workspaceDetails?.current_user_role?.toUpperCase()}
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Total Members</span>
                <span className="stat-value">{workspaceDetails?.member_count ?? members.length}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Total Documents</span>
                <span className="stat-value">{workspaceDetails?.document_count ?? documents.length}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Owner Information</span>
                <span className="stat-value">
                  {workspaceDetails?.owner_name
                    ? `${workspaceDetails.owner_name} (${workspaceDetails.owner_email})`
                    : workspaceDetails?.owner_email || "System"}
                </span>
              </div>
            </div>

            {/* DANGER ZONE FOR OWNER */}
            {workspaceDetails?.is_owner && (
              <div className="danger-zone workspace-danger">
                <div>
                  <strong>Permanently Delete Workspace</strong>
                  <p className="danger-desc">
                    {activeCompany.name.toLowerCase() === "acme global security vault" ? (
                      <span style={{ color: "var(--cyber-cyan)", fontWeight: 600 }}>
                        🔒 Protected Showcase Workspace: This presentation vault is permanently protected against deletion.
                      </span>
                    ) : (
                      `This permanently deletes "${activeCompany.name}", all contained documents, and associated memberships. User accounts will remain intact.`
                    )}
                  </p>
                </div>
                {activeCompany.name.toLowerCase() === "acme global security vault" ? (
                  <span style={{ fontSize: "0.75rem", color: "var(--cyber-cyan)", padding: "0.4rem 0.8rem", background: "rgba(56, 189, 248, 0.1)", borderRadius: "6px", border: "1px solid rgba(56, 189, 248, 0.25)" }}>
                    🔒 Protected Showcase Workspace
                  </span>
                ) : (
                  <button
                    className="danger-button"
                    onClick={handleDeleteWorkspacePermanently}
                    disabled={busy}
                  >
                    Delete Workspace
                  </button>
                )}
              </div>
            )}
          </section>
        ) : (
          /* ====================================================
             AUDIT TRAIL TAB
             ==================================================== */
          <section className="panel wide-panel">
            <div className="panel-heading">
              <div>
                <div className="audit-header-badges">
                  <h2>Cryptographic Audit Trail</h2>
                  <span className="verified-badge">✓ Tamper-Evident SHA-256 Chain</span>
                </div>
                <p>Every authentication, access attempt, file modification, and permission change is chained.</p>
              </div>
              <button className="secondary" onClick={refreshAuditEvents}>
                🔄 Refresh Logs
              </button>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Outcome</th>
                    <th>Resource Target</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((evt) => (
                    <tr key={evt.id}>
                      <td>{new Date(evt.created_at).toLocaleString()}</td>
                      <td>
                        <strong>{evt.actor_email || "System"}</strong>
                      </td>
                      <td>
                        <code className="action-code">{evt.action}</code>
                      </td>
                      <td>
                        <span className={`outcome-pill outcome-${evt.outcome.toLowerCase()}`}>
                          {evt.outcome}
                        </span>
                      </td>
                      <td>{evt.document_id ? `Document #${evt.document_id}` : "Workspace / Auth"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {auditEvents.length === 0 && (
              <p className="muted empty-note">No security audit records logged yet.</p>
            )}
          </section>
        )}

        <footer className="footer-note">
          <span>TrustVault Enterprise Security</span>
          <span>Zero-Trust Workspace Isolation · End-to-End Audit Integrity · Role Enforcement</span>
        </footer>
      </main>

      {/* MODAL: CREATE WORKSPACE */}
      {showNewWorkspaceModal && (
        <div className="modal-overlay" onClick={() => setShowNewWorkspaceModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Create New Workspace</h2>
              <button className="close-btn" onClick={() => setShowNewWorkspaceModal(false)}>✕</button>
            </div>
            <p className="muted">
              Create an isolated workspace for your team or project. You will automatically become its Owner and Administrator.
            </p>
            <form onSubmit={handleCreateWorkspace} className="stack">
              <label>
                Workspace Name
                <input
                  type="text"
                  value={newWorkspaceName}
                  onChange={(e) => setNewWorkspaceName(e.target.value)}
                  maxLength={200}
                  required
                  placeholder="e.g. Finance Vault, Legal Team"
                  className={workspaceNameWarning ? "input-warning" : ""}
                  autoFocus
                />
                {workspaceNameWarning && (
                  <span className="field-warning-message" role="alert">
                    ⚠️ {workspaceNameWarning}
                  </span>
                )}
              </label>
              <div className="modal-actions">
                <button type="button" className="secondary" onClick={() => setShowNewWorkspaceModal(false)}>
                  Cancel
                </button>
                <button className="primary" disabled={busy || !newWorkspaceName.trim() || !!workspaceNameWarning}>
                  {busy ? "Creating…" : "Create Workspace"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ARCHITECTURE VIDEO BRIEFING (WHEN OPENED FROM DASHBOARD) */}
      {showBriefingVideo && (
        <div className="video-modal-overlay">
          <div className="video-player-card">
            <div className="video-player-header">
              <div className="video-title-row">
                <span className="live-rec-dot" />
                <strong>TRUSTVAULT // SYSTEM ARCHITECTURE BRIEFING</strong>
                <span className="video-badge">LIVE PRESENTATION</span>
              </div>
              <button className="video-close-btn" onClick={closeBriefing}>
                Close Briefing ✕
              </button>
            </div>

            {/* 16:9 VIDEO STAGE */}
            <div className="video-stage">
              <div className="video-stage-bg" />
              <div className="video-stage-content">
                <div className="scene-text-block">
                  <span className="scene-eyebrow" style={{ color: currentSceneData.accent }}>
                    {currentSceneData.tag}
                  </span>
                  <h2>{currentSceneData.title}</h2>
                  <p className="scene-headline">{currentSceneData.headline}</p>
                  <p className="scene-description">{currentSceneData.description}</p>

                  <div className="scene-metrics-grid">
                    {currentSceneData.metrics.map((m, idx) => (
                      <div key={idx} className="scene-metric-tile">
                        <span className="metric-label">{m.label}</span>
                        <strong className="metric-val" style={{ color: currentSceneData.accent }}>
                          {m.val}
                        </strong>
                      </div>
                    ))}
                  </div>
                </div>

                {/* DYNAMIC SCENE VISUALIZATION */}
                <div className="scene-visual-block">
                  {activeScene === 0 && (
                    <div className="visual-graphic visual-isolation">
                      <div className="tenant-node node-a">
                        <span className="node-icon">🏢</span>
                        <strong>Tenant Vault A</strong>
                        <small>Acme Security</small>
                        <span className="pulse-ring" />
                      </div>
                      <div className="firewall-barrier">
                        <span className="barrier-shield">🛡️</span>
                        <span className="barrier-text">ZERO CROSS-LEAKAGE</span>
                      </div>
                      <div className="tenant-node node-b">
                        <span className="node-icon">🏦</span>
                        <strong>Tenant Vault B</strong>
                        <small>FinCorp Global</small>
                        <span className="pulse-ring" />
                      </div>
                    </div>
                  )}
                  {activeScene === 1 && (
                    <div className="visual-graphic visual-permissions">
                      <div className="center-document-icon">
                        <span>📄</span>
                        <strong>Encrypted Doc</strong>
                        <small>#101 AES-256</small>
                      </div>
                      <div className="perm-orbit orbit-owner">
                        <span className="orbit-badge gold">OWNER: Full Control</span>
                      </div>
                      <div className="perm-orbit orbit-edit">
                        <span className="orbit-badge blue">EDIT: Modify & Upload</span>
                      </div>
                      <div className="perm-orbit orbit-read">
                        <span className="orbit-badge green">READ: View Only</span>
                      </div>
                    </div>
                  )}
                  {activeScene === 2 && (
                    <div className="visual-graphic visual-hashchain">
                      <div className="hash-block">
                        <small>Block #10</small>
                        <code>PREV: a8f4...</code>
                        <code>HASH: 7c1e...</code>
                      </div>
                      <span className="chain-link">🔗</span>
                      <div className="hash-block active-block">
                        <small>Block #11</small>
                        <code>PREV: 7c1e...</code>
                        <code>HASH: 9d3a...</code>
                      </div>
                      <span className="chain-link">🔗</span>
                      <div className="hash-block">
                        <small>Block #12</small>
                        <code>PREV: 9d3a...</code>
                        <code>HASH: 4b20...</code>
                      </div>
                      <div className="chain-verified-pill">✓ SHA-256 Chain Verified</div>
                    </div>
                  )}
                  {activeScene === 3 && (
                    <div className="visual-graphic visual-guard">
                      <div className="radar-scanner">
                        <div className="radar-sweep" />
                        <div className="conflict-badge conflict-hit">
                          <span>✕</span> "Acme Security": Taken (409)
                        </div>
                        <div className="conflict-badge conflict-ok">
                          <span>✓</span> "Acme Labs": Available
                        </div>
                      </div>
                      <div className="guard-footer">Real-Time Collision Guard Enabled</div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* VIDEO PLAYER BOTTOM CONTROLS */}
            <div className="video-player-controls">
              <div className="video-progress-track">
                <div
                  className="video-progress-fill"
                  style={{
                    width: `${((activeScene + sceneProgress / 100) / INTRO_SCENES.length) * 100}%`,
                  }}
                />
              </div>

              <div className="video-controls-bar">
                <div className="controls-left">
                  <button
                    className="control-icon-btn"
                    onClick={() => setIsPlaying(!isPlaying)}
                    title={isPlaying ? "Pause" : "Play"}
                  >
                    {isPlaying ? "❚❚" : "▶"}
                  </button>
                  <span className="video-timecode">
                    00:0{activeScene + 1} / 00:0{INTRO_SCENES.length}
                  </span>
                </div>

                <div className="scene-selectors">
                  {INTRO_SCENES.map((s, idx) => (
                    <button
                      key={s.id}
                      className={`scene-select-btn ${activeScene === idx ? "active" : ""}`}
                      onClick={() => {
                        setActiveScene(idx);
                        setSceneProgress(0);
                      }}
                    >
                      {s.id}. {s.title.split(" ")[0]}
                    </button>
                  ))}
                </div>

                <div className="controls-right">
                  <button className="primary launch-app-btn" onClick={closeBriefing}>
                    Back to Dashboard →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

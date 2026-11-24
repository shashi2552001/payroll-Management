import {
  Bell,
  Building2,
  ClipboardCheck,
  FileCheck2,
  IndianRupee,
  LayoutDashboard,
  LogOut,
  Menu,
  Shield,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { AuthViews, ResetPasswordView } from './components/AuthViews';
import { CandidatePortal } from './components/CandidatePortal';
import {
  EmployeeDirectoryPanel,
  OverviewAndEssPanel,
  PayrollPanel,
  TeamApprovalsPanel,
} from './components/CoreHrPanels';
import { RecruitmentPanel } from './components/RecruitmentPanel';
import {
  AdminConsolePanel,
  ChecklistConfigPanel,
  SecuritySessionsPanel,
  StepUpModal,
} from './components/SecurityAndAdminPanels';
import { apiFetch } from './lib/api';
import type { AuthUser, NotificationItem } from './types';

type NavSection =
  | 'overview'
  | 'team'
  | 'recruitment'
  | 'employees'
  | 'payroll'
  | 'checklist'
  | 'security'
  | 'admin';

export default function App() {
  const pathname = window.location.pathname;

  // Isolated public Candidate Upload Portal route (no access to internal HR dashboard)
  if (pathname.startsWith('/candidate-upload')) {
    return <CandidatePortal />;
  }

  // Dedicated password reset route
  if (pathname.startsWith('/reset-password')) {
    return (
      <ResetPasswordView
        onDone={() => {
          window.history.replaceState({}, '', '/');
          window.location.reload();
        }}
      />
    );
  }

  return <InternalWorkspace />;
}

function InternalWorkspace() {
  const [bootChecking, setBootChecking] = useState(true);
  const [needsBootstrap, setNeedsBootstrap] = useState(false);
  const [envAdminPasswordConfigured, setEnvAdminPasswordConfigured] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);

  const [activeSection, setActiveSection] = useState<NavSection>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifCandidateId, setNotifCandidateId] = useState<string | null>(null);

  // Step-up re-authentication modal coordinator
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [pendingStepUpAction, setPendingStepUpAction] = useState<(() => void) | null>(null);

  const refreshMe = useCallback(async () => {
    try {
      const res = await apiFetch<{ user: AuthUser }>('/api/auth/me');
      setUser(res.user);
      return res.user;
    } catch {
      setUser(null);
      return null;
    }
  }, []);

  const loadNotifications = useCallback(async () => {
    try {
      const res = await apiFetch<{ notifications: NotificationItem[] }>('/api/hr/notifications');
      setNotifications(res.notifications);
    } catch {
      // ignore if unauthenticated
    }
  }, []);

  useEffect(() => {
    let active = true;
    async function init() {
      try {
        const bs = await apiFetch<{
          needsBootstrap: boolean;
          envAdminPasswordConfigured: boolean;
        }>('/api/auth/bootstrap-status', { skipAutoRefresh: true });
        if (!active) return;
        setNeedsBootstrap(bs.needsBootstrap);
        setEnvAdminPasswordConfigured(bs.envAdminPasswordConfigured);

        if (!bs.needsBootstrap) {
          const me = await refreshMe();
          if (me) {
            const urlParams = new URLSearchParams(window.location.search);
            const sec = urlParams.get('section') as NavSection | null;
            const cand = urlParams.get('candidate');
            if (sec) setActiveSection(sec);
            if (cand) setNotifCandidateId(cand);
          }
        }
      } finally {
        if (active) setBootChecking(false);
      }
    }
    init();
    return () => {
      active = false;
    };
  }, [refreshMe]);

  useEffect(() => {
    if (!user) return;
    loadNotifications();
    const timer = setInterval(loadNotifications, 20_000);
    return () => clearInterval(timer);
  }, [user, loadNotifications]);

  async function handleLogout() {
    await apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
    setUser(null);
    setNotifications([]);
    setActiveSection('overview');
  }

  function requestStepUp(callback: () => void) {
    setPendingStepUpAction(() => callback);
    setStepUpOpen(true);
  }

  if (bootChecking) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="text-sm font-medium text-slate-600">Loading 9HR India Workspace...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <AuthViews
        needsBootstrap={needsBootstrap}
        envAdminPasswordConfigured={envAdminPasswordConfigured}
        onAuthenticated={(authUser) => {
          setNeedsBootstrap(false);
          setUser(authUser);
          setActiveSection(
            authUser.role === 'HR'
              ? 'recruitment'
              : authUser.role === 'Accounts'
                ? 'payroll'
                : 'overview',
          );
        }}
      />
    );
  }

  const navItems: Array<{
    key: NavSection;
    label: string;
    icon: typeof LayoutDashboard;
    visible: boolean;
  }> = [
    { key: 'overview', label: 'Overview & ESS', icon: LayoutDashboard, visible: true },
    {
      key: 'team',
      label: 'Team & Approvals',
      icon: Users,
      visible: user.role === 'Manager' || user.role === 'HR' || user.role === 'Admin',
    },
    {
      key: 'recruitment',
      label: 'Recruitment & Docs',
      icon: FileCheck2,
      visible: user.role === 'HR' || user.role === 'Admin' || user.role === 'Manager',
    },
    {
      key: 'employees',
      label: 'Employee Directory',
      icon: Building2,
      visible: user.role === 'HR' || user.role === 'Accounts' || user.role === 'Admin',
    },
    {
      key: 'payroll',
      label: 'Payroll & Statutory',
      icon: IndianRupee,
      visible: user.role === 'Accounts' || user.role === 'Admin',
    },
    {
      key: 'checklist',
      label: 'Checklist Policy',
      icon: ClipboardCheck,
      visible: user.role === 'HR' || user.role === 'Admin',
    },
    { key: 'security', label: 'Security & Sessions', icon: Shield, visible: true },
    {
      key: 'admin',
      label: 'Admin & Audit',
      icon: ShieldCheck,
      visible: user.role === 'Admin',
    },
  ];

  const visibleNav = navItems.filter((n) => n.visible);
  const unreadCount = notifications.filter((n) => !n.is_read).length;

  return (
    <div className="min-h-screen bg-slate-50 flex">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-64 bg-[#0B131E] text-white shrink-0">
        <div className="px-6 py-5 border-b border-slate-800/80 flex items-center gap-3">
          <img
            src="/assets/aistudio/image_0ecd2493.png"
            alt="9HR India"
            className="w-10 h-10 rounded-full bg-white p-0.5 object-contain shrink-0"
          />
          <div className="min-w-0">
            <div className="font-display font-bold text-base text-white truncate">9HR India</div>
            <div className="text-xs text-slate-400 truncate">{user.role} Workspace</div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {visibleNav.map((item) => {
            const Icon = item.icon;
            const active = activeSection === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setActiveSection(item.key)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-blue-700 text-white'
                    : 'text-slate-300 hover:bg-slate-800/70 hover:text-white'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/80 space-y-3">
          <div className="text-xs">
            <div className="font-semibold text-white truncate">{user.fullName}</div>
            <div className="text-slate-400 truncate">{user.email}</div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-64 bg-[#0B131E] text-white p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <span className="font-display font-bold">9HR India</span>
                <button type="button" onClick={() => setMobileMenuOpen(false)}>
                  <X className="w-5 h-5" />
                </button>
              </div>
              <nav className="mt-4 space-y-1">
                {visibleNav.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.key}
                      type="button"
                      onClick={() => {
                        setActiveSection(item.key);
                        setMobileMenuOpen(false);
                      }}
                      className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium ${
                        activeSection === item.key ? 'bg-blue-700 text-white' : 'text-slate-300'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </nav>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="w-full py-2 bg-slate-800 rounded-lg text-xs font-medium"
            >
              Sign Out
            </button>
          </div>
          <div className="flex-1 bg-slate-900/50" onClick={() => setMobileMenuOpen(false)} />
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="bg-white border-b border-slate-200 px-4 sm:px-8 py-3.5 flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 text-slate-600 hover:text-slate-900"
              aria-label="Open menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="text-sm font-display font-bold text-slate-900 truncate">
              {visibleNav.find((n) => n.key === activeSection)?.label || 'Workspace'}
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0 relative">
            {/* Notification Centre */}
            <button
              type="button"
              onClick={() => setNotifOpen((v) => !v)}
              aria-label="Notifications"
              className="relative p-2 text-slate-600 hover:text-slate-900 rounded-lg hover:bg-slate-100"
            >
              <Bell className="w-4 h-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-[18px] h-[18px] px-1 bg-blue-700 text-white text-[10px] font-mono-tabular font-bold rounded-full flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </button>

            {notifOpen && (
              <div className="absolute right-0 top-11 w-80 sm:w-96 bg-white border border-slate-200 rounded-2xl shadow-xl z-50 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
                  <span className="font-display font-bold text-xs text-slate-900">
                    Notification Centre
                  </span>
                  {unreadCount > 0 && (
                    <button
                      type="button"
                      onClick={async () => {
                        await apiFetch('/api/hr/notifications/read-all', { method: 'POST' });
                        await loadNotifications();
                      }}
                      className="text-xs text-blue-700 hover:underline"
                    >
                      Mark all read
                    </button>
                  )}
                </div>
                <div className="max-h-80 overflow-y-auto divide-y divide-slate-100">
                  {notifications.length === 0 ? (
                    <div className="p-4 text-xs text-slate-500 text-center">No notifications.</div>
                  ) : (
                    notifications.map((n) => (
                      <button
                        key={n.id}
                        type="button"
                        onClick={async () => {
                          if (!n.is_read) {
                            await apiFetch(`/api/hr/notifications/${n.id}/read`, { method: 'PATCH' });
                            await loadNotifications();
                          }
                          if (n.related_entity_type === 'candidate' && n.related_entity_id) {
                            setNotifCandidateId(n.related_entity_id);
                            setActiveSection('recruitment');
                          }
                          setNotifOpen(false);
                        }}
                        className={`w-full text-left p-3.5 hover:bg-slate-50 ${
                          n.is_read ? 'opacity-75' : 'bg-blue-50/40'
                        }`}
                      >
                        <div className="text-xs font-semibold text-slate-900">{n.title}</div>
                        <div className="text-xs text-slate-600 mt-0.5">{n.message}</div>
                        <div className="text-[11px] font-mono-tabular text-slate-400 mt-1">
                          {new Date(n.created_at).toLocaleString()}
                        </div>
                      </button>
                    ))
                  )}
                </div>
              </div>
            )}

            <button
              type="button"
              onClick={handleLogout}
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg whitespace-nowrap"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Logout</span>
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-8 max-w-7xl w-full mx-auto">
          {activeSection === 'overview' && (
            <OverviewAndEssPanel user={user} onRequestStepUp={requestStepUp} />
          )}
          {activeSection === 'team' && <TeamApprovalsPanel />}
          {activeSection === 'recruitment' && (
            <RecruitmentPanel
              user={user}
              selectedCandidateIdFromNotification={notifCandidateId}
              onClearNotificationSelection={() => setNotifCandidateId(null)}
            />
          )}
          {activeSection === 'employees' && <EmployeeDirectoryPanel />}
          {activeSection === 'payroll' && <PayrollPanel onRequestStepUp={requestStepUp} />}
          {activeSection === 'checklist' && <ChecklistConfigPanel />}
          {activeSection === 'security' && (
            <SecuritySessionsPanel
              user={user}
              onUserRefresh={async () => {
                await refreshMe();
              }}
              onRequestStepUp={requestStepUp}
            />
          )}
          {activeSection === 'admin' && <AdminConsolePanel onRequestStepUp={requestStepUp} />}
        </main>
      </div>

      <StepUpModal
        open={stepUpOpen}
        totpEnabled={user.totpEnabled}
        onClose={() => {
          setStepUpOpen(false);
          setPendingStepUpAction(null);
        }}
        onVerified={() => {
          setStepUpOpen(false);
          const fn = pendingStepUpAction;
          setPendingStepUpAction(null);
          fn?.();
        }}
      />
    </div>
  );
}

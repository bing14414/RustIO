import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiClient, apiClient } from './api/client';
import { authService } from './api/services';
import type { LoginResponse } from './types';
import { AppShell } from './layout/AppShell';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { MetricsPage } from './pages/MetricsPage';
import { IamPage } from './pages/IamPage';
import { BucketsPage } from './pages/BucketsPage';
import { ObjectsPage } from './pages/ObjectsPage';
import { ReplicationPage } from './pages/ReplicationPage';
import { AlertsPage } from './pages/AlertsPage';
import { SecurityPage } from './pages/SecurityPage';
import { AuditPage } from './pages/AuditPage';
import { JobsPage } from './pages/JobsPage';
import { OperationsPage } from './pages/OperationsPage';
import { ConfigPage } from './pages/ConfigPage';
import { TenantsPage } from './pages/TenantsPage';
import { OidcCallbackPage } from './pages/OidcCallbackPage';

type SessionState = {
  username: string;
  token: string;
  permissions: string[];
  refreshToken?: string;
  sessionId?: string;
  expiresAt?: string;
  refreshExpiresAt?: string;
};

function hasPermission(session: SessionState | null, required: string) {
  return !!session?.permissions.includes(required);
}

function AccessDenied() {
  return (
    <section className="rounded-xl border border-rose-400/40 bg-rose-500/10 p-4 text-rose-300">
      当前账号无权限执行该操作。
    </section>
  );
}

function samePermissions(left: string[], right: string[]) {
  return left.length === right.length && left.every((permission, index) => permission === right[index]);
}

export default function App() {
  const location = useLocation();
  const [session, setSession] = useState<SessionState | null>(() => {
    const raw = localStorage.getItem('rustio_session');
    if (!raw) return null;

    try {
      return JSON.parse(raw) as SessionState;
    } catch {
      return null;
    }
  });
  const sessionRef = useRef<SessionState | null>(session);
  const refreshInFlightRef = useRef<Promise<string | null> | null>(null);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  const persistSession = useCallback((next: SessionState | null) => {
    sessionRef.current = next;
    setSession(next);
    if (next) {
      localStorage.setItem('rustio_session', JSON.stringify(next));
      return;
    }
    localStorage.removeItem('rustio_session');
  }, []);

  const clearSession = useCallback(() => {
    persistSession(null);
  }, [persistSession]);

  const buildSessionState = useCallback((username: string, auth: LoginResponse): SessionState => {
    return {
      username,
      token: auth.access_token,
      permissions: auth.permissions,
      refreshToken: auth.refresh_token,
      sessionId: auth.session_id,
      expiresAt: auth.expires_at,
      refreshExpiresAt: auth.refresh_expires_at
    };
  }, []);

  const refreshSession = useCallback(async (): Promise<string | null> => {
    if (refreshInFlightRef.current) {
      return refreshInFlightRef.current;
    }

    const current = sessionRef.current;
    if (!current?.refreshToken) {
      clearSession();
      return null;
    }

    refreshInFlightRef.current = (async () => {
      try {
        const response = await authService.refresh(apiClient, current.refreshToken!);
        const next = buildSessionState(current.username, response);
        persistSession(next);
        return next.token;
      } catch {
        clearSession();
        return null;
      } finally {
        refreshInFlightRef.current = null;
      }
    })();

    return refreshInFlightRef.current;
  }, [buildSessionState, clearSession, persistSession]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const handleStorage = (event: StorageEvent) => {
      if (event.key !== 'rustio_session') {
        return;
      }

      if (!event.newValue) {
        sessionRef.current = null;
        setSession(null);
        return;
      }

      try {
        const next = JSON.parse(event.newValue) as SessionState;
        sessionRef.current = next;
        setSession(next);
      } catch {
        sessionRef.current = null;
        setSession(null);
      }
    };

    window.addEventListener('storage', handleStorage);
    return () => {
      window.removeEventListener('storage', handleStorage);
    };
  }, []);

  const client = useMemo<ApiClient>(() => {
    if (!session?.token) return apiClient;
    return apiClient.withAuth({
      getAccessToken: () => sessionRef.current?.token,
      refreshAccessToken: refreshSession,
      onAuthFailure: clearSession
    });
  }, [clearSession, refreshSession, session?.token]);

  const syncCurrentSession = useCallback(async () => {
    const current = sessionRef.current;
    if (!current?.token) {
      return;
    }

    try {
      const remote = await authService.currentSession(client);
      const next: SessionState = {
        ...current,
        username: remote.principal,
        permissions: remote.permissions,
        sessionId: remote.session_id,
        expiresAt: remote.access_expires_at,
        refreshExpiresAt: remote.refresh_expires_at
      };

      if (
        current.username !== next.username ||
        current.sessionId !== next.sessionId ||
        current.expiresAt !== next.expiresAt ||
        current.refreshExpiresAt !== next.refreshExpiresAt ||
        !samePermissions(current.permissions, next.permissions)
      ) {
        persistSession(next);
      }
    } catch {
    }
  }, [client, persistSession]);

  useEffect(() => {
    if (!session?.token) {
      return;
    }

    void syncCurrentSession();
  }, [session?.token, syncCurrentSession]);

  useEffect(() => {
    if (!session?.token) {
      return;
    }

    void syncCurrentSession();
  }, [location.pathname, session?.token, syncCurrentSession]);

  useEffect(() => {
    if (!session?.token) {
      return;
    }

    const interval = window.setInterval(() => {
      void syncCurrentSession();
    }, 10 * 60 * 1000);

    const handleFocus = () => {
      void syncCurrentSession();
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void syncCurrentSession();
      }
    };

    window.addEventListener('focus', handleFocus);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener('focus', handleFocus);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [session?.token, syncCurrentSession]);

  function handleLogin(username: string, auth: LoginResponse) {
    persistSession(buildSessionState(username, auth));
  }

  async function handleLogout() {
    try {
      if (sessionRef.current?.token) {
        await authService.logout(apiClient.withToken(sessionRef.current.token));
      }
    } catch {
    } finally {
      clearSession();
    }
  }

  if (!session) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage onLogin={handleLogin} />} />
        <Route path="/login/oidc/callback" element={<OidcCallbackPage onLogin={handleLogin} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route
        path="/"
        element={
          <AppShell
            username={session.username}
            permissions={session.permissions}
            onLogout={handleLogout}
          />
        }
      >
        <Route path="dashboard" element={<DashboardPage client={client} token={session.token} />} />
        <Route
          path="metrics"
          element={hasPermission(session, 'cluster:read') ? <MetricsPage client={client} /> : <AccessDenied />}
        />
        <Route
          path="iam"
          element={hasPermission(session, 'iam:read') ? <IamPage client={client} /> : <AccessDenied />}
        />
        <Route
          path="tenants"
          element={hasPermission(session, 'cluster:read') ? <TenantsPage client={client} /> : <AccessDenied />}
        />
        <Route
          path="buckets"
          element={hasPermission(session, 'bucket:read') ? <BucketsPage client={client} /> : <AccessDenied />}
        />
        <Route
          path="objects"
          element={hasPermission(session, 'bucket:read') ? <ObjectsPage client={client} /> : <AccessDenied />}
        />
        <Route
          path="replication"
          element={
            hasPermission(session, 'replication:read') ? <ReplicationPage client={client} /> : <AccessDenied />
          }
        />
        <Route
          path="alerts"
          element={hasPermission(session, 'security:read') ? <AlertsPage client={client} /> : <AccessDenied />}
        />
        <Route
          path="security"
          element={
            hasPermission(session, 'security:read') ? <SecurityPage client={client} /> : <AccessDenied />
          }
        />
        <Route
          path="config"
          element={
            hasPermission(session, 'cluster:read') ? (
              <ConfigPage client={client} canWrite={hasPermission(session, 'cluster:write')} />
            ) : (
              <AccessDenied />
            )
          }
        />
        <Route
          path="audit"
          element={hasPermission(session, 'audit:read') ? <AuditPage client={client} /> : <AccessDenied />}
        />
        <Route path="jobs" element={hasPermission(session, 'jobs:read') ? <JobsPage client={client} /> : <AccessDenied />} />
        <Route
          path="operations"
          element={
            hasPermission(session, 'cluster:write') ? <OperationsPage client={client} /> : <AccessDenied />
          }
        />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}

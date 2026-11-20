import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { SessionProvider, useSession } from "./context/SessionContext";
import { ServerDataProvider } from "./context/ServerDataContext";
import Login from "./pages/Login";
import { ScanProvider } from "./context/ScanContext";
import { ApplicationProvider } from "./context/ApplicationContext";
import { PolicyProvider } from "./context/PolicyContext";
import { IssueProvider } from "./context/IssueContext";
import { AppLayout, SimpleLayout } from "./components/Layouts";
import ProtectedRoute from "./components/ProtectedRoute";
import Landing from "./pages/Landing";
import Connect from "./pages/Connect";
import Scanner from "./pages/Scanner";
import Results from "./pages/Results";
import NewScan from "./pages/NewScan";
import ScanRun from "./pages/ScanRun";
import Workbench from "./pages/Workbench";

/** The landing page and the login page are public. Everything else needs a signed-in user (unless sign-in is switched off). */
function Protected() {
  const { ready, authEnabled, user, notice } = useSession();
  const where = useLocation();
  if (!ready) return <p className="muted" style={{ padding: 40, textAlign: "center" }}>{notice || "Loading…"}</p>;
  if (authEnabled && !user) return <Navigate to="/login" replace state={{ from: where.pathname + where.search }} />;
  return (
    <AuthProvider>
      <ServerDataProvider>
        <ScanProvider>
          <ApplicationProvider>
            <PolicyProvider>
              <IssueProvider><Outlet /></IssueProvider>
            </PolicyProvider>
          </ApplicationProvider>
        </ScanProvider>
      </ServerDataProvider>
    </AuthProvider>
  );
}

/** Already signed in (or sign-in is off): skip the form and go where the person was heading. */
function LoginRoute() {
  const { ready, authEnabled, user } = useSession();
  const from = (useLocation().state as { from?: string } | null)?.from;
  if (ready && (!authEnabled || user)) return <Navigate to={from && from !== "/login" ? from : "/workbench"} replace />;
  return <Login />;
}

export default function App() {
  return (
    <BrowserRouter>
      <SessionProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<LoginRoute />} />
          <Route element={<Protected />}>
            <Route element={<SimpleLayout />}>
              <Route path="/connect" element={<Connect />} />
            </Route>
            <Route path="/workbench" element={<Workbench />} />
            <Route element={<AppLayout />}>
              <Route path="/scan/new" element={<NewScan />} />
              <Route path="/scan/run/:id" element={<ScanRun />} />
              <Route path="/scanner" element={<ProtectedRoute><Scanner /></ProtectedRoute>} />
              <Route path="/results" element={<Results />} />
            </Route>
            <Route path="/upload" element={<Navigate to="/scan/new" replace />} />
          </Route>
        </Routes>
      </SessionProvider>
    </BrowserRouter>
  );
}

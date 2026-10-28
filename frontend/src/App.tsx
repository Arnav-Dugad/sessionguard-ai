import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { AppLayout } from "@/components/Layout";
import { Spinner } from "@/components/ui";
import Login from "@/pages/Login";
import Overview from "@/pages/Overview";
import Sessions from "@/pages/Sessions";
import Threats from "@/pages/Threats";
import Lab from "@/pages/Lab";
import Events from "@/pages/Events";
import Analytics from "@/pages/Analytics";
import Models from "@/pages/Models";
import PolicyPage from "@/pages/Policy";
import Comparison from "@/pages/Comparison";
import PresentationMode from "@/pages/Presentation";
import SettingsPage from "@/pages/Settings";
import Portal from "@/pages/Portal";

function Loading() {
  return (
    <div className="grid min-h-screen place-items-center">
      <div className="flex items-center gap-3 text-[color:var(--color-muted)]"><Spinner className="h-5 w-5" /> Loading SessionGuard AI…</div>
    </div>
  );
}

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <Loading />;
  if (!user) return (
    <Routes>
      <Route path="*" element={<Login />} />
    </Routes>
  );

  const isAdmin = user.role === "admin";
  const home = isAdmin ? "/overview" : "/portal";

  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to={home} replace />} />
        <Route path="/login" element={<Navigate to={home} replace />} />
        <Route path="/portal" element={<Portal />} />
        {isAdmin ? (
          <>
            <Route path="/overview" element={<Overview />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/lab" element={<Lab />} />
            <Route path="/events" element={<Events />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/models" element={<Models />} />
            <Route path="/policy" element={<PolicyPage />} />
            <Route path="/comparison" element={<Comparison />} />
            <Route path="/presentation" element={<PresentationMode />} />
            <Route path="/settings" element={<SettingsPage />} />
          </>
        ) : null}
        <Route path="*" element={<Navigate to={home} replace />} />
      </Routes>
    </AppLayout>
  );
}

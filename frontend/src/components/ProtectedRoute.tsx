import { Navigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const { signedIn } = useAuth();
  return signedIn ? <>{children}</> : <Navigate to="/connect" replace />;
}

import { Navigate } from "react-router-dom";
import DeviceLogin from "../components/DeviceLogin";
import { useAuth } from "../context/AuthContext";

export default function Connect() {
  const { signedIn } = useAuth();
  if (signedIn) return <Navigate to="/scanner" replace />;
  return <DeviceLogin />;
}

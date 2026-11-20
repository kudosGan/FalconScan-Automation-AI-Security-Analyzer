import "./Sidebar.css";
import { Link, NavLink } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import SeverityBadge from "./SeverityBadge";
import type { Risk, ScanRecord } from "../types";

const ORDER: Risk[] = ["High", "Medium", "Low", "Unknown"];
const worst = (r: ScanRecord): Risk =>
  ORDER.find((lvl) => r.response.results.some((x) => x.risk === lvl)) ?? "Unknown";
const label = (r: ScanRecord) => {
  const rs = r.response.results;
  return rs.length === 1 ? rs[0].name : `${rs.length} flows`;
};

export default function Sidebar() {
  const { signedIn } = useAuth();
  const { history, clearHistory } = useScan();
  return (
    <aside className="sidebar">
      <Link className="btn new-scan" to="/scan/new">＋ New scan</Link>
      <nav className="side-nav">
        {signedIn && <NavLink to="/scanner">Live scanner</NavLink>}
        <NavLink to="/results">Latest report</NavLink>
      </nav>
      <div className="side-title">
        <span>Recent scans</span>
        {history.length > 0 && <button onClick={clearHistory}>Clear</button>}
      </div>
      <nav className="side-nav">
        {history.length === 0 && <span className="muted">No scans yet</span>}
        {history.map((r) => (
          <NavLink key={r.id} to={`/scan/run/${r.id}`} className="history-item">
            <span>{label(r)}<small>{new Date(r.createdAt).toLocaleTimeString()} · {r.source}</small></span>
            <SeverityBadge level={worst(r)} />
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

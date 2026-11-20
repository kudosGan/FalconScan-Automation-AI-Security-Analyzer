import "./SeverityBadge.css";
import type { Risk } from "../types";

export default function SeverityBadge({ level }: { level: Risk }) {
  return <span className={`badge ${level.toLowerCase()}`}>{level}</span>;
}

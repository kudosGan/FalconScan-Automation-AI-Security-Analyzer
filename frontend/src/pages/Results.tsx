import { Link } from "react-router-dom";
import { useScan } from "../context/ScanContext";
import SummaryCards from "../components/SummaryCards";
import ResultsTable from "../components/ResultsTable";

export default function Results() {
  const { scan } = useScan();
  if (!scan) {
    return <div className="card center"><p>No scan yet.</p><Link className="btn" to="/scan/new">Start a new scan</Link></div>;
  }
  const sorted = [...scan.results].sort((a, b) => b.score - a.score);
  return (
    <>
      <h2>Scan results</h2>
      <SummaryCards results={scan.results} />
      <div className="card"><ResultsTable results={sorted} /></div>
    </>
  );
}

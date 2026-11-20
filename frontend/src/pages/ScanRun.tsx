import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { useScan } from "../context/ScanContext";
import ScanRunner from "../components/ScanRunner";

export default function ScanRun() {
  const { id = "" } = useParams();
  const { history, selectScan, markCompleted } = useScan();
  const record = history.find((r) => r.id === id);

  useEffect(() => { if (record) selectScan(record.id); }, [record?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!record) {
    return <div className="card center"><p>Scan not found.</p><Link className="btn" to="/scan/new">Start a new scan</Link></div>;
  }
  const rs = record.response.results;
  return (
    <>
      <h2>Scanning {rs.length === 1 ? rs[0].name : `${rs.length} flows`}</h2>
      <ScanRunner key={record.id} results={rs} startCompleted={record.completed}
        onComplete={() => markCompleted(record.id)} />
    </>
  );
}

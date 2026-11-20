import "./JsonViewer.css";
export default function JsonViewer({ data, onClose }: { data: unknown; onClose: () => void }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <b>Flow definition</b>
          <button className="btn ghost" onClick={onClose}>Close</button>
        </div>
        <pre className="json">{JSON.stringify(data, null, 2)}</pre>
      </div>
    </div>
  );
}

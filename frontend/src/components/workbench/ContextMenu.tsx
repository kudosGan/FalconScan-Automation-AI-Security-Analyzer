import "./ContextMenu.css";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { MenuItem } from "./MenuBar";

export type CtxItem = MenuItem & { danger?: boolean };
type Props = { x: number; y: number; title?: string; items: CtxItem[]; onClose: () => void };

/** Right-click menu. Closes on outside click, Escape, scroll or resize, and stays inside the window. */
export default function ContextMenu({ x, y, title, items, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos({
      left: Math.max(4, Math.min(x, window.innerWidth - r.width - 4)),
      top: Math.max(4, Math.min(y, window.innerHeight - r.height - 4)),
    });
  }, [x, y]);

  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    window.addEventListener("resize", onClose);
    window.addEventListener("blur", onClose);
    return () => { window.removeEventListener("keydown", esc); window.removeEventListener("resize", onClose); window.removeEventListener("blur", onClose); };
  }, [onClose]);

  return (
    <>
      <div className="ctx-backdrop" onClick={onClose} onContextMenu={(e) => { e.preventDefault(); onClose(); }} />
      <div className="ctx" ref={ref} style={pos} role="menu">
        {title && <div className="ctx-title">{title}</div>}
        {items.map((it, i) => it.separator ? <hr key={i} /> : (
          <button key={i} role="menuitem" disabled={it.disabled} className={it.danger ? "danger" : ""}
            onClick={() => { onClose(); it.onClick?.(); }}>
            <span>{it.label}</span><kbd>{it.shortcut}</kbd>
          </button>
        ))}
      </div>
    </>
  );
}

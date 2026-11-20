import "./Splitter.css";
import { useEffect, useRef, type KeyboardEvent, type PointerEvent } from "react";

const KEY = "falconscan.layout";
type Saved = Record<string, number>;
const read = (): Saved => { try { return JSON.parse(localStorage.getItem(KEY) ?? "{}"); } catch { return {}; } };
const write = (name: string, px: number) => { try { localStorage.setItem(KEY, JSON.stringify({ ...read(), [name]: Math.round(px) })); } catch { /* storage full: ignore */ } };

type Props = {
  /** x: a vertical bar that resizes left and right. y: a horizontal bar that resizes up and down. */
  axis: "x" | "y";
  /** CSS variable that holds the size in pixels of the pane this bar resizes (the stylesheet reads it). */
  cssVar: string;
  /** The pane that changes size: the element just before the bar, or just after it. */
  grows: "prev" | "next";
  min: number;
  /** Size when collapsed (double-click, or drag below half of the minimum). */
  collapsed: number;
  label: string;
};

/** A draggable border between two panes. Remembers its size, collapses on double-click and works with the arrow keys. */
export default function Splitter({ axis, cssVar, grows, min, collapsed, label }: Props) {
  const bar = useRef<HTMLDivElement>(null);
  const drag = useRef<{ start: number; size: number; max: number } | null>(null);
  const root = () => document.documentElement;
  const set = (px: number) => root().style.setProperty(cssVar, `${Math.round(px)}px`);
  const target = () => (grows === "prev" ? bar.current?.previousElementSibling : bar.current?.nextElementSibling) as HTMLElement | null;
  const sizeOf = () => { const r = target()?.getBoundingClientRect(); return r ? (axis === "x" ? r.width : r.height) : 0; };
  const maxOf = () => {
    const p = bar.current?.parentElement?.getBoundingClientRect();
    return Math.max(min, (p ? (axis === "x" ? p.width : p.height) : 800) - 140);
  };

  useEffect(() => { const v = read()[cssVar]; if (typeof v === "number") set(v); }, []);   // eslint-disable-line react-hooks/exhaustive-deps

  const apply = (px: number) => {
    const v = px < min / 2 ? collapsed : Math.min(Math.max(px, min), maxOf());
    set(v); write(cssVar, v);
  };
  const down = (e: PointerEvent) => {
    e.preventDefault();
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    drag.current = { start: axis === "x" ? e.clientX : e.clientY, size: sizeOf(), max: maxOf() };
    document.body.classList.add("resizing", axis === "x" ? "resizing-x" : "resizing-y");
  };
  const move = (e: PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const delta = (axis === "x" ? e.clientX : e.clientY) - d.start;
    apply(d.size + (grows === "prev" ? delta : -delta));
  };
  const up = () => { drag.current = null; document.body.classList.remove("resizing", "resizing-x", "resizing-y"); };
  const toggle = () => {
    const cur = sizeOf();
    if (cur > collapsed + 4) { write(`${cssVar}.restore`, cur); apply(0); }
    else { const back = read()[`${cssVar}.restore`]; apply(typeof back === "number" && back >= min ? back : min * 2); }
  };
  const key = (e: KeyboardEvent) => {
    const grow = axis === "x" ? "ArrowRight" : "ArrowDown";
    const shrink = axis === "x" ? "ArrowLeft" : "ArrowUp";
    if (e.key !== grow && e.key !== shrink) return;
    e.preventDefault();
    const step = (e.key === grow ? 1 : -1) * 24 * (grows === "prev" ? 1 : -1);
    apply(sizeOf() + step);
  };

  return (
    <div ref={bar} className={`splitter splitter-${axis}`} role="separator" tabIndex={0} aria-orientation={axis === "x" ? "vertical" : "horizontal"}
      aria-label={`Resize ${label}`} title={`Drag to resize ${label}. Double-click to collapse or restore.`}
      onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up} onDoubleClick={toggle} onKeyDown={key} />
  );
}

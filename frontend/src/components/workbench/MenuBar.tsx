import "./MenuBar.css";
import { useState } from "react";

export type MenuItem = { label?: string; onClick?: () => void; disabled?: boolean; shortcut?: string; separator?: boolean; items?: MenuItem[]; hint?: string; icon?: string };
export type Menu = { label: string; items: MenuItem[] };

function Items({ items, close }: { items: MenuItem[]; close: () => void }) {
  return (
    <>
      {items.map((it, j) => it.separator ? <hr key={j} /> : it.items ? (
        <div key={j} className={"menu-item has-sub" + (it.disabled ? " off" : "")}>
          <button disabled={it.disabled} title={it.hint}><span><i className="mi">{it.icon}</i>{it.label}</span><kbd>▸</kbd></button>
          {!it.disabled && <div className="menu-drop menu-sub"><Items items={it.items} close={close} /></div>}
        </div>
      ) : (
        <button key={j} disabled={it.disabled} title={it.hint} onClick={() => { close(); it.onClick?.(); }}>
          <span><i className="mi">{it.icon}</i>{it.label}</span><kbd>{it.shortcut}</kbd>
        </button>
      ))}
    </>
  );
}

export default function MenuBar({ menus }: { menus: Menu[] }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="menubar">
      {menus.map((m, i) => (
        <div key={m.label} className="menu">
          <button className={open === i ? "on" : ""} onClick={() => setOpen(open === i ? null : i)}
            onMouseEnter={() => open !== null && setOpen(i)}>{m.label}</button>
          {open === i && (
            <>
              <div className="menu-backdrop" onClick={() => setOpen(null)} />
              <div className="menu-drop"><Items items={m.items} close={() => setOpen(null)} /></div>
            </>
          )}
        </div>
      ))}
    </div>
  );
}

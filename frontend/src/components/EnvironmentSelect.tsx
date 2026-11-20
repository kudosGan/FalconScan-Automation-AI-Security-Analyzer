import type { Env } from "../types";

type Props = {
  envs: Env[]; value: string; admin: boolean;
  onChange: (id: string) => void; onAdminChange: (v: boolean) => void;
};

export default function EnvironmentSelect({ envs, value, admin, onChange, onAdminChange }: Props) {
  return (
    <div className="toolbar">
      <label>Environment{" "}
        <select value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">— select —</option>
          {envs.map((e) => (
            <option key={e.id} value={e.id}>{e.displayName} ({e.type}{e.isDefault ? ", default" : ""})</option>
          ))}
        </select>
      </label>
      <label title="Requires Power Platform admin rights">
        <input type="checkbox" checked={admin} onChange={(e) => onAdminChange(e.target.checked)} /> Admin scope (all flows)
      </label>
    </div>
  );
}

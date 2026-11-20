import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/** Where the live application runs. Set when the public website is built (VITE_APP_URL); empty inside the application itself. */
const APP = ((import.meta.env.VITE_APP_URL as string | undefined) ?? "").replace(/\/$/, "");

/** A link into the application: an ordinary route inside the app, or an address on the live application from the public website. */
export default function AppLink({ to, className, children }: { to: string; className?: string; children: ReactNode }) {
  return APP ? <a className={className} href={APP + to}>{children}</a> : <Link className={className} to={to}>{children}</Link>;
}

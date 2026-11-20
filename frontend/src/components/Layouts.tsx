import "./Layouts.css";
import { Outlet } from "react-router-dom";
import Navbar from "./Navbar";
import Sidebar from "./Sidebar";

export function SimpleLayout() {
  return (
    <>
      <Navbar />
      <main className="container"><Outlet /></main>
    </>
  );
}

export function AppLayout() {
  return (
    <>
      <Navbar />
      <div className="app-shell">
        <Sidebar />
        <main className="app-main"><Outlet /></main>
      </div>
    </>
  );
}

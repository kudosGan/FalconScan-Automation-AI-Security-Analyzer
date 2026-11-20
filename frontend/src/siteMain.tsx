import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { SessionProvider } from "./context/SessionContext";
import Landing from "./pages/Landing";
import SiteNotice from "./pages/SiteNotice";
import "./index.css";

/**
 * The public website: the landing page only. It is built from this file alone, so none of the application
 * (workbench, scanner screens, API code) is included in what visitors download.
 */
createRoot(document.getElementById("root")!).render(
  <BrowserRouter basename={import.meta.env.BASE_URL.replace(/\/$/, "")}>
    <SessionProvider staticSite>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<SiteNotice />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </SessionProvider>
  </BrowserRouter>,
);

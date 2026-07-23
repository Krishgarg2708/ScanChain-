import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ScanUpload from "./pages/ScanUpload";
import ScanDetail from "./pages/ScanDetail";
import Schedules from "./pages/Schedules";
import { isAuthed } from "./api";

function Protected({ children }: { children: React.ReactElement }) {
  return isAuthed() ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Protected><Layout /></Protected>}>
          <Route index element={<Dashboard />} />
          <Route path="scan/new" element={<ScanUpload />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="schedules" element={<Schedules />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

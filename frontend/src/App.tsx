import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Layout from "./components/Layout/Layout";
import DashboardPage from "./pages/DashboardPage";
import EventsPage from "./pages/EventsPage";
import AlertsPage from "./pages/AlertsPage";
import InvestigationPage from "./pages/InvestigationPage";
import RulesPage from "./pages/RulesPage";
import WikiPage from "./pages/WikiPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 15000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/investigation" element={<InvestigationPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/wiki" element={<WikiPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

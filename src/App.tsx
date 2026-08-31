import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { pageTransitionVariants } from './lib/animations';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LanguageProvider, useLanguage } from './context/LanguageContext';
import { Navbar } from './layouts/Navbar';
import { Footer } from './layouts/Footer';
import { HeroSection } from './features/landing/HeroSection';
import { ReportTrackingModal } from './features/landing/ReportTrackingModal';
import { CitizenReportModal } from './features/reports/CitizenReportModal';
import { LeafletMap } from './features/map/LeafletMap';
import { RangerDashboard } from './features/operations/RangerDashboard';
import { AdminPanel } from './features/admin/AdminPanel';
import { AnalyticsDashboard } from './features/analytics/AnalyticsDashboard';
import { GeminiFloatingChat } from './features/assistant/GeminiFloatingChat';
import { ProtectedRoute } from './routes/ProtectedRoute';
import { AboutPage } from './pages/AboutPage';
import { PreventionPage } from './pages/PreventionPage';
import { ContactPage } from './pages/ContactPage';
import { LiveMapPage } from './pages/LiveMapPage';
import { LoginPage } from './pages/LoginPage';
import { LandingPage } from './pages/LandingPage';
import { IncidentReport } from './types';
import api from './services/api';
import { MapPin, CheckCircle2 } from 'lucide-react';
import { Button } from './components/ui/button';

// Animated Route Page Wrapper
const AnimatedRouteWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <motion.div
    variants={pageTransitionVariants}
    initial="initial"
    animate="animate"
    exit="exit"
    className="w-full flex-1 flex flex-col"
  >
    {children}
  </motion.div>
);

// Main App View Router & Layout Container
const MainAppLayout: React.FC = () => {
  const { currentUser, token } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [pendingReports, setPendingReports] = useState<IncidentReport[]>([]);
  const [publicStats, setPublicStats] = useState({
    total: 0,
    active: 0,
    controlled: 0,
    closed: 0,
  });

  // Modals
  const [isCitizenReportOpen, setIsCitizenReportOpen] = useState(false);
  const [isTrackModalOpen, setIsTrackModalOpen] = useState(false);
  const [successTrackingCode, setSuccessTrackingCode] = useState<string | null>(null);

  // Sync route triggers for /reportar and /rastrear
  useEffect(() => {
    if (location.pathname === '/reportar') {
      setIsCitizenReportOpen(true);
    } else if (location.pathname === '/rastrear') {
      setIsTrackModalOpen(true);
    }
  }, [location.pathname]);

  // Fetch reports or public summary from backend
  const fetchData = async () => {
    if (token && currentUser) {
      // 1. Authenticated Officer / Ranger Flow
      try {
        const res = await api.get('/reports/');
        if (res.data && Array.isArray(res.data)) {
          setReports(res.data);
        }
      } catch (err) {
        console.error('Error fetching reports:', err);
      }

      try {
        const resPending = await api.get('/reports/?status=Citizen_Pending');
        if (resPending.data && Array.isArray(resPending.data)) {
          setPendingReports(resPending.data);
        }
      } catch (err) {
        console.error('Error fetching pending reports:', err);
      }
    } else {
      // 2. Unauthenticated Citizen Flow (Safe Public Data)
      try {
        const res = await api.get('/reports/public_summary');
        if (res.data) {
          if (res.data.stats) {
            setPublicStats(res.data.stats);
          }
          if (res.data.reports && Array.isArray(res.data.reports)) {
            setReports(res.data.reports);
          }
        }
      } catch (err) {
        console.error('Error fetching public summary:', err);
        setReports(mockReports);
      }
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => {
      fetchData();
    }, 30000);
    return () => clearInterval(interval);
  }, [token, currentUser]);

  const stats = (token && currentUser)
    ? {
        total: reports.length,
        active: reports.filter((r) => r.status === 'Second_State').length,
        controlled: reports.filter((r) => r.status === 'First_State').length,
        closed: reports.filter((r) => r.status === 'Attended').length,
      }
    : publicStats;

  const isLoginPage = location.pathname === '/login';
  const isAdminPage = location.pathname === '/admin' || location.pathname.startsWith('/admin');
  const isRangerPage = location.pathname === '/guardaparques' || location.pathname.startsWith('/guardaparques');
  const isOperationalPage = isAdminPage || isRangerPage;

  return (
    <div className="min-h-screen flex flex-col bg-[#fbfbf9] dark:bg-[#0b100d] text-[#203126] dark:text-[#f8fafc] font-sans antialiased">
      
      {/* Brand Navbar (Hidden on /login) */}
      {!isLoginPage && (
        <Navbar
          onOpenCitizenReport={() => setIsCitizenReportOpen(true)}
          onOpenTrackModal={() => setIsTrackModalOpen(true)}
        />
      )}

      {/* Main React Router Routes with AnimatePresence */}
      <main className="flex-1 flex flex-col">
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            
            {/* Public Home */}
            <Route
              path="/"
              element={
                <AnimatedRouteWrapper>
                  <LandingPage
                    onOpenCitizenReport={() => setIsCitizenReportOpen(true)}
                    onOpenTrackModal={() => setIsTrackModalOpen(true)}
                    stats={stats}
                  />
                </AnimatedRouteWrapper>
              }
            />

            {/* Public Brand Pages */}
            <Route path="/login" element={<AnimatedRouteWrapper><LoginPage /></AnimatedRouteWrapper>} />
            <Route path="/nosotros" element={<AnimatedRouteWrapper><AboutPage /></AnimatedRouteWrapper>} />
            <Route path="/prevencion" element={<AnimatedRouteWrapper><PreventionPage /></AnimatedRouteWrapper>} />
            <Route path="/contacto" element={<AnimatedRouteWrapper><ContactPage /></AnimatedRouteWrapper>} />
            <Route path="/alertas-en-vivo" element={<AnimatedRouteWrapper><LiveMapPage reports={reports} /></AnimatedRouteWrapper>} />
            <Route path="/reportar" element={<Navigate to="/" replace />} />
            <Route path="/rastrear" element={<Navigate to="/" replace />} />

            {/* Protected Guardaparques Route */}
            <Route element={<ProtectedRoute allowedRoles={['ranger', 'admin']} />}>
              <Route
                path="/guardaparques"
                element={
                  <AnimatedRouteWrapper>
                    <RangerDashboard
                      reports={reports}
                      pendingReports={pendingReports}
                      onRefreshReports={() => {
                        fetchData();
                      }}
                    />
                  </AnimatedRouteWrapper>
                }
              />
            </Route>

            {/* Protected Admin Route */}
            <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
              <Route
                path="/admin"
                element={
                  <AnimatedRouteWrapper>
                    <AdminPanel
                      reports={reports}
                      pendingReports={pendingReports}
                      onRefreshReports={() => {
                        fetchData();
                      }}
                    />
                  </AnimatedRouteWrapper>
                }
              />
            </Route>

            {/* Catch-all Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />

          </Routes>
        </AnimatePresence>
      </main>

      {/* Floating Gemini RAG AI Assistant (Hidden on /login, /admin and /guardaparques) */}
      {!isLoginPage && !isOperationalPage && <GeminiFloatingChat />}

      {/* Footer (Hidden on /login) */}
      {!isLoginPage && <Footer />}

      {/* Modals */}
      <CitizenReportModal
        isOpen={isCitizenReportOpen}
        onClose={() => {
          setIsCitizenReportOpen(false);
          if (location.pathname === '/reportar') navigate('/');
        }}
        onSuccess={(code) => {
          setSuccessTrackingCode(code);
          fetchData();
        }}
      />

      <ReportTrackingModal
        isOpen={isTrackModalOpen}
        onClose={() => {
          setIsTrackModalOpen(false);
          if (location.pathname === '/rastrear') navigate('/');
        }}
      />

      {/* Success Banner */}
      {successTrackingCode && (
        <div className="fixed top-24 right-6 z-50 bg-[#1c2c22] text-white p-5 rounded-2xl shadow-2xl border-2 border-[#3f644e] max-w-sm space-y-3 animate-in fade-in slide-in-from-top-5">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            <h4 className="font-bold text-sm">¡Reporte Registrado!</h4>
          </div>
          <p className="text-xs text-[#77877c]">
            Su reporte ha sido enviado a la brigada de guardaparques del SERNAP. Guarde su código para darle seguimiento:
          </p>
          <div className="p-2.5 rounded-lg bg-[#3f644e]/30 border border-[#3f644e] text-center font-mono font-extrabold text-emerald-300 tracking-wider">
            {successTrackingCode}
          </div>
          <Button
            size="sm"
            onClick={() => setSuccessTrackingCode(null)}
            className="w-full bg-[#3f644e] text-white text-xs font-bold"
          >
            Entendido
          </Button>
        </div>
      )}

    </div>
  );
};

// Root Component
export default function App() {
  return (
    <AuthProvider>
      <LanguageProvider>
        <BrowserRouter>
          <MainAppLayout />
        </BrowserRouter>
      </LanguageProvider>
    </AuthProvider>
  );
}

// Fallback Mock Data
const mockReports: IncidentReport[] = [
  {
    id: 1,
    tracking_code: 'WCH-8921',
    date_reported: '2026-07-29',
    reporter_name: 'Guardaparques Ramos',
    reporter_type: 'ranger',
    incident_type: 'Incendio Forestal',
    severity: 'Alto',
    probable_cause: 'Quema Agrícola',
    vegetation_type: 'Bosque Seco',
    latitude: -17.3401,
    longitude: -66.1823,
    status: 'Second_State',
    description: 'Fuego activo en ladera norte de Taquiña con vientos sostenidos.',
  },
  {
    id: 2,
    tracking_code: 'WCH-7740',
    date_reported: '2026-07-28',
    reporter_name: 'Ciudadano Anónimo',
    reporter_type: 'citizen',
    incident_type: 'Quema Descontrolada',
    severity: 'Medio',
    probable_cause: 'Negligencia',
    vegetation_type: 'Pastizal',
    latitude: -17.382,
    longitude: -66.234,
    status: 'Attended',
    description: 'Quema de pastizales sofocada por brigada SAR-Bolivia.',
  },
];

const mockPendingReports: IncidentReport[] = [
  {
    id: 3,
    tracking_code: 'WCH-9102',
    date_reported: '2026-07-30',
    reporter_name: 'Juan Mendoza',
    reporter_email: 'juan@gmail.com',
    reporter_type: 'citizen',
    incident_type: 'Foco de Calor',
    severity: 'Medio',
    probable_cause: 'Quema Agrícola',
    vegetation_type: 'Matorral',
    latitude: -17.361,
    longitude: -66.21,
    status: 'First_State',
    description: 'Columna de humo blanco observada desde Tiquipaya.',
  },
];

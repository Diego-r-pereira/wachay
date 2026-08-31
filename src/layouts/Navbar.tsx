import React, { useState, useEffect, useRef } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { Button } from '@/components/ui/button';
import { LogIn, LogOut, Flame, Sun, Moon, Menu, X, Check, ChevronDown, Shield, User, Radio } from 'lucide-react';
import { motion, AnimatePresence, useScroll, useMotionValueEvent } from 'motion/react';
import { gentleSpring } from '../lib/animations';

import isoSvgGreen from '../assets/iso_svg_green.svg';
import isoSvgWhite from '../assets/iso_svg_white.svg';

interface NavbarProps {
  onOpenCitizenReport: () => void;
  onOpenTrackModal?: () => void;
}

const LANGUAGES = [
  { code: 'es', label: 'ES' },
  { code: 'en', label: 'EN' },
  { code: 'qu', label: 'QU' },
] as const;

export const Navbar: React.FC<NavbarProps> = ({ onOpenCitizenReport }) => {
  const { currentUser, logout } = useAuth();
  const { lang, setLang, t } = useLanguage();
  const navigate = useNavigate();
  const location = useLocation();

  const isAdminPage = location.pathname === '/admin' || location.pathname.startsWith('/admin');
  const isRangerPage = location.pathname === '/guardaparques' || location.pathname.startsWith('/guardaparques');
  const isOperationalPage = isAdminPage || isRangerPage;
  const isHomePage = location.pathname === '/';

  // Scroll dynamics for public non-operational pages
  const { scrollY } = useScroll();
  const [hidden, setHidden] = useState(false);
  const [isAtTop, setIsAtTop] = useState(true);

  useMotionValueEvent(scrollY, 'change', (latest) => {
    if (isOperationalPage) return; // Never hide or float in operational pages

    const previous = scrollY.getPrevious() ?? 0;
    const diff = latest - previous;

    if (latest <= 30) {
      setIsAtTop(true);
      setHidden(false);
    } else {
      setIsAtTop(false);
      // If scrolling down significantly and past top zone
      if (diff > 6 && latest > 120) {
        setHidden(true);
      } else if (diff < -6) {
        // If scrolling up
        setHidden(false);
      }
    }
  });

  // Dark Mode state
  const [isDark, setIsDark] = useState<boolean>(() => {
    return document.documentElement.classList.contains('dark') ||
      window.matchMedia('(prefers-color-scheme: dark)').matches;
  });

  // Mobile menu drawer state
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);

  // Custom Language Dropdown state
  const [isLangOpen, setIsLangOpen] = useState<boolean>(false);
  const langRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (langRef.current && !langRef.current.contains(e.target as Node)) {
        setIsLangOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const toggleTheme = () => {
    setIsDark((prev) => !prev);
  };

  const currentLangObj = LANGUAGES.find((l) => l.code === lang) || LANGUAGES[0];

  const navLinkClass = ({ isActive }: { isActive: boolean }) => {
    if (isAtTop && isHomePage) {
      return `px-3.5 py-2 text-xs font-bold rounded-xl transition-all ${
        isActive
          ? 'bg-white/20 text-white font-extrabold shadow-sm backdrop-blur-md'
          : 'text-slate-100 hover:text-white hover:bg-white/10 drop-shadow'
      }`;
    }

    return `px-3.5 py-2 text-xs font-bold rounded-xl transition-all ${
      isActive
        ? 'bg-emerald-500/15 text-emerald-800 dark:text-emerald-300 font-extrabold shadow-xs'
        : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5'
    }`;
  };

  const isRangerOrAdmin = currentUser?.role === 'ranger' || currentUser?.role === 'admin';

  // ==========================================
  // 1. OPERATIONAL COMMAND HEADER (Admin & Guardaparques - Fixed at Top, Non-Floating)
  // ==========================================
  if (isOperationalPage) {
    const portalTitle = isAdminPage ? 'Panel Admin' : 'Guardaparques';
    const portalSubtitle = isAdminPage
      ? 'Sistema Central SERNAP Cochabamba'
      : 'Puesto de Control & Operaciones Tunari';
    const roleBadge = isAdminPage ? 'Administrador Central' : 'Guardaparques SERNAP';
    const roleBadgeClass = isAdminPage
      ? 'bg-purple-100 dark:bg-purple-950/60 text-purple-900 dark:text-purple-300 border-purple-300 dark:border-purple-800'
      : 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-900 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800';

    return (
      <header className="w-full bg-white dark:bg-[#0b100d] border-b border-slate-200/90 dark:border-white/[0.08] shadow-xs relative z-40">
        <div className="max-w-7xl mx-auto h-20 px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-6">
          
          {/* Brand & Portal Identity */}
          <div
            className="flex items-center gap-3 cursor-pointer group"
            onClick={() => navigate('/')}
          >
            <div className="p-2 rounded-xl bg-emerald-500/10 dark:bg-white/10 group-hover:scale-105 transition-transform">
              <img
                src={isoSvgGreen}
                alt="WACHAY Isotype Light"
                className="h-9 w-auto dark:hidden"
              />
              <img
                src={isoSvgWhite}
                alt="WACHAY Isotype Dark"
                className="h-9 w-auto hidden dark:block"
              />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-heading text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                  WACHAY
                </span>
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase font-mono border ${roleBadgeClass}`}>
                  {portalTitle}
                </span>
              </div>
              <span className="text-[11px] text-slate-500 dark:text-slate-400">
                {portalSubtitle}
              </span>
            </div>
          </div>

          {/* Right Side: Generous Spacing for High Legibility */}
          <div className="flex items-center gap-4 sm:gap-6">
            
            {/* Quick Link to Main Public Site */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/')}
              className="hidden md:flex text-xs font-bold border-slate-200 dark:border-white/10 rounded-xl h-10 px-4 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-surface-elevated cursor-pointer"
            >
              <span>Ver Sitio Público</span>
            </Button>

            {/* Theme Toggle Button */}
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleTheme}
              title={isDark ? 'Modo Claro' : 'Modo Oscuro'}
              className="h-10 w-10 text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white rounded-xl cursor-pointer hover:bg-slate-100 dark:hover:bg-surface-elevated"
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-emerald-600" />}
            </Button>

            {/* Divider */}
            <div className="hidden sm:block h-6 w-[1px] bg-slate-200 dark:bg-white/10" />

            {/* User Profile Info & Logout */}
            <div className="flex items-center gap-3">
              <div className="hidden sm:flex flex-col text-right">
                <span className="text-xs font-extrabold text-slate-900 dark:text-white font-mono">
                  {currentUser?.first_name || currentUser?.username || 'Guardaparques'}
                </span>
                <span className="text-[10px] text-emerald-700 dark:text-emerald-400 font-mono font-semibold">
                  {roleBadge}
                </span>
              </div>

              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  logout();
                  navigate('/');
                }}
                className="border-rose-200 dark:border-rose-900/40 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/30 h-10 px-3.5 rounded-xl font-bold text-xs gap-2 cursor-pointer transition-all"
                title="Cerrar sesión"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden sm:inline">Cerrar Sesión</span>
              </Button>
            </div>

          </div>

        </div>
      </header>
    );
  }

  // ==========================================
  // 2. PUBLIC FLOATING NAVBAR (For Landing and Public Views)
  // ==========================================
  return (
    <motion.header
      variants={{
        visible: { y: 0, opacity: 1 },
        hidden: { y: -100, opacity: 0 },
      }}
      animate={hidden ? 'hidden' : 'visible'}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className="fixed top-3 sm:top-4 left-0 right-0 z-50 px-3 sm:px-6 lg:px-8 pointer-events-none"
    >
      <div
        className={`max-w-7xl mx-auto h-16 sm:h-20 px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-4 rounded-2xl sm:rounded-3xl pointer-events-auto transition-all duration-300 ${
          isAtTop
            ? 'bg-transparent border-transparent shadow-none'
            : 'bg-[#fbfbf9]/85 dark:bg-[#0b100d]/85 backdrop-blur-xl border border-white/40 dark:border-white/[0.12] shadow-2xl'
        }`}
      >
        
        {/* Logo & Brand Title */}
        <motion.div
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          className="flex items-center gap-3 cursor-pointer group"
          onClick={() => navigate('/')}
        >
          <div
            className={`relative flex items-center justify-center p-2 rounded-xl transition-all ${
              isAtTop && isHomePage
                ? 'bg-black/40 backdrop-blur-md border border-white/20'
                : 'bg-emerald-500/10 dark:bg-white/10'
            }`}
          >
            {isAtTop && isHomePage ? (
              <img
                src={isoSvgWhite}
                alt="WACHAY Isotype"
                className="h-9 sm:h-10 w-auto"
              />
            ) : (
              <>
                <img
                  src={isoSvgGreen}
                  alt="WACHAY Isotype Light"
                  className="h-9 sm:h-10 w-auto dark:hidden"
                />
                <img
                  src={isoSvgWhite}
                  alt="WACHAY Isotype Dark"
                  className="h-9 sm:h-10 w-auto hidden dark:block"
                />
              </>
            )}
          </div>
          <div>
            <span
              className={`font-heading text-xl sm:text-2xl font-bold tracking-tight flex items-center gap-1.5 transition-colors ${
                isAtTop && isHomePage
                  ? 'text-white drop-shadow-[0_2px_8px_rgba(0,0,0,0.8)]'
                  : 'text-slate-900 dark:text-white'
              }`}
            >
              WACHAY
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            </span>
          </div>
        </motion.div>

        {/* Desktop Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1">
          {!isRangerOrAdmin && (
            <>
              <NavLink to="/nosotros" className={navLinkClass}>
                {t('navAbout')}
              </NavLink>

              <NavLink to="/prevencion" className={navLinkClass}>
                {t('navPrevention')}
              </NavLink>

              <NavLink to="/contacto" className={navLinkClass}>
                {t('navContact')}
              </NavLink>

              <NavLink to="/alertas-en-vivo" className={navLinkClass}>
                {t('navLiveMap')}
              </NavLink>
            </>
          )}

          {currentUser?.role === 'ranger' && (
            <NavLink to="/guardaparques" className={navLinkClass}>
              {t('navRanger')}
            </NavLink>
          )}

          {currentUser?.role === 'admin' && (
            <NavLink to="/admin" className={navLinkClass}>
              {t('navAdmin')}
            </NavLink>
          )}
        </nav>

        {/* Right Actions: CTAs, Theme Toggle, Sleek Initials Language Dropdown, Auth */}
        <div className="flex items-center gap-2 sm:gap-3">
          
          {/* Quick Report Citizen Button */}
          {!isRangerOrAdmin && (
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button
                onClick={onOpenCitizenReport}
                title="Reportar Incendio"
                size="icon"
                className="bg-rose-600 hover:bg-rose-700 text-white font-medium shadow-md hover:shadow-lg transition-all h-9 sm:h-10 w-9 sm:w-10 rounded-xl cursor-pointer"
              >
                <Flame className="w-5 h-5 animate-bounce" />
              </Button>
            </motion.div>
          )}

          {/* Theme Switcher Toggle (Sun / Moon) */}
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleTheme}
            title={isDark ? 'Modo Claro' : 'Modo Oscuro'}
            className={`h-9 w-9 rounded-xl cursor-pointer transition-colors ${
              isAtTop && isHomePage
                ? 'text-white hover:bg-white/20'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-emerald-600" />}
          </Button>

          {/* Clean Initials Only Language Dropdown (ES, EN, QU) - Hidden for Rangers & Admins */}
          {!isRangerOrAdmin && (
            <div className="relative" ref={langRef}>
              <button
                onClick={() => setIsLangOpen(!isLangOpen)}
                className={`h-9 px-3 flex items-center gap-1.5 text-xs font-extrabold uppercase rounded-xl transition-all shadow-xs cursor-pointer ${
                  isAtTop && isHomePage
                    ? 'bg-black/40 backdrop-blur-md border border-white/20 text-white hover:bg-black/60'
                    : 'bg-slate-100 dark:bg-surface-elevated hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-white/10'
                }`}
              >
                <span>{currentLangObj.label}</span>
                <ChevronDown className="w-3 h-3 opacity-70" />
              </button>

              <AnimatePresence>
                {isLangOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -6, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -6, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 mt-2 w-28 bg-[#fbfbf9] dark:bg-surface-elevated border border-slate-200 dark:border-white/10 rounded-2xl shadow-2xl py-1.5 z-50 backdrop-blur-xl"
                  >
                    {LANGUAGES.map((l) => (
                      <button
                        key={l.code}
                        onClick={() => {
                          setLang(l.code as 'es' | 'en' | 'qu');
                          setIsLangOpen(false);
                        }}
                        className="w-full px-3 py-2 text-left text-xs font-bold flex items-center justify-between hover:bg-emerald-500/15 text-slate-800 dark:text-slate-200 transition-colors cursor-pointer"
                      >
                        <span className="flex items-center gap-2">
                          <span>{l.label}</span>
                          <span className="text-[10px] text-slate-400 font-normal">
                            {l.code === 'es' ? 'Español' : l.code === 'en' ? 'English' : 'Quechua'}
                          </span>
                        </span>
                        {lang === l.code && <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />}
                      </button>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          {/* Authentication Action Button */}
          {currentUser ? (
            <div className="flex items-center gap-2">
              <span
                className={`text-xs font-mono font-bold hidden sm:inline ${
                  isAtTop && isHomePage ? 'text-white' : 'text-slate-700 dark:text-slate-300'
                }`}
              >
                {currentUser.username}
              </span>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => {
                  logout();
                  navigate('/');
                }}
                title={t('logout')}
                className="text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/30 h-9 w-9 rounded-xl cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
              </Button>
            </div>
          ) : (
            <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
              <Button
                onClick={() => navigate('/login')}
                className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold shadow-sm transition-all gap-1.5 text-xs h-9 px-3.5 rounded-xl cursor-pointer"
              >
                <LogIn className="w-4 h-4" />
                <span className="hidden sm:inline">{t('btnLogin')}</span>
              </Button>
            </motion.div>
          )}

          {/* Mobile Hamburger Toggle Button */}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className={`lg:hidden h-9 w-9 cursor-pointer ${
              isAtTop && isHomePage ? 'text-white hover:bg-white/20' : 'text-slate-900 dark:text-white'
            }`}
          >
            {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>

        </div>
      </div>

      {/* Mobile Slide-Out Drawer Navigation */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.98 }}
            transition={{ duration: 0.2 }}
            className="lg:hidden mt-2 max-w-7xl mx-auto bg-[#fbfbf9]/95 dark:bg-[#0b100d]/95 backdrop-blur-xl border border-white/40 dark:border-white/[0.12] rounded-2xl shadow-2xl px-5 py-4 space-y-2 text-xs font-bold pointer-events-auto"
          >
            {!isRangerOrAdmin && (
              <>
                <NavLink
                  to="/nosotros"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="block py-2 text-slate-700 dark:text-slate-300 hover:text-emerald-600"
                >
                  {t('navAbout')}
                </NavLink>
                <NavLink
                  to="/prevencion"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="block py-2 text-slate-700 dark:text-slate-300 hover:text-emerald-600"
                >
                  {t('navPrevention')}
                </NavLink>
                <NavLink
                  to="/contacto"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="block py-2 text-slate-700 dark:text-slate-300 hover:text-emerald-600"
                >
                  {t('navContact')}
                </NavLink>
                <NavLink
                  to="/alertas-en-vivo"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="block py-2 text-slate-700 dark:text-slate-300 hover:text-emerald-600"
                >
                  {t('navLiveMap')}
                </NavLink>
              </>
            )}

            {currentUser?.role === 'ranger' && (
              <NavLink
                to="/guardaparques"
                onClick={() => setIsMobileMenuOpen(false)}
                className="block py-2 text-slate-700 dark:text-slate-300 hover:text-emerald-600"
              >
                {t('navRanger')}
              </NavLink>
            )}

            {currentUser?.role === 'admin' && (
              <NavLink
                to="/admin"
                onClick={() => setIsMobileMenuOpen(false)}
                className="block py-2 text-slate-700 dark:text-slate-300 hover:text-emerald-600"
              >
                {t('navAdmin')}
              </NavLink>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.header>
  );
};

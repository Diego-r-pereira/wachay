import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { PhoneCall, Shield, Radio, Trees } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import isoSvgWhite from '../assets/iso_svg_white.svg';

export const Footer: React.FC = () => {
  const location = useLocation();
  const { t } = useLanguage();
  const isAdminPage = location.pathname === '/admin' || location.pathname.startsWith('/admin');
  const isRangerPage = location.pathname === '/guardaparques' || location.pathname.startsWith('/guardaparques');
  const isOperationalPage = isAdminPage || isRangerPage;

  // ==========================================
  // 1. OPERATIONAL FOOTER (Only Brand Identity & Mission Centered)
  // ==========================================
  if (isOperationalPage) {
    const consoleLabel = isAdminPage
      ? 'Consola Administrativa Central'
      : 'Puesto de Control & Operaciones Guardaparques';

    return (
      <footer className="bg-[#070b08] text-slate-400 border-t border-white/[0.07] mt-auto select-none py-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center justify-center text-center space-y-4">
          
          {/* Centered Brand Mark */}
          <NavLink to="/" className="flex items-center gap-3 group">
            <img
              src={isoSvgWhite}
              alt="WACHAY Emblem"
              className="h-8 w-auto transition-transform group-hover:scale-105"
            />
            <span className="font-heading text-xl font-bold tracking-tight text-white group-hover:text-emerald-400 transition-colors">
              WACHAY
            </span>
          </NavLink>

          {/* Centered Subtitle & SERNAP Credit */}
          <div className="space-y-1 max-w-lg">
            <p className="text-xs font-mono font-medium text-slate-300">
              Wildfire Alert & Cochabamba Heat Analysis System
            </p>
            <p className="text-[11px] text-slate-500 flex items-center justify-center gap-1.5">
              <Trees className="w-3.5 h-3.5 text-emerald-500" />
              <span>Custodiando el Parque Nacional Tunari • SERNAP Bolivia</span>
            </p>
          </div>

          <p className="text-[10px] text-slate-600 font-mono pt-2">
            © {new Date().getFullYear()} WACHAY System • {consoleLabel}
          </p>
        </div>
      </footer>
    );
  }

  // ==========================================
  // 2. PUBLIC MINIMALIST FOOTER
  // ==========================================
  return (
    <footer className="bg-[#070b08] text-slate-400 border-t border-white/[0.07] mt-auto select-none">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 sm:py-12 space-y-8">
        
        {/* Main Single-Row Minimalist Flow */}
        <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
          
          {/* Brand Identity & Mission */}
          <div className="flex flex-col sm:flex-row items-center sm:items-start text-center sm:text-left gap-4">
            <NavLink to="/" className="flex items-center gap-3 group">
              <img
                src={isoSvgWhite}
                alt="WACHAY Emblem"
                className="h-8 w-auto transition-transform group-hover:scale-105"
              />
              <span className="font-heading text-xl font-bold tracking-tight text-white group-hover:text-emerald-400 transition-colors">
                WACHAY
              </span>
            </NavLink>

            <div className="hidden sm:block h-7 w-[1px] bg-white/10" />

            <div className="space-y-0.5">
              <p className="text-xs font-mono font-medium text-slate-300">
                Wildfire Alert & Cochabamba Heat Analysis System
              </p>
              <p className="text-[11px] text-slate-500 flex items-center justify-center sm:justify-start gap-1.5">
                <Trees className="w-3 h-3 text-emerald-500" />
                <span>Custodiando el Parque Nacional Tunari • SERNAP Bolivia</span>
              </p>
            </div>
          </div>

          {/* Clean Horizontal Navigation */}
          <nav className="flex flex-wrap items-center justify-center gap-6 sm:gap-8 text-xs font-semibold">
            <NavLink
              to="/nosotros"
              className={({ isActive }) =>
                `transition-colors hover:text-white ${isActive ? 'text-emerald-400' : 'text-slate-400'}`
              }
            >
              {t('navAbout')}
            </NavLink>
            <NavLink
              to="/prevencion"
              className={({ isActive }) =>
                `transition-colors hover:text-white ${isActive ? 'text-emerald-400' : 'text-slate-400'}`
              }
            >
              {t('navPrevention')}
            </NavLink>
            <NavLink
              to="/contacto"
              className={({ isActive }) =>
                `transition-colors hover:text-white ${isActive ? 'text-emerald-400' : 'text-slate-400'}`
              }
            >
              {t('navContact')}
            </NavLink>
            <NavLink
              to="/alertas-en-vivo"
              className={({ isActive }) =>
                `transition-colors hover:text-white flex items-center gap-1.5 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`
              }
            >
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              <span>{t('navLiveMap')}</span>
            </NavLink>
          </nav>

          {/* Minimalist Emergency Quick Dial Pill */}
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/[0.04] border border-white/10 text-xs text-slate-300">
            <PhoneCall className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-[11px] text-slate-400 font-mono">Emergencias:</span>
            <a href="tel:119" className="font-mono font-bold text-white hover:text-rose-400 transition-colors">
              119
            </a>
            <span className="text-white/20">•</span>
            <a href="tel:132" className="font-mono font-bold text-white hover:text-emerald-400 transition-colors">
              132
            </a>
          </div>

        </div>

        {/* Minimal Sub-Footer Bar */}
        <div className="border-t border-white/[0.05] pt-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-slate-500 font-mono">
          <p>© {new Date().getFullYear()} WACHAY System. Todos los derechos reservados.</p>
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Monitoreo Activo en Tiempo Real</span>
          </div>
        </div>

      </div>
    </footer>
  );
};

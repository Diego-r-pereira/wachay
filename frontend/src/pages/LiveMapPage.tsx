import React, { useState } from 'react';
import { LeafletMap } from '../features/map/LeafletMap';
import { AnalyticsDashboard } from '../features/analytics/AnalyticsDashboard';
import { IncidentReport } from '../types';
import { MapPin, Flame, BarChart3, Radio, ShieldAlert, CheckCircle2, ShieldCheck, Activity, Layers, Sparkles } from 'lucide-react';
import { motion } from 'motion/react';
import { useLanguage } from '../context/LanguageContext';
import { fadeInUp, staggerContainer, gentleSpring } from '../lib/animations';

interface LiveMapPageProps {
  reports: IncidentReport[];
}

export const LiveMapPage: React.FC<LiveMapPageProps> = ({ reports }) => {
  const { t } = useLanguage();
  const [activeFilter, setActiveFilter] = useState<'all' | 'active' | 'controlled' | 'closed'>('all');
  const [focusedReportId, setFocusedReportId] = useState<number | null>(null);

  const activeCount = reports.filter((r) => r.status === 'Second_State').length;
  const controlledCount = reports.filter((r) => r.status === 'First_State').length;
  const closedCount = reports.filter((r) => r.status === 'Attended').length;

  const handleFilterChange = (filter: 'all' | 'active' | 'controlled' | 'closed') => {
    setActiveFilter(filter);
    setFocusedReportId(null); // Clear selected focused incident when switching filter
  };

  const filteredReports = reports.filter((r) => {
    if (activeFilter === 'active') return r.status === 'Second_State';
    if (activeFilter === 'controlled') return r.status === 'First_State';
    if (activeFilter === 'closed') return r.status === 'Attended';
    return true;
  });

  return (
    <div className="relative min-h-screen bg-[#f8faf7] dark:bg-obsidian text-slate-900 dark:text-[#f8fafc] pt-28 sm:pt-36 pb-32 overflow-hidden space-y-12 sm:space-y-16">
      
      {/* Ambient Topographic Glows */}
      <div className="absolute top-20 left-[-10%] w-[550px] h-[550px] rounded-full bg-rose-500/10 dark:bg-rose-500/10 blur-[140px] pointer-events-none -z-0" />
      <div className="absolute top-[800px] right-[-10%] w-[650px] h-[650px] rounded-full bg-cuenca/15 dark:bg-cuenca/10 blur-[160px] pointer-events-none -z-0" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-10 relative z-10">
        
        {/* COMMAND CENTER HEADER BAR */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-200/80 dark:border-white/[0.08] pb-6"
        >
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 text-xs font-bold font-mono border border-rose-200 dark:border-rose-800/40">
                <Radio className="w-3.5 h-3.5 text-rose-600 animate-pulse" />
                {t('liveMap.badge')}
              </span>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                {t('liveMap.syncSub')}
              </span>
            </div>

            <h1 className="text-3xl sm:text-4xl font-black font-heading text-slate-900 dark:text-white flex items-center gap-3">
              <MapPin className="w-8 h-8 text-rose-600 animate-bounce" />
              {t('liveMap.title')}
            </h1>

            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
              {t('liveMap.subtitle')}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 text-xs font-bold border border-emerald-200 dark:border-emerald-700/50">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              {t('liveMap.systemSynced')}
            </span>
          </div>
        </motion.div>

        {/* MAP & LIVE STREAM SPLIT SECTION */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Main GIS Map Viewport (8 cols) */}
          <div className="lg:col-span-8 space-y-4">
            
            {/* Metric Status Pills as Interactive Clickable Filter Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] p-2.5 rounded-2xl shadow-sm">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                
                {/* Total Pill */}
                <button
                  onClick={() => handleFilterChange('all')}
                  className={`px-3.5 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                    activeFilter === 'all'
                      ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-950 shadow-md ring-2 ring-slate-400 font-extrabold scale-105'
                      : 'bg-slate-50 dark:bg-surface-elevated text-slate-700 dark:text-slate-200 border border-slate-200/80 dark:border-white/[0.08] hover:border-slate-400'
                  }`}
                >
                  <Activity className={`w-4 h-4 ${activeFilter === 'all' ? 'text-emerald-400 dark:text-emerald-600' : 'text-slate-500'}`} />
                  <span>{t('liveMap.filterAll')}</span>
                  <span className="font-mono font-bold text-sm ml-0.5">({reports.length})</span>
                </button>

                {/* Activos Pill */}
                <button
                  onClick={() => handleFilterChange('active')}
                  className={`px-3.5 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 ${
                    activeFilter === 'active'
                      ? 'bg-rose-600 text-white shadow-md ring-2 ring-rose-300 font-extrabold scale-105'
                      : 'bg-rose-50/90 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800/40 hover:border-rose-400'
                  }`}
                  title={t('liveMap.filterActive')}
                >
                  <Flame className={`w-4 h-4 ${activeFilter === 'active' ? 'text-amber-200 animate-bounce' : 'text-rose-600 animate-pulse'}`} />
                  <span className="font-mono font-bold text-sm">({activeCount})</span>
                </button>

                {/* En Control Pill */}
                <button
                  onClick={() => handleFilterChange('controlled')}
                  className={`px-3.5 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 ${
                    activeFilter === 'controlled'
                      ? 'bg-amber-500 text-slate-950 shadow-md ring-2 ring-amber-200 font-extrabold scale-105'
                      : 'bg-amber-50/90 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-pajonal/40 hover:border-pajonal'
                  }`}
                  title={t('liveMap.filterControlled')}
                >
                  <ShieldAlert className={`w-4 h-4 ${activeFilter === 'controlled' ? 'text-slate-950' : 'text-amber-600'}`} />
                  <span className="font-mono font-bold text-sm">({controlledCount})</span>
                </button>

                {/* Sofocados Pill */}
                <button
                  onClick={() => handleFilterChange('closed')}
                  className={`px-3.5 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 ${
                    activeFilter === 'closed'
                      ? 'bg-emerald-600 text-white shadow-md ring-2 ring-emerald-300 font-extrabold scale-105'
                      : 'bg-emerald-50/90 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 border border-emerald-500/30 hover:border-emerald-500'
                  }`}
                  title={t('liveMap.filterClosed')}
                >
                  <CheckCircle2 className={`w-4 h-4 ${activeFilter === 'closed' ? 'text-white' : 'text-emerald-600'}`} />
                  <span className="font-mono font-bold text-sm">({closedCount})</span>
                </button>
              </div>

              <span className="text-[11px] text-slate-400 hidden sm:inline-block">
                {t('liveMap.filterHint')}
              </span>
            </div>

            {/* Interactive Leaflet Map */}
            <LeafletMap
              reports={reports}
              activeFilter={activeFilter}
              focusedReportId={focusedReportId}
              height="620px"
            />
          </div>

          {/* User-Friendly Incident List (4 cols) */}
          <div className="lg:col-span-4 bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-white/[0.08] pb-3">
              <div>
                <h3 className="font-bold text-sm font-heading text-slate-900 dark:text-white flex items-center gap-2">
                  <Flame className="w-4 h-4 text-rose-600" />
                  {t('liveMap.listTitle')}
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  {t('liveMap.listSub')}
                </p>
              </div>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-surface-elevated text-slate-600 dark:text-slate-300">
                {filteredReports.length}
              </span>
            </div>

            {/* Scrollable list of reports */}
            <div className="space-y-3 max-h-[540px] overflow-y-auto pr-1">
              {filteredReports.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400 space-y-2">
                  <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500" />
                  <p className="font-medium text-slate-600 dark:text-slate-300">{t('liveMap.emptyTitle')}</p>
                  <p className="text-[11px]">{t('liveMap.emptySub')}</p>
                </div>
              ) : (
                filteredReports.map((r) => {
                  const isSelected = focusedReportId === r.id;
                  const rawSev = String(r.severity_level || r.severity || 'Medio').toLowerCase();
                  const sev = rawSev.includes('cr') || rawSev.includes('alt') || rawSev.includes('high') ? t('analytics.sevHigh') : rawSev.includes('baj') || rawSev.includes('low') ? t('analytics.sevLow') : t('analytics.sevMed');

                  return (
                    <motion.div
                      key={r.id}
                      whileHover={{ scale: 1.02, x: 2 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setFocusedReportId(r.id)}
                      className={`p-3.5 rounded-2xl border transition-all cursor-pointer space-y-2 text-xs ${
                        isSelected
                          ? 'bg-emerald-50 dark:bg-surface-elevated border-emerald-500 shadow-md ring-2 ring-emerald-500/40'
                          : 'bg-slate-50/80 dark:bg-surface-elevated/70 border-slate-200/80 dark:border-white/[0.08] hover:border-emerald-400'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <p className="font-bold text-slate-900 dark:text-white text-xs">
                          {r.incident_type}
                        </p>
                        <span className={`font-extrabold text-[9px] uppercase px-2 py-0.5 rounded-full shrink-0 ${
                          rawSev.includes('cr') || rawSev.includes('alt') || rawSev.includes('high')
                            ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300'
                            : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                        }`}>
                          {sev}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200/50 dark:border-white/5">
                        <span>
                          {r.date_reported || t('liveMap.recent')}
                        </span>
                        <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                          {r.status === 'Second_State' ? t('liveMap.statusActive') : r.status === 'First_State' ? t('liveMap.statusControlled') : t('liveMap.statusClosed')}
                        </span>
                      </div>
                    </motion.div>
                  );
                })
              )}
            </div>
          </div>

        </div>

        {/* SECTION: OPERATIONAL ANALYTICS & STATS DASHBOARD */}
        <section className="space-y-4 pt-6">
          <div className="flex items-center gap-2 border-b border-slate-200/80 dark:border-white/[0.08] pb-3">
            <BarChart3 className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
            <h2 className="text-2xl font-bold font-heading text-slate-900 dark:text-white">
              {t('liveMap.analyticsTitle')}
            </h2>
          </div>
          
          <AnalyticsDashboard
            reports={reports}
            onSelectReport={(id) => {
              setFocusedReportId(id);
              window.scrollTo({ top: 120, behavior: 'smooth' });
            }}
          />
        </section>

      </div>
    </div>
  );
};

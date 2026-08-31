import React from 'react';
import { IncidentReport } from '../../types';
import { TrendingUp, Clock, AlertTriangle, ShieldCheck, Flame, Calendar, Activity, Compass, CheckCircle2, ChevronRight, Layers } from 'lucide-react';
import { motion } from 'motion/react';
import { useLanguage } from '../../context/LanguageContext';
import { fadeInUp, staggerContainer, gentleSpring } from '../../lib/animations';

interface AnalyticsDashboardProps {
  reports: IncidentReport[];
  onSelectReport?: (id: number) => void;
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({
  reports,
  onSelectReport,
}) => {
  const { t } = useLanguage();
  const totalCount = reports.length;
  const activeCount = reports.filter((r) => r.status === 'Second_State').length;
  const controlledCount = reports.filter((r) => r.status === 'First_State').length;
  const closedCount = reports.filter((r) => r.status === 'Attended').length;

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-10 shadow-xl space-y-8 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-5">
        <div>
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            {t('analytics.badge')}
          </span>
          <h3 className="text-xl sm:text-2xl font-extrabold font-heading text-slate-900 dark:text-white mt-1">
            {t('analytics.title')}
          </h3>
        </div>
        <span className="px-3.5 py-1.5 rounded-full bg-cuenca/15 text-cuenca-dark dark:text-cuenca text-xs font-mono font-bold border border-cuenca/30">
          {t('analytics.base')}
        </span>
      </div>

      {/* Metric Cards Grid */}
      <motion.div
        variants={staggerContainer}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true }}
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6"
      >
        {/* Metric 1: Response Time (Cuenca) */}
        <motion.div
          variants={fadeInUp}
          whileHover={{ y: -4, scale: 1.02 }}
          transition={gentleSpring}
          className="p-5 rounded-2xl bg-slate-50/80 dark:bg-surface-elevated border border-cuenca/30 dark:border-white/[0.08] space-y-2 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-cuenca-dark dark:text-cuenca-light font-mono">
              {t('analytics.kpiResponseTitle')}
            </span>
            <div className="p-2 rounded-xl bg-cuenca/15 text-cuenca">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white font-heading">
            18.5 min
          </div>
          <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1">
            <span>↓ 12%</span>
            <span className="text-slate-500 dark:text-slate-400 font-normal">{t('analytics.kpiResponseSub')}</span>
          </p>
        </motion.div>

        {/* Metric 2: Control Duration (Pajonal) */}
        <motion.div
          variants={fadeInUp}
          whileHover={{ y: -4, scale: 1.02 }}
          transition={gentleSpring}
          className="p-5 rounded-2xl bg-amber-50/80 dark:bg-surface-elevated border border-pajonal/40 dark:border-white/[0.08] space-y-2 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-pajonal-dark dark:text-pajonal font-mono">
              {t('analytics.kpiControlTitle')}
            </span>
            <div className="p-2 rounded-xl bg-pajonal/20 text-pajonal-dark dark:text-pajonal">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-pajonal-dark dark:text-pajonal font-heading">
            2.4 hrs
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            {t('analytics.kpiControlSub')}
          </p>
        </motion.div>

        {/* Metric 3: Total Affected Area (Terracota) */}
        <motion.div
          variants={fadeInUp}
          whileHover={{ y: -4, scale: 1.02 }}
          transition={gentleSpring}
          className="p-5 rounded-2xl bg-slate-50/80 dark:bg-surface-elevated border border-terracota/40 dark:border-white/[0.08] space-y-2 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-terracota-dark dark:text-terracota font-mono">
              {t('analytics.kpiAreaTitle')}
            </span>
            <div className="p-2 rounded-xl bg-terracota/20 text-terracota">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-rose-600 dark:text-rose-400 font-heading">
            142.8 Ha
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            {t('analytics.kpiAreaSub')}
          </p>
        </motion.div>

        {/* Metric 4: False Alarms Filtered (Emerald) */}
        <motion.div
          variants={fadeInUp}
          whileHover={{ y: -4, scale: 1.02 }}
          transition={gentleSpring}
          className="p-5 rounded-2xl bg-emerald-50/80 dark:bg-surface-elevated border border-emerald-500/30 dark:border-white/[0.08] space-y-2 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400 font-mono">
              {t('analytics.kpiFalseTitle')}
            </span>
            <div className="p-2 rounded-xl bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400 font-heading">
            3.2%
          </div>
          <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-bold">
            {t('analytics.kpiFalseSub')}
          </p>
        </motion.div>
      </motion.div>

      {/* 7-Day Recent History Stream */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-2 font-mono">
            <Calendar className="w-4 h-4 text-cuenca" />
            {t('analytics.historyTitle')}
          </h4>
          <span className="text-xs text-slate-400">{t('analytics.historyClick')}</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {reports.slice(0, 6).map((r) => {
            const rawSev = String(r.severity_level || r.severity || 'Medio').toLowerCase();
            const sev = rawSev.includes('cr') || rawSev.includes('alt') || rawSev.includes('high') ? t('analytics.sevHigh') : rawSev.includes('baj') || rawSev.includes('low') ? t('analytics.sevLow') : t('analytics.sevMed');
            return (
              <motion.div
                key={r.id}
                whileHover={{ y: -3, scale: 1.02 }}
                onClick={() => onSelectReport && onSelectReport(r.id)}
                className="p-4 rounded-2xl bg-slate-50/90 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/[0.08] hover:border-emerald-500/50 hover:shadow-lg transition-all cursor-pointer space-y-2 group"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-xs text-emerald-700 dark:text-emerald-400">
                    {r.tracking_code || '#' + r.id}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    {r.date_reported || t('liveMap.recent')}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <p className="font-bold text-sm text-slate-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
                    {r.incident_type}
                  </p>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-emerald-500 group-hover:translate-x-1 transition-all" />
                </div>

                <div className="flex items-center justify-between text-xs pt-1 border-t border-slate-200/60 dark:border-white/5">
                  <span className="text-slate-500 dark:text-slate-400">
                    {t('severity')}: <strong className="text-rose-600 dark:text-rose-400">{sev}</strong>
                  </span>
                  <span className={`font-bold px-2 py-0.5 rounded-full text-[10px] ${
                    r.status === 'Second_State'
                      ? 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300'
                      : r.status === 'First_State'
                      ? 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300'
                      : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                  }`}>
                    {r.status === 'Second_State' ? t('liveMap.statusActive') : r.status === 'First_State' ? t('liveMap.statusControlled') : t('liveMap.statusClosed')}
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>

    </div>
  );
};

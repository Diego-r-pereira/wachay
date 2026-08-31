import React, { useState } from 'react';
import { CitizenApprovalMatrix } from './CitizenApprovalMatrix';
import { ReportTable } from '../reports/ReportTable';
import { UserManagement } from './UserManagement';
import { BomberosManagement } from './BomberosManagement';
import { BackupControlPanel } from './BackupControlPanel';
import { ReportsExportModal } from '../reports/ReportsExportModal';
import { IncidentReport } from '../../types';
import { Shield, Clock, Flame, Users, Phone, Database, FileText, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { motion, AnimatePresence } from 'motion/react';
import { gentleSpring } from '../../lib/animations';

interface AdminPanelProps {
  reports: IncidentReport[];
  pendingReports: IncidentReport[];
  onRefreshReports: () => void;
}

export const AdminPanel: React.FC<AdminPanelProps> = ({
  reports,
  pendingReports,
  onRefreshReports,
}) => {
  const [activeTab, setActiveTab] = useState<'pendientes' | 'global' | 'usuarios' | 'bomberos' | 'backup'>('pendientes');
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);

  const TABS_CONFIG = [
    {
      id: 'pendientes' as const,
      label: 'Pendientes',
      count: pendingReports.length,
      icon: Clock,
      isAlertCategory: true,
    },
    {
      id: 'global' as const,
      label: 'Lista Global',
      count: reports.length,
      icon: Flame,
      isAlertCategory: false,
    },
    {
      id: 'usuarios' as const,
      label: 'Personal SERNAP',
      icon: Users,
      isAlertCategory: false,
    },
    {
      id: 'bomberos' as const,
      label: 'Brigadas Bomberos',
      icon: Phone,
      isAlertCategory: false,
    },
    {
      id: 'backup' as const,
      label: 'Respaldo DB',
      icon: Database,
      isAlertCategory: false,
    },
  ];

  return (
    <div className="relative min-h-screen bg-[#f8faf7] dark:bg-obsidian text-slate-900 dark:text-[#f8fafc] py-8 sm:py-10 pb-28 overflow-hidden">
      
      {/* Ambient Topographic Glows */}
      <div className="absolute top-20 left-[-10%] w-[550px] h-[550px] rounded-full bg-emerald-500/10 blur-[140px] pointer-events-none -z-0" />
      <div className="absolute top-[800px] right-[-10%] w-[650px] h-[650px] rounded-full bg-cuenca/10 blur-[160px] pointer-events-none -z-0" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8 relative z-10">
        
        {/* Admin Header Command Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6 ring-1 ring-black/5 dark:ring-white/[0.08]"
        >
          <div className="flex items-center gap-4">
            <div className="p-3.5 rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 shadow-inner">
              <Shield className="w-8 h-8" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 font-mono text-[10px] font-extrabold uppercase border border-emerald-200 dark:border-emerald-700/50">
                  SERNAP • Nivel Administrador Central
                </span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-black font-heading text-slate-900 dark:text-white">
                Panel de Control y Administración
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Gestión centralizada de denuncias ciudadanas, personal operativo, cuadrillas de bomberos y base de datos.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} className="w-full sm:w-auto">
              <Button
                onClick={() => setIsExportModalOpen(true)}
                className="w-full sm:w-auto bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-5 py-5 rounded-2xl shadow-md cursor-pointer"
              >
                <FileText className="w-4 h-4" />
                <span>Exportar Reportes (PDF / Excel)</span>
              </Button>
            </motion.div>
          </div>
        </motion.div>

        {/* ========================================================================= */}
        {/* LUXURY SEGMENTED NAVIGATION DOCK (Fully Responsive, Chromatic & Animated) */}
        {/* ========================================================================= */}
        <div className="w-full bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] p-1.5 rounded-2xl sm:rounded-3xl shadow-sm overflow-hidden">
          <div className="flex items-center gap-2 overflow-x-auto no-scrollbar py-1 px-1 sm:grid sm:grid-cols-5 sm:gap-2">
            {TABS_CONFIG.map((tab) => {
              const isActive = activeTab === tab.id;
              const Icon = tab.icon;

              // Chromatic Styling based on Semantics
              let activeClasses = '';
              let inactiveClasses = '';

              if (tab.isAlertCategory) {
                // Amber Solar for Pending Critical Alert
                activeClasses = 'bg-amber-500 text-slate-950 shadow-lg shadow-amber-500/25 ring-2 ring-amber-300 font-black';
                inactiveClasses = 'text-amber-800 dark:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-950/40 border border-amber-300/40 dark:border-amber-700/30';
              } else {
                // Emerald WACHAY for Standard Operational Tabs
                activeClasses = 'bg-emerald-700 dark:bg-emerald-600 text-white shadow-lg shadow-emerald-700/25 ring-2 ring-emerald-400/40 font-extrabold';
                inactiveClasses = 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-surface-elevated border border-transparent';
              }

              return (
                <motion.button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.97 }}
                  transition={gentleSpring}
                  className={`relative shrink-0 sm:shrink flex items-center justify-center gap-2 px-4 py-3 rounded-xl sm:rounded-2xl text-xs transition-all cursor-pointer select-none ${
                    isActive ? activeClasses : inactiveClasses
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-transform ${
                      isActive ? (tab.isAlertCategory ? 'text-slate-950 animate-pulse' : 'text-white scale-110') : 'opacity-80'
                    }`}
                  />
                  <span className="whitespace-nowrap">{tab.label}</span>

                  {/* Dynamic Count Pill */}
                  {tab.count !== undefined && (
                    <span
                      className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded-full transition-colors ${
                        isActive
                          ? tab.isAlertCategory
                            ? 'bg-slate-950/15 text-slate-950'
                            : 'bg-white/20 text-white'
                          : tab.isAlertCategory
                          ? 'bg-amber-100 dark:bg-amber-950/80 text-amber-900 dark:text-amber-300'
                          : 'bg-slate-100 dark:bg-surface-elevated text-slate-600 dark:text-slate-300'
                      }`}
                    >
                      {tab.count}
                    </span>
                  )}
                </motion.button>
              );
            })}
          </div>
        </div>

        {/* Tab Content Panels with Smooth Motion Transitions */}
        <AnimatePresence mode="wait">
          {activeTab === 'pendientes' && (
            <motion.div
              key="tab-pendientes"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.2 }}
            >
              <CitizenApprovalMatrix
                pendingReports={pendingReports}
                onRefresh={onRefreshReports}
              />
            </motion.div>
          )}

          {activeTab === 'global' && (
            <motion.div
              key="tab-global"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.2 }}
            >
              <ReportTable
                reports={reports}
                onRefresh={onRefreshReports}
                onOpenExportModal={() => setIsExportModalOpen(true)}
                isAdmin
              />
            </motion.div>
          )}

          {activeTab === 'usuarios' && (
            <motion.div
              key="tab-usuarios"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.2 }}
            >
              <UserManagement />
            </motion.div>
          )}

          {activeTab === 'bomberos' && (
            <motion.div
              key="tab-bomberos"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.2 }}
            >
              <BomberosManagement />
            </motion.div>
          )}

          {activeTab === 'backup' && (
            <motion.div
              key="tab-backup"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.2 }}
            >
              <BackupControlPanel />
            </motion.div>
          )}
        </AnimatePresence>

        <ReportsExportModal
          isOpen={isExportModalOpen}
          onClose={() => setIsExportModalOpen(false)}
        />

      </div>
    </div>
  );
};

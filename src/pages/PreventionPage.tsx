import React, { useState } from 'react';
import { ShieldAlert, Flame, AlertTriangle, CheckCircle2, FileText, Compass, Download, Wind, Droplets, Thermometer, Shield, PhoneCall, Trees, AlertOctagon, Info, ArrowRight, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { motion } from 'motion/react';
import { useLanguage } from '../context/LanguageContext';
import { fadeInUp, staggerContainer, gentleSpring } from '../lib/animations';

import paisaje3 from '../assets/1. Paisajes Emblemáticos/paisaje_3.jpg';
import bomberos2 from '../assets/2. Guardaparques y Bomberos/bomberos_2.webp';

export const PreventionPage: React.FC = () => {
  const navigate = useNavigate();
  const { t } = useLanguage();
  const [activeTab, setActiveTab] = useState<'rules' | 'chaqueos' | 'interface'>('rules');

  return (
    <div className="relative min-h-screen bg-[#f8faf7] dark:bg-obsidian text-slate-900 dark:text-[#f8fafc] pt-28 sm:pt-36 pb-32 overflow-hidden space-y-28 sm:space-y-36">
      
      {/* Ambient Background Glows */}
      <div className="absolute top-20 left-[-10%] w-[550px] h-[550px] rounded-full bg-rose-500/10 dark:bg-rose-500/10 blur-[140px] pointer-events-none -z-0" />
      <div className="absolute top-[1200px] right-[-10%] w-[650px] h-[650px] rounded-full bg-pajonal/15 dark:bg-pajonal/10 blur-[160px] pointer-events-none -z-0" />
      <div className="absolute top-[2400px] left-[10%] w-[750px] h-[750px] rounded-full bg-cuenca/15 dark:bg-cuenca/10 blur-[170px] pointer-events-none -z-0" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-28 sm:space-y-36 relative z-10">
        
        {/* HERO HEADER */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="text-center max-w-3xl mx-auto space-y-6"
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 text-xs font-extrabold uppercase tracking-wider border border-rose-200 dark:border-rose-800/50 shadow-xs">
            <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400 animate-pulse" />
            <span>{t('prevention.hero.badge')}</span>
          </div>

          <h1 className="font-heading text-4xl sm:text-6xl font-black tracking-tight text-slate-900 dark:text-white leading-tight">
            {t('prevention.hero.title')}
          </h1>

          <p className="text-base sm:text-xl text-slate-600 dark:text-slate-300 leading-relaxed font-medium">
            {t('prevention.hero.subtitle')}
          </p>
        </motion.div>

        {/* SECTION 1: THE CRITICAL 30-30-30 METEOROLOGICAL RULE & SEMAPHORE */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6 }}
          className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-2xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-8 sm:p-14 shadow-xl space-y-10 ring-1 ring-black/5 dark:ring-white/[0.08]"
        >
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 border-b border-slate-100 dark:border-white/[0.08] pb-6">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-pajonal-dark dark:text-pajonal flex items-center gap-2">
                <Thermometer className="w-4 h-4 text-pajonal" />
                {t('prevention.rule30.badge')}
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold font-heading text-slate-900 dark:text-white mt-1">
                {t('prevention.rule30.title')}
              </h2>
            </div>
            <span className="px-4 py-2 rounded-2xl bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800/40 text-xs font-bold">
              {t('prevention.rule30.tag')}
            </span>
          </div>

          {/* 30-30-30 Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-2xl bg-rose-50/80 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/40 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-2xl font-black text-rose-600 dark:text-rose-400">&gt; 30 °C</span>
                <div className="p-2.5 rounded-xl bg-rose-100 dark:bg-rose-900/50 text-rose-600">
                  <Thermometer className="w-5 h-5" />
                </div>
              </div>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('prevention.rule30.tempTitle')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('prevention.rule30.tempDesc')}
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-amber-50/80 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/40 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-2xl font-black text-amber-600 dark:text-amber-400">&lt; 30 %</span>
                <div className="p-2.5 rounded-xl bg-amber-100 dark:bg-amber-900/50 text-amber-600">
                  <Droplets className="w-5 h-5" />
                </div>
              </div>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('prevention.rule30.humTitle')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('prevention.rule30.humDesc')}
              </p>
            </div>

            <div className="p-6 rounded-2xl bg-cuenca/15 dark:bg-cuenca/20 border border-cuenca/30 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-2xl font-black text-cuenca-dark dark:text-cuenca-light">&gt; 30 km/h</span>
                <div className="p-2.5 rounded-xl bg-cuenca/20 text-cuenca-dark dark:text-cuenca-light">
                  <Wind className="w-5 h-5" />
                </div>
              </div>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('prevention.rule30.windTitle')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('prevention.rule30.windDesc')}
              </p>
            </div>
          </div>

          {/* Semaphore Risk Cards */}
          <div className="space-y-4 pt-4">
            <h3 className="font-bold text-lg text-slate-900 dark:text-white">{t('prevention.semaphore.title')}</h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-emerald-50/80 dark:bg-emerald-950/30 border border-emerald-300 dark:border-emerald-800/40 rounded-2xl p-5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-extrabold text-xs text-emerald-800 dark:text-emerald-300 uppercase font-mono">{t('prevention.semaphore.low')}</span>
                  <span className="w-3.5 h-3.5 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"></span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {t('prevention.semaphore.lowDesc')}
                </p>
              </div>

              <div className="bg-amber-50/80 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-800/40 rounded-2xl p-5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-extrabold text-xs text-amber-800 dark:text-amber-300 uppercase font-mono">{t('prevention.semaphore.mod')}</span>
                  <span className="w-3.5 h-3.5 rounded-full bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]"></span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {t('prevention.semaphore.modDesc')}
                </p>
              </div>

              <div className="bg-orange-50/80 dark:bg-orange-950/30 border border-orange-300 dark:border-orange-800/40 rounded-2xl p-5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-extrabold text-xs text-orange-800 dark:text-orange-300 uppercase font-mono">{t('prevention.semaphore.high')}</span>
                  <span className="w-3.5 h-3.5 rounded-full bg-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.5)]"></span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {t('prevention.semaphore.highDesc')}
                </p>
              </div>

              <div className="bg-rose-50/80 dark:bg-rose-950/30 border border-rose-400 dark:border-rose-800/40 rounded-2xl p-5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-extrabold text-xs text-rose-800 dark:text-rose-300 uppercase font-mono">{t('prevention.semaphore.crit')}</span>
                  <span className="w-3.5 h-3.5 rounded-full bg-rose-600 animate-ping"></span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {t('prevention.semaphore.critDesc')}
                </p>
              </div>
            </div>
          </div>

        </motion.div>

        {/* SECTION 2: INTERACTIVE PROTOCOL TABS */}
        <div className="space-y-8">
          <div className="text-center max-w-2xl mx-auto space-y-2">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-cuenca-dark dark:text-cuenca">
              {t('prevention.protocols.badge')}
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white">
              {t('prevention.protocols.title')}
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
              {t('prevention.protocols.subtitle')}
            </p>
          </div>

          {/* Navigation Pills */}
          <div className="flex flex-wrap items-center justify-center gap-3">
            <button
              onClick={() => setActiveTab('rules')}
              className={`px-5 py-2.5 rounded-2xl text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'rules'
                  ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 shadow-md'
                  : 'bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] text-slate-600 dark:text-slate-400 hover:border-cuenca'
              }`}
            >
              {t('prevention.tabs.rules')}
            </button>

            <button
              onClick={() => setActiveTab('chaqueos')}
              className={`px-5 py-2.5 rounded-2xl text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'chaqueos'
                  ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 shadow-md'
                  : 'bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] text-slate-600 dark:text-slate-400 hover:border-pajonal'
              }`}
            >
              {t('prevention.tabs.chaqueos')}
            </button>

            <button
              onClick={() => setActiveTab('interface')}
              className={`px-5 py-2.5 rounded-2xl text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'interface'
                  ? 'bg-slate-900 dark:bg-white text-white dark:text-slate-900 shadow-md'
                  : 'bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] text-slate-600 dark:text-slate-400 hover:border-terracota'
              }`}
            >
              {t('prevention.tabs.interface')}
            </button>
          </div>

          {/* Tab 1: Campers & Mountain Visitors */}
          {activeTab === 'rules' && (
            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="bg-white/95 dark:bg-surface-dark/95 border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-8 sm:p-12 shadow-xl grid grid-cols-1 lg:grid-cols-2 gap-8 items-center"
            >
              <div className="space-y-5">
                <h3 className="text-2xl font-bold font-heading text-slate-900 dark:text-white">
                  {t('prevention.rules.title')}
                </h3>
                <ul className="space-y-3.5 text-xs sm:text-sm text-slate-600 dark:text-slate-300">
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.rules.r1Title')}</strong> {t('prevention.rules.r1Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.rules.r2Title')}</strong> {t('prevention.rules.r2Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.rules.r3Title')}</strong> {t('prevention.rules.r3Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.rules.r4Title')}</strong> {t('prevention.rules.r4Desc')}</span>
                  </li>
                </ul>
              </div>

              <div className="relative rounded-3xl overflow-hidden shadow-xl border border-slate-200/80 dark:border-white/10">
                <img src={paisaje3} alt="Reserva Tunari" className="w-full h-80 object-cover" />
                <div className="absolute inset-0 bg-gradient-to-t from-obsidian/80 via-transparent to-transparent flex items-end p-6 text-white text-xs font-semibold">
                  <span>{t('prevention.rules.photoDesc')}</span>
                </div>
              </div>
            </motion.div>
          )}

          {/* Tab 2: Agricultural Burning (Chaqueos) */}
          {activeTab === 'chaqueos' && (
            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="bg-white/95 dark:bg-surface-dark/95 border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-8 sm:p-12 shadow-xl grid grid-cols-1 lg:grid-cols-2 gap-8 items-center"
            >
              <div className="space-y-5">
                <h3 className="text-2xl font-bold font-heading text-slate-900 dark:text-white">
                  {t('prevention.chaqueos.title')}
                </h3>
                <ul className="space-y-3.5 text-xs sm:text-sm text-slate-600 dark:text-slate-300">
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-pajonal shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.chaqueos.r1Title')}</strong> {t('prevention.chaqueos.r1Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-pajonal shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.chaqueos.r2Title')}</strong> {t('prevention.chaqueos.r2Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-pajonal shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.chaqueos.r3Title')}</strong> {t('prevention.chaqueos.r3Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-pajonal shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.chaqueos.r4Title')}</strong> {t('prevention.chaqueos.r4Desc')}</span>
                  </li>
                </ul>
              </div>

              <div className="p-8 rounded-3xl bg-amber-50/80 dark:bg-surface-elevated border border-pajonal/30 space-y-4">
                <AlertOctagon className="w-10 h-10 text-pajonal-dark dark:text-pajonal" />
                <h4 className="font-bold text-lg text-slate-900 dark:text-white">{t('prevention.chaqueos.lawTitle')}</h4>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  {t('prevention.chaqueos.lawDesc')}
                </p>
                <div className="pt-2">
                  <span className="text-[11px] font-mono font-bold text-emerald-800 dark:text-emerald-400 block uppercase">
                    {t('prevention.chaqueos.lawReport')}
                  </span>
                </div>
              </div>
            </motion.div>
          )}

          {/* Tab 3: Urban Interface (Homes near mountains) */}
          {activeTab === 'interface' && (
            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="bg-white/95 dark:bg-surface-dark/95 border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-8 sm:p-12 shadow-xl grid grid-cols-1 lg:grid-cols-2 gap-8 items-center"
            >
              <div className="space-y-5">
                <h3 className="text-2xl font-bold font-heading text-slate-900 dark:text-white">
                  {t('prevention.interface.title')}
                </h3>
                <ul className="space-y-3.5 text-xs sm:text-sm text-slate-600 dark:text-slate-300">
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-terracota shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.interface.r1Title')}</strong> {t('prevention.interface.r1Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-terracota shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.interface.r2Title')}</strong> {t('prevention.interface.r2Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-terracota shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.interface.r3Title')}</strong> {t('prevention.interface.r3Desc')}</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-terracota shrink-0 mt-0.5" />
                    <span><strong className="text-slate-900 dark:text-white">{t('prevention.interface.r4Title')}</strong> {t('prevention.interface.r4Desc')}</span>
                  </li>
                </ul>
              </div>

              <div className="relative rounded-3xl overflow-hidden shadow-xl border border-slate-200/80 dark:border-white/10">
                <img src={bomberos2} alt="Patrullaje Preventivo" className="w-full h-80 object-cover" />
                <div className="absolute inset-0 bg-gradient-to-t from-obsidian/80 via-transparent to-transparent flex items-end p-6 text-white text-xs font-semibold">
                  <span>{t('prevention.interface.photoDesc')}</span>
                </div>
              </div>
            </motion.div>
          )}

        </div>

        {/* SECTION 3: EMERGENCY ACTION PROTOCOL */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6 }}
          className="bg-gradient-to-br from-cuenca/15 via-white to-pajonal/10 dark:from-surface-dark dark:via-surface-elevated dark:to-obsidian border border-cuenca/30 rounded-3xl p-8 sm:p-14 shadow-xl space-y-8"
        >
          <div className="text-center max-w-2xl mx-auto space-y-2">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-cuenca-dark dark:text-cuenca">
              {t('prevention.action.badge')}
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white">
              {t('prevention.action.title')}
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="p-6 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] space-y-2.5 shadow-xs">
              <span className="w-8 h-8 rounded-full bg-rose-600 text-white font-extrabold text-xs flex items-center justify-center font-mono">01</span>
              <h4 className="font-bold text-slate-900 dark:text-white text-sm">{t('prevention.action.s1Title')}</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">{t('prevention.action.s1Desc')}</p>
            </div>

            <div className="p-6 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] space-y-2.5 shadow-xs">
              <span className="w-8 h-8 rounded-full bg-amber-600 text-white font-extrabold text-xs flex items-center justify-center font-mono">02</span>
              <h4 className="font-bold text-slate-900 dark:text-white text-sm">{t('prevention.action.s2Title')}</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">{t('prevention.action.s2Desc')}</p>
            </div>

            <div className="p-6 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] space-y-2.5 shadow-xs">
              <span className="w-8 h-8 rounded-full bg-cuenca text-white font-extrabold text-xs flex items-center justify-center font-mono">03</span>
              <h4 className="font-bold text-slate-900 dark:text-white text-sm">{t('prevention.action.s3Title')}</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">{t('prevention.action.s3Desc')}</p>
            </div>

            <div className="p-6 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] space-y-2.5 shadow-xs">
              <span className="w-8 h-8 rounded-full bg-emerald-700 text-white font-extrabold text-xs flex items-center justify-center font-mono">04</span>
              <h4 className="font-bold text-slate-900 dark:text-white text-sm">{t('prevention.action.s4Title')}</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">{t('prevention.action.s4Desc')}</p>
            </div>
          </div>
        </motion.div>

        {/* SECTION 4: CALL TO ACTION */}
        <motion.div
          initial={{ opacity: 0, scale: 0.97 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="bg-gradient-to-r from-emerald-950 via-[#14281e] to-obsidian text-white rounded-3xl p-8 sm:p-16 text-center space-y-6 shadow-[0_20px_60px_-15px_rgba(16,185,129,0.3)] relative overflow-hidden border border-emerald-500/40 ring-1 ring-white/10"
        >
          <div className="space-y-3 max-w-2xl mx-auto">
            <span className="px-3.5 py-1.5 rounded-full bg-emerald-500/20 text-emerald-300 text-xs font-extrabold uppercase tracking-wider inline-flex items-center gap-2 border border-emerald-500/40 shadow-xs">
              <Shield className="w-4 h-4 text-emerald-400 animate-pulse" />
              {t('prevention.cta.badge')}
            </span>
            <h2 className="text-3xl sm:text-5xl font-black font-heading tracking-tight text-white">
              {t('prevention.cta.title')}
            </h2>
            <p className="text-xs sm:text-base text-slate-200 max-w-xl mx-auto leading-relaxed">
              {t('prevention.cta.subtitle')}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
            <motion.div whileHover={{ scale: 1.04, y: -2 }} whileTap={{ scale: 0.97 }}>
              <Button
                onClick={() => navigate('/reportar')}
                size="lg"
                className="w-full sm:w-auto bg-rose-600 hover:bg-rose-700 text-white font-extrabold px-8 py-6 rounded-2xl shadow-xl hover:shadow-2xl transition-all gap-3 text-base cursor-pointer"
              >
                <Flame className="w-5 h-5 animate-bounce" />
                <span>{t('prevention.cta.btnReport')}</span>
              </Button>
            </motion.div>

            <motion.div whileHover={{ scale: 1.04, y: -2 }} whileTap={{ scale: 0.97 }}>
              <Button
                onClick={() => navigate('/contacto')}
                size="lg"
                variant="outline"
                className="w-full sm:w-auto border-2 border-emerald-400/80 text-emerald-300 hover:bg-emerald-500/15 font-bold px-8 py-6 rounded-2xl shadow-sm gap-3 text-base cursor-pointer"
              >
                <PhoneCall className="w-5 h-5 text-emerald-400" />
                <span>{t('prevention.cta.btnEmergency')}</span>
              </Button>
            </motion.div>
          </div>
        </motion.div>

      </div>
    </div>
  );
};

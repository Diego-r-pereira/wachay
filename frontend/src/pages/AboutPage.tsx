import React from 'react';
import { Shield, Sparkles, Cpu, BookOpen, Heart, CheckCircle2, Trees, Flame, Compass, ArrowRight, Eye, Layers, Activity, PhoneCall } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { motion } from 'motion/react';
import { useLanguage } from '../context/LanguageContext';
import { fadeInUp, staggerContainer, gentleSpring } from '../lib/animations';

import isoSvgGreen from '../assets/iso_svg_green.svg';
import isoSvgWhite from '../assets/iso_svg_white.svg';
import paisaje1 from '../assets/1. Paisajes Emblemáticos/paisaje_1.jpg';
import bomberos1 from '../assets/2. Guardaparques y Bomberos/bomberos_1.webp';

export const AboutPage: React.FC = () => {
  const navigate = useNavigate();
  const { t } = useLanguage();

  return (
    <div className="relative min-h-screen bg-[#f8faf7] dark:bg-obsidian text-slate-900 dark:text-[#f8fafc] pt-28 sm:pt-36 pb-32 overflow-hidden space-y-28 sm:space-y-36">
      
      {/* Subtle Ambient Glows */}
      <div className="absolute top-20 left-[-10%] w-[550px] h-[550px] rounded-full bg-cuenca/15 dark:bg-cuenca/10 blur-[140px] pointer-events-none -z-0" />
      <div className="absolute top-[1000px] right-[-10%] w-[650px] h-[650px] rounded-full bg-pajonal/15 dark:bg-pajonal/10 blur-[160px] pointer-events-none -z-0" />
      <div className="absolute top-[2000px] left-[10%] w-[750px] h-[750px] rounded-full bg-terracota/15 dark:bg-terracota/10 blur-[170px] pointer-events-none -z-0" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-28 sm:space-y-36 relative z-10">
        
        {/* HERO HEADER SECTION */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="text-center max-w-3xl mx-auto space-y-6"
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cuenca/15 text-cuenca-dark dark:text-cuenca text-xs font-extrabold uppercase tracking-wider border border-cuenca/30 shadow-xs">
            <Sparkles className="w-4 h-4 text-cuenca" />
            <span>{t('about.hero.badge')}</span>
          </div>

          <h1 className="font-heading text-4xl sm:text-6xl font-black tracking-tight text-slate-900 dark:text-white leading-tight">
            {t('about.hero.title')}
          </h1>

          <p className="text-base sm:text-xl text-slate-600 dark:text-slate-300 leading-relaxed font-medium">
            {t('about.hero.subtitle')}
          </p>
        </motion.div>

        {/* SECTION 1: QUECHUA ORIGIN & PHILOSOPHY */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6 }}
          className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-2xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-8 sm:p-14 shadow-xl grid grid-cols-1 lg:grid-cols-12 gap-10 items-center ring-1 ring-black/5 dark:ring-white/[0.08]"
        >
          <div className="lg:col-span-7 space-y-6">
            <div className="space-y-2">
              <span className="text-xs font-mono font-bold uppercase tracking-widest text-terracota-dark dark:text-terracota flex items-center gap-2">
                <Trees className="w-4 h-4 text-terracota" />
                {t('about.origin.badge')}
              </span>
              <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white leading-tight">
                {t('about.origin.title')}
              </h2>
            </div>

            <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 leading-relaxed font-medium">
              {t('about.origin.p1')}
            </p>

            <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              {t('about.origin.p2')}
            </p>

            <div className="p-5 rounded-2xl bg-terracota/10 dark:bg-terracota/15 border border-terracota/30 text-xs sm:text-sm space-y-1.5">
              <span className="font-bold text-terracota-dark dark:text-terracota block uppercase tracking-wider font-mono">
                {t('about.origin.acronymTitle')}
              </span>
              <p className="font-mono font-bold text-slate-900 dark:text-white text-base">
                W.A.C.H.A.Y. = <span className="text-emerald-700 dark:text-emerald-400">{t('about.origin.acronymDesc')}</span>
              </p>
            </div>
          </div>

          <div className="lg:col-span-5 relative rounded-3xl overflow-hidden shadow-2xl border border-slate-200/80 dark:border-white/10 group">
            <img
              src={paisaje1}
              alt="Cordillera del Tunari"
              className="w-full h-80 sm:h-96 object-cover group-hover:scale-105 transition-transform duration-700"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-obsidian/90 via-obsidian/30 to-transparent flex flex-col justify-end p-6 text-white">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-pajonal">{t('about.origin.photoBadge')}</span>
              <p className="text-sm font-semibold mt-1">{t('about.origin.photoDesc')}</p>
            </div>
          </div>
        </motion.div>

        {/* SECTION 2: ANATOMY OF THE BRAND ISOTYPE */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6 }}
          className="bg-obsidian text-white rounded-3xl p-8 sm:p-14 border border-white/10 shadow-2xl space-y-10 relative overflow-hidden"
        >
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <span className="px-3.5 py-1.5 rounded-full bg-pajonal/20 text-pajonal text-xs font-extrabold uppercase tracking-wider inline-flex items-center gap-2 border border-pajonal/30">
              <Sparkles className="w-4 h-4 text-pajonal" />
              {t('about.isotype.badge')}
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-white">
              {t('about.isotype.title')}
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              {t('about.isotype.subtitle')}
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            
            {/* Center Logo Showcase */}
            <div className="lg:col-span-5 flex flex-col items-center justify-center p-8 rounded-3xl bg-white/[0.04] border border-white/10 relative">
              <div className="relative p-6 rounded-3xl bg-emerald-950/40 border border-emerald-500/30 shadow-[0_0_50px_-10px_rgba(16,185,129,0.3)]">
                <img src={isoSvgWhite} alt="WACHAY Official Emblem" className="h-32 sm:h-40 w-auto animate-pulse-slow" />
              </div>
              <span className="font-heading text-2xl font-black mt-6 tracking-tight text-white">WACHAY</span>
              <span className="text-xs font-mono uppercase tracking-widest text-emerald-400 mt-1">{t('about.isotype.subCaption')}</span>
            </div>

            {/* Explanatory Points */}
            <div className="lg:col-span-7 space-y-4">
              <div className="p-5 rounded-2xl bg-white/[0.03] border border-white/[0.08] hover:border-emerald-500/40 transition-all flex items-start gap-4">
                <div className="p-3 rounded-xl bg-emerald-500/15 text-emerald-400 shrink-0">
                  <Trees className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h4 className="font-bold text-white text-base">{t('about.isotype.card1Title')}</h4>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {t('about.isotype.card1Desc')}
                  </p>
                </div>
              </div>

              <div className="p-5 rounded-2xl bg-white/[0.03] border border-white/[0.08] hover:border-amber-400/40 transition-all flex items-start gap-4">
                <div className="p-3 rounded-xl bg-amber-500/15 text-amber-400 shrink-0">
                  <Flame className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h4 className="font-bold text-white text-base">{t('about.isotype.card2Title')}</h4>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {t('about.isotype.card2Desc')}
                  </p>
                </div>
              </div>

              <div className="p-5 rounded-2xl bg-white/[0.03] border border-white/[0.08] hover:border-cuenca/40 transition-all flex items-start gap-4">
                <div className="p-3 rounded-xl bg-cuenca/20 text-cuenca-light shrink-0">
                  <Sparkles className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h4 className="font-bold text-white text-base">{t('about.isotype.card3Title')}</h4>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {t('about.isotype.card3Desc')}
                  </p>
                </div>
              </div>
            </div>

          </div>
        </motion.div>

        {/* SECTION 3: INSTITUTIONAL PILLARS (MISIÓN, VISIÓN, VALORES) */}
        <div className="space-y-10">
          <div className="text-center max-w-2xl mx-auto space-y-2">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-cuenca-dark dark:text-cuenca">
              {t('about.pillars.badge')}
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white">
              {t('about.pillars.title')}
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
              {t('about.pillars.subtitle')}
            </p>
          </div>

          <motion.div
            variants={staggerContainer}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            className="grid grid-cols-1 md:grid-cols-3 gap-6"
          >
            {/* Misión (Cuenca) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-cuenca rounded-3xl p-8 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="w-12 h-12 rounded-2xl bg-cuenca/15 text-cuenca flex items-center justify-center border border-cuenca/20">
                <Compass className="w-6 h-6" />
              </div>
              <h3 className="font-extrabold text-xl text-slate-900 dark:text-white">{t('about.pillars.missionTitle')}</h3>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.pillars.missionDesc')}
              </p>
            </motion.div>

            {/* Visión (Pajonal) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-pajonal rounded-3xl p-8 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="w-12 h-12 rounded-2xl bg-pajonal/20 text-pajonal-dark dark:text-pajonal flex items-center justify-center border border-pajonal/30">
                <Eye className="w-6 h-6" />
              </div>
              <h3 className="font-extrabold text-xl text-slate-900 dark:text-white">{t('about.pillars.visionTitle')}</h3>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.pillars.visionDesc')}
              </p>
            </motion.div>

            {/* Valores (Terracota) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-terracota rounded-3xl p-8 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="w-12 h-12 rounded-2xl bg-terracota/20 text-terracota-dark dark:text-terracota flex items-center justify-center border border-terracota/30">
                <Heart className="w-6 h-6" />
              </div>
              <h3 className="font-extrabold text-xl text-slate-900 dark:text-white">{t('about.pillars.valuesTitle')}</h3>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.pillars.valuesDesc')}
              </p>
            </motion.div>
          </motion.div>
        </div>

        {/* SECTION 4: COLLABORATION WITH PARK RANGERS */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6 }}
          className="bg-gradient-to-br from-emerald-50/80 via-white to-cuenca/10 dark:from-surface-dark dark:via-surface-elevated dark:to-obsidian border border-emerald-500/20 rounded-3xl p-8 sm:p-14 shadow-xl grid grid-cols-1 lg:grid-cols-12 gap-10 items-center ring-1 ring-black/5 dark:ring-white/[0.08]"
        >
          <div className="lg:col-span-5 relative rounded-3xl overflow-hidden shadow-2xl border border-slate-200/80 dark:border-white/10 group">
            <img
              src={bomberos1}
              alt="Guardaparques y Bomberos en Acción"
              className="w-full h-80 sm:h-96 object-cover group-hover:scale-105 transition-transform duration-700"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-obsidian/90 via-obsidian/30 to-transparent flex flex-col justify-end p-6 text-white">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">{t('about.rangers.photoBadge')}</span>
              <p className="text-sm font-semibold mt-1">{t('about.rangers.photoDesc')}</p>
            </div>
          </div>

          <div className="lg:col-span-7 space-y-6">
            <div className="space-y-2">
              <span className="text-xs font-mono font-bold uppercase tracking-widest text-emerald-700 dark:text-emerald-400 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                {t('about.rangers.badge')}
              </span>
              <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white leading-tight">
                {t('about.rangers.title')}
              </h2>
            </div>

            <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 leading-relaxed font-medium">
              {t('about.rangers.subtitle')}
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-semibold pt-2">
              <div className="p-4 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/[0.08] space-y-1 shadow-xs">
                <span className="text-emerald-700 dark:text-emerald-400 font-bold block text-sm">{t('about.rangers.card1Title')}</span>
                <p className="text-slate-500 dark:text-slate-400">{t('about.rangers.card1Desc')}</p>
              </div>
              <div className="p-4 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/[0.08] space-y-1 shadow-xs">
                <span className="text-pajonal-dark dark:text-pajonal font-bold block text-sm">{t('about.rangers.card2Title')}</span>
                <p className="text-slate-500 dark:text-slate-400">{t('about.rangers.card2Desc')}</p>
              </div>
            </div>
          </div>
        </motion.div>

        {/* SECTION 5: CÓMO FUNCIONA / FLUJO DE OPERACIONES */}
        <div className="space-y-10">
          <div className="text-center max-w-2xl mx-auto space-y-2">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-pajonal-dark dark:text-pajonal">
              {t('about.flow.badge')}
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white">
              {t('about.flow.title')}
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
              {t('about.flow.subtitle')}
            </p>
          </div>

          <motion.div
            variants={staggerContainer}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6"
          >
            {/* Step 1: Cuenca */}
            <motion.div variants={fadeInUp} className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-cuenca hover:dark:bg-surface-elevated rounded-3xl p-6 relative space-y-3 shadow-xs hover:shadow-xl transition-all">
              <span className="w-8 h-8 rounded-full bg-cuenca text-white font-extrabold text-xs flex items-center justify-center font-mono shadow-xs">
                01
              </span>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('about.flow.step1Title')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.flow.step1Desc')}
              </p>
            </motion.div>

            {/* Step 2: Pajonal */}
            <motion.div variants={fadeInUp} className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-pajonal hover:dark:bg-surface-elevated rounded-3xl p-6 relative space-y-3 shadow-xs hover:shadow-xl transition-all">
              <span className="w-8 h-8 rounded-full bg-pajonal text-slate-950 font-extrabold text-xs flex items-center justify-center font-mono shadow-xs">
                02
              </span>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('about.flow.step2Title')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.flow.step2Desc')}
              </p>
            </motion.div>

            {/* Step 3: Terracota */}
            <motion.div variants={fadeInUp} className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-terracota hover:dark:bg-surface-elevated rounded-3xl p-6 relative space-y-3 shadow-xs hover:shadow-xl transition-all">
              <span className="w-8 h-8 rounded-full bg-terracota text-white font-extrabold text-xs flex items-center justify-center font-mono shadow-xs">
                03
              </span>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('about.flow.step3Title')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.flow.step3Desc')}
              </p>
            </motion.div>

            {/* Step 4: Emerald */}
            <motion.div variants={fadeInUp} className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-emerald-500 hover:dark:bg-surface-elevated rounded-3xl p-6 relative space-y-3 shadow-xs hover:shadow-xl transition-all">
              <span className="w-8 h-8 rounded-full bg-emerald-700 text-white font-extrabold text-xs flex items-center justify-center font-mono shadow-xs">
                04
              </span>
              <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('about.flow.step4Title')}</h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('about.flow.step4Desc')}
              </p>
            </motion.div>
          </motion.div>
        </div>

        {/* SECTION 6: INSTITUTIONAL ACTION CALLOUT */}
        <motion.div
          initial={{ opacity: 0, scale: 0.97 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="bg-gradient-to-r from-emerald-950 via-[#14281e] to-obsidian text-white rounded-3xl p-8 sm:p-16 text-center space-y-6 shadow-[0_20px_60px_-15px_rgba(207,177,89,0.25)] relative overflow-hidden border border-pajonal/30 ring-1 ring-white/10"
        >
          <div className="space-y-3 max-w-2xl mx-auto">
            <span className="px-3.5 py-1.5 rounded-full bg-pajonal/20 text-pajonal text-xs font-extrabold uppercase tracking-wider inline-flex items-center gap-2 border border-pajonal/40 shadow-xs">
              <Shield className="w-4 h-4 text-pajonal animate-pulse" />
              {t('about.cta.badge')}
            </span>
            <h2 className="text-3xl sm:text-5xl font-black font-heading tracking-tight text-white">
              {t('about.cta.title')}
            </h2>
            <p className="text-xs sm:text-base text-slate-200 max-w-xl mx-auto leading-relaxed">
              {t('about.cta.subtitle')}
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
                <span>{t('about.cta.btnReport')}</span>
              </Button>
            </motion.div>

            <motion.div whileHover={{ scale: 1.04, y: -2 }} whileTap={{ scale: 0.97 }}>
              <Button
                onClick={() => navigate('/contacto')}
                size="lg"
                variant="outline"
                className="w-full sm:w-auto border-2 border-pajonal/80 text-pajonal hover:bg-pajonal/15 font-bold px-8 py-6 rounded-2xl shadow-sm gap-3 text-base cursor-pointer"
              >
                <PhoneCall className="w-5 h-5 text-pajonal" />
                <span>{t('about.cta.btnContact')}</span>
              </Button>
            </motion.div>
          </div>
        </motion.div>

      </div>
    </div>
  );
};

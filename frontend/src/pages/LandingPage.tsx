import React, { useState, useEffect } from 'react';
import { HeroSection } from '../features/landing/HeroSection';
import { useLanguage } from '../context/LanguageContext';
import {
  Flame,
  ShieldAlert,
  Cpu,
  Sparkles,
  Send,
  CheckCircle2,
  ArrowRight,
  PhoneCall,
  Layers,
  Heart,
  Activity,
  Compass,
  Shield,
  ChevronLeft,
  ChevronRight,
  Database,
  BrainCircuit,
  Zap,
  Globe,
  Radio,
  ExternalLink,
  Code2,
  Share2
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { fadeInUp, staggerContainer, gentleSpring } from '../lib/animations';

// ============================================================================
// Brigade Hero Images Imports (7 photos per brigade from src/assets/5. Heros)
// ============================================================================

// 1. FV-FEROS
import feros1 from '../assets/5. Heros/FV-FEROS/1.jpg';
import feros2 from '../assets/5. Heros/FV-FEROS/2.jpg';
import feros3 from '../assets/5. Heros/FV-FEROS/3.jpg';
import feros4 from '../assets/5. Heros/FV-FEROS/4.jpg';
import feros5 from '../assets/5. Heros/FV-FEROS/5.jpg';
import feros6 from '../assets/5. Heros/FV-FEROS/6.jpg';
import feros7 from '../assets/5. Heros/FV-FEROS/7.jpg';

// 2. GEOS
import geos1 from '../assets/5. Heros/GEOS/1.jpg';
import geos2 from '../assets/5. Heros/GEOS/2.jpg';
import geos3 from '../assets/5. Heros/GEOS/3.jpg';
import geos4 from '../assets/5. Heros/GEOS/4.jpg';
import geos5 from '../assets/5. Heros/GEOS/5.jpg';
import geos6 from '../assets/5. Heros/GEOS/6.jpg';
import geos7 from '../assets/5. Heros/GEOS/8.jpeg';

// 3. SAR
import sar1 from '../assets/5. Heros/SAR/1.jpg';
import sar2 from '../assets/5. Heros/SAR/2.jpg';
import sar3 from '../assets/5. Heros/SAR/3.jpg';
import sar4 from '../assets/5. Heros/SAR/4.png';
import sar5 from '../assets/5. Heros/SAR/5.jpg';
import sar6 from '../assets/5. Heros/SAR/6.jpg';
import sar7 from '../assets/5. Heros/SAR/7.jpg';

// 4. SERNAP
import sernap1 from '../assets/5. Heros/SERNAP/1.jpg';
import sernap2 from '../assets/5. Heros/SERNAP/2.jpg';
import sernap3 from '../assets/5. Heros/SERNAP/3.jpg';
import sernap4 from '../assets/5. Heros/SERNAP/4.jpg';
import sernap5 from '../assets/5. Heros/SERNAP/5.jpg';
import sernap6 from '../assets/5. Heros/SERNAP/6.jpg';
import sernap7 from '../assets/5. Heros/SERNAP/7.jpg';

// 5. POLICIA
import policia1 from '../assets/5. Heros/Policia/1.jpg';
import policia2 from '../assets/5. Heros/Policia/2.jpg';
import policia3 from '../assets/5. Heros/Policia/3.jpg';
import policia4 from '../assets/5. Heros/Policia/5.jpg';
import policia5 from '../assets/5. Heros/Policia/6.jpg';
import policia6 from '../assets/5. Heros/Policia/7.jpg';
import policia7 from '../assets/5. Heros/Policia/8.jpg';

interface LandingPageProps {
  onOpenCitizenReport: () => void;
  onOpenTrackModal: () => void;
  stats: {
    total: number;
    active: number;
    controlled: number;
    closed: number;
  };
}

// 5 Official Brigades Data in Exact User Order: FV-FEROS, GEOS, SAR, SERNAP, POLICIA
const BRIGADES = [
  {
    id: 'FV-FEROS',
    selectorName: 'FV-FEROS',
    nameKey: 'heroes.feros.name',
    descKey: 'heroes.feros.desc',
    color: 'orange',
    facebookUrl: 'https://www.facebook.com/FVFEROS.CBBA',
    photos: [
      { src: feros1, captionKey: 'heroes.feros.photo1' },
      { src: feros2, captionKey: 'heroes.feros.photo2' },
      { src: feros3, captionKey: 'heroes.feros.photo3' },
      { src: feros4, captionKey: 'heroes.feros.photo4' },
      { src: feros5, captionKey: 'heroes.feros.photo5' },
      { src: feros6, captionKey: 'heroes.feros.photo6' },
      { src: feros7, captionKey: 'heroes.feros.photo7' },
    ],
  },
  {
    id: 'GEOS',
    selectorName: 'GEOS',
    nameKey: 'heroes.geos.name',
    descKey: 'heroes.geos.desc',
    color: 'amber',
    facebookUrl: 'https://www.facebook.com/BomberosVoluntariosGeos',
    photos: [
      { src: geos1, captionKey: 'heroes.geos.photo1' },
      { src: geos2, captionKey: 'heroes.geos.photo2' },
      { src: geos3, captionKey: 'heroes.geos.photo3' },
      { src: geos4, captionKey: 'heroes.geos.photo4' },
      { src: geos5, captionKey: 'heroes.geos.photo5' },
      { src: geos6, captionKey: 'heroes.geos.photo6' },
      { src: geos7, captionKey: 'heroes.geos.photo7' },
    ],
  },
  {
    id: 'SAR',
    selectorName: 'SAR',
    nameKey: 'heroes.sar.name',
    descKey: 'heroes.sar.desc',
    color: 'rose',
    facebookUrl: 'https://www.facebook.com/sarboliviacbba',
    photos: [
      { src: sar1, captionKey: 'heroes.sar.photo1' },
      { src: sar2, captionKey: 'heroes.sar.photo2' },
      { src: sar3, captionKey: 'heroes.sar.photo3' },
      { src: sar4, captionKey: 'heroes.sar.photo4' },
      { src: sar5, captionKey: 'heroes.sar.photo5' },
      { src: sar6, captionKey: 'heroes.sar.photo6' },
      { src: sar7, captionKey: 'heroes.sar.photo7' },
    ],
  },
  {
    id: 'SERNAP',
    selectorName: 'SERNAP',
    nameKey: 'heroes.sernap.name',
    descKey: 'heroes.sernap.desc',
    color: 'emerald',
    facebookUrl: 'https://www.facebook.com/BoliviaSernap',
    photos: [
      { src: sernap1, captionKey: 'heroes.sernap.photo1' },
      { src: sernap2, captionKey: 'heroes.sernap.photo2' },
      { src: sernap3, captionKey: 'heroes.sernap.photo3' },
      { src: sernap4, captionKey: 'heroes.sernap.photo4' },
      { src: sernap5, captionKey: 'heroes.sernap.photo5' },
      { src: sernap6, captionKey: 'heroes.sernap.photo6' },
      { src: sernap7, captionKey: 'heroes.sernap.photo7' },
    ],
  },
  {
    id: 'POLICIA',
    selectorName: 'POLICIA',
    nameKey: 'heroes.policia.name',
    descKey: 'heroes.policia.desc',
    color: 'teal',
    facebookUrl: 'https://www.facebook.com/Bomberos.Voluntarios.Nataniel.Aguirre.Cochabamba',
    photos: [
      { src: policia1, captionKey: 'heroes.policia.photo1' },
      { src: policia2, captionKey: 'heroes.policia.photo2' },
      { src: policia3, captionKey: 'heroes.policia.photo3' },
      { src: policia4, captionKey: 'heroes.policia.photo4' },
      { src: policia5, captionKey: 'heroes.policia.photo5' },
      { src: policia6, captionKey: 'heroes.policia.photo6' },
      { src: policia7, captionKey: 'heroes.policia.photo7' },
    ],
  },
];

// Tech Stack List for Infinite Marquee
const TECH_STACK = [
  { name: 'FastAPI', role: 'Python Backend REST', icon: '⚡' },
  { name: 'MobileNetV2', role: 'Visión CNN (Edge AI)', icon: '🧠' },
  { name: 'Random Forest', role: 'Estimador Climático ML', icon: '🌲' },
  { name: 'Google Gemini', role: 'Asistente RAG SERNAP', icon: '✨' },
  { name: 'Leaflet GIS', role: 'Mapas & Telemetría', icon: '🗺️' },
  { name: 'Open-Meteo', role: 'Telemetría Satelital', icon: '🌤️' },
  { name: 'React 19', role: 'Frontend Reactivo', icon: '⚛️' },
  { name: 'TypeScript', role: 'Tipado Estricto', icon: '🔷' },
  { name: 'Tailwind CSS', role: 'Estilo Táctico Obsidian', icon: '🎨' },
  { name: 'Vite', role: 'Compilación Rápida', icon: '🚀' },
  { name: 'Esri Satellite', role: 'Imágenes HD Satelitales', icon: '🛰️' },
  { name: 'OpenStreetMap', role: 'Capas Cartográficas', icon: '🌍' },
];

export const LandingPage: React.FC<LandingPageProps> = ({
  onOpenCitizenReport,
  onOpenTrackModal,
  stats,
}) => {
  const navigate = useNavigate();
  const { t } = useLanguage();

  // Brigade Carousel State
  const [selectedBrigadeIndex, setSelectedBrigadeIndex] = useState<number>(0);
  const [currentPhotoIndex, setCurrentPhotoIndex] = useState<number>(0);
  const currentBrigade = BRIGADES[selectedBrigadeIndex];

  // Automatic photo slide transition every 4.5 seconds
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentPhotoIndex((prev) => (prev + 1) % currentBrigade.photos.length);
    }, 4500);
    return () => clearInterval(timer);
  }, [selectedBrigadeIndex, currentBrigade.photos.length]);

  // When changing brigade, reset photo index
  const handleSelectBrigade = (idx: number) => {
    setSelectedBrigadeIndex(idx);
    setCurrentPhotoIndex(0);
  };

  const handleNextPhoto = () => {
    setCurrentPhotoIndex((prev) => (prev + 1) % currentBrigade.photos.length);
  };

  const handlePrevPhoto = () => {
    setCurrentPhotoIndex((prev) => (prev - 1 + currentBrigade.photos.length) % currentBrigade.photos.length);
  };

  return (
    <div className="relative bg-[#f8faf7] dark:bg-obsidian text-slate-900 dark:text-[#f8fafc] overflow-hidden space-y-28 sm:space-y-36 pb-32">
      
      {/* Subtle Creative Ambient Background Glows */}
      <div className="absolute top-[800px] left-[-10%] w-[550px] h-[550px] rounded-full bg-cuenca/15 dark:bg-cuenca/10 blur-[140px] pointer-events-none -z-0" />
      <div className="absolute top-[1800px] right-[-10%] w-[650px] h-[650px] rounded-full bg-pajonal/15 dark:bg-pajonal/10 blur-[160px] pointer-events-none -z-0" />
      <div className="absolute top-[2800px] left-[15%] w-[750px] h-[750px] rounded-full bg-terracota/15 dark:bg-terracota/10 blur-[170px] pointer-events-none -z-0" />

      {/* ========================================================================= */}
      {/* 1. HERO PRINCIPAL                                                         */}
      {/* ========================================================================= */}
      <HeroSection
        onOpenCitizenReport={onOpenCitizenReport}
        onOpenTrackModal={onOpenTrackModal}
      />

      {/* ========================================================================= */}
      {/* 2. CONTADOR DE TELEMETRÍA OPERATIVA                                      */}
      {/* ========================================================================= */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 -mt-16 sm:-mt-24 relative z-30">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-2xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-10 shadow-[0_15px_40px_-10px_rgba(0,0,0,0.07)] dark:shadow-2xl ring-1 ring-black/5 dark:ring-white/[0.08]"
        >
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-8 border-b border-slate-100 dark:border-white/[0.08] pb-5">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-cuenca-dark dark:text-cuenca flex items-center gap-2">
                <Compass className="w-4 h-4 animate-spin-slow text-cuenca" />
                {t('stats.badge')}
              </span>
              <h3 className="text-xl sm:text-2xl font-extrabold font-heading text-slate-900 dark:text-white mt-1">
                {t('stats.title')}
              </h3>
            </div>
            <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cuenca/10 dark:bg-cuenca/20 text-cuenca-dark dark:text-cuenca-light text-xs font-bold border border-cuenca/30 shadow-xs">
              <span className="w-2 h-2 rounded-full bg-cuenca animate-pulse" />
              {t('stats.synced')}
            </span>
          </div>

          <motion.div
            variants={staggerContainer}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6"
          >
            {/* Total Incidentes (Teal Cuenca) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-slate-50/70 dark:bg-surface-elevated border border-cuenca/20 dark:border-white/[0.08] rounded-2xl p-5 shadow-xs hover:shadow-lg hover:border-cuenca/50 transition-all"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold uppercase tracking-wider text-cuenca-dark dark:text-cuenca-light">
                  {t('stats.total')}
                </span>
                <div className="p-2 rounded-xl bg-cuenca/15 text-cuenca">
                  <Activity className="w-5 h-5" />
                </div>
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white font-heading">
                {stats.total}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('stats.totalSub')}</p>
            </motion.div>

            {/* Focos Activos (Rose Flame) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-rose-50/80 dark:bg-rose-950/25 border border-rose-200 dark:border-rose-700/50 rounded-2xl p-5 shadow-xs hover:shadow-lg hover:border-rose-400 transition-all"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">
                  {t('stats.active')}
                </span>
                <div className="p-2 rounded-xl bg-rose-100 dark:bg-rose-900/50 text-rose-600 dark:text-rose-400">
                  <Flame className="w-5 h-5 animate-pulse" />
                </div>
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-rose-600 dark:text-rose-400 font-heading">
                {stats.active}
              </div>
              <p className="text-xs text-rose-500 dark:text-rose-400 mt-1">{t('stats.activeSub')}</p>
            </motion.div>

            {/* En Control (Oro Pajonal) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-amber-50/80 dark:bg-amber-950/25 border border-pajonal/30 dark:border-pajonal/40 rounded-2xl p-5 shadow-xs hover:shadow-lg hover:border-pajonal transition-all"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold uppercase tracking-wider text-pajonal-dark dark:text-pajonal">
                  {t('stats.controlled')}
                </span>
                <div className="p-2 rounded-xl bg-pajonal/20 text-pajonal-dark dark:text-pajonal">
                  <ShieldAlert className="w-5 h-5" />
                </div>
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-pajonal-dark dark:text-pajonal font-heading">
                {stats.controlled}
              </div>
              <p className="text-xs text-amber-600/80 dark:text-pajonal/80 mt-1">{t('stats.controlledSub')}</p>
            </motion.div>

            {/* Focos Extinguidos (Verde Esmeralda) */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-emerald-50/80 dark:bg-emerald-950/25 border border-emerald-200 dark:border-emerald-700/50 rounded-2xl p-5 shadow-xs hover:shadow-lg hover:border-emerald-400 transition-all"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400">
                  {t('stats.closed')}
                </span>
                <div className="p-2 rounded-xl bg-emerald-100 dark:bg-emerald-900/50 text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 className="w-5 h-5" />
                </div>
              </div>
              <div className="text-3xl sm:text-4xl font-extrabold text-emerald-700 dark:text-emerald-400 font-heading">
                {stats.closed}
              </div>
              <p className="text-xs text-emerald-600 dark:text-emerald-400 mt-1">{t('stats.closedSub')}</p>
            </motion.div>
          </motion.div>
        </motion.div>
      </section>

      {/* ========================================================================= */}
      {/* 3. CARRUSEL INFINITO CON LOS LOGOS DEL STACK TECNOLÓGICO                  */}
      {/* ========================================================================= */}
      <section className="w-full relative z-20 overflow-hidden">
        {/* Distinctive High-Contrast Background Bar (Adaptive in Light & Dark Mode) */}
        <div className="bg-gradient-to-r from-[#0c1410] via-[#101b15] to-[#080d0a] text-white py-14 border-y border-emerald-500/20 shadow-2xl relative">
          
          {/* Subtle Ambient Glow inside tech bar */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-emerald-500/10 via-transparent to-transparent pointer-events-none" />

          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-8 text-center space-y-2 relative z-10">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 font-mono text-[11px] font-bold uppercase tracking-wider border border-emerald-500/30">
              <Cpu className="w-3.5 h-3.5" />
              <span>{t('tech.badge')}</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold font-heading text-white tracking-tight">
              {t('tech.title')}
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
              {t('tech.subtitle')}
            </p>
          </div>

          {/* Infinite Marquee Track (Double repeat for seamless loop) */}
          <div className="relative w-full overflow-hidden flex [mask-image:linear-gradient(to_right,transparent,white_15%,white_85%,transparent)]">
            <motion.div
              animate={{ x: ['0%', '-50%'] }}
              transition={{ repeat: Infinity, ease: 'linear', duration: 32 }}
              className="flex items-center gap-5 sm:gap-7 whitespace-nowrap will-change-transform py-2"
            >
              {[...TECH_STACK, ...TECH_STACK].map((tech, idx) => (
                <div
                  key={idx}
                  className="inline-flex items-center gap-3.5 px-5 py-3 rounded-2xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 hover:border-emerald-400/40 backdrop-blur-md transition-all duration-300 shadow-sm shrink-0 group cursor-default"
                >
                  <span className="text-2xl group-hover:scale-115 transition-transform">{tech.icon}</span>
                  <div className="text-left">
                    <span className="font-heading font-extrabold text-sm text-white block group-hover:text-emerald-400 transition-colors">
                      {tech.name}
                    </span>
                    <span className="font-mono text-[10px] text-slate-400 block">
                      {tech.role}
                    </span>
                  </div>
                </div>
              ))}
            </motion.div>
          </div>

        </div>
      </section>

      {/* ========================================================================= */}
      {/* 4. DESTACAR IMPLEMENTACIÓN DE IA Y MODELOS UTILIZADOS                    */}
      {/* ========================================================================= */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
        <div className="text-center max-w-3xl mx-auto space-y-3">
          <span className="px-3.5 py-1.5 rounded-full bg-emerald-500/15 text-emerald-800 dark:text-emerald-400 text-xs font-mono font-extrabold uppercase tracking-wider inline-flex items-center gap-2 border border-emerald-500/30 shadow-xs">
            <BrainCircuit className="w-4 h-4 text-emerald-600 dark:text-emerald-400 animate-pulse" />
            {t('ai.badge')}
          </span>
          <h2 className="text-3xl sm:text-5xl font-black font-heading text-slate-900 dark:text-white tracking-tight leading-tight">
            {t('ai.title')}
          </h2>
          <p className="text-xs sm:text-base text-slate-600 dark:text-slate-300 max-w-2xl mx-auto leading-relaxed">
            {t('ai.subtitle')}
          </p>
        </div>

        {/* 3 AI Model Cards with Interactive Diagnostics & Suggested Visual Artifacts */}
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-60px' }}
          className="grid grid-cols-1 lg:grid-cols-3 gap-8"
        >
          
          {/* MODEL 1: MobileNetV2 CNN Fire Classifier */}
          <motion.div
            variants={fadeInUp}
            whileHover={{ y: -8 }}
            transition={gentleSpring}
            className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] hover:border-emerald-500 rounded-3xl p-7 space-y-5 shadow-lg hover:shadow-2xl transition-all flex flex-col justify-between"
          >
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <Cpu className="w-7 h-7" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-900 dark:text-emerald-300 font-mono text-[10px] font-black border border-emerald-300 dark:border-emerald-800">
                  {t('ai.cnn.tag')}
                </span>
              </div>

              <div>
                <h3 className="text-xl font-bold text-slate-900 dark:text-white font-heading">
                  {t('ai.cnn.title')}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
                  {t('ai.cnn.sub')}
                </p>
              </div>

              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('ai.cnn.desc')}
              </p>

              {/* Technical Performance Badges */}
              <div className="grid grid-cols-2 gap-2 pt-2 text-center font-mono">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/70 dark:border-white/5">
                  <span className="text-lg font-black text-emerald-600 dark:text-emerald-400 block">{t('ai.cnn.kpi1Val')}</span>
                  <span className="text-[10px] text-slate-400 block">{t('ai.cnn.kpi1Lbl')}</span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/70 dark:border-white/5">
                  <span className="text-lg font-black text-emerald-600 dark:text-emerald-400 block">{t('ai.cnn.kpi2Val')}</span>
                  <span className="text-[10px] text-slate-400 block">{t('ai.cnn.kpi2Lbl')}</span>
                </div>
              </div>
            </div>

            {/* Suggested Visual Concept Box */}
            <div className="p-3.5 rounded-2xl bg-emerald-50/70 dark:bg-emerald-950/30 border border-emerald-200/70 dark:border-emerald-800/40 text-[11px] text-slate-600 dark:text-slate-300 space-y-1">
              <span className="font-bold text-emerald-800 dark:text-emerald-300 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-emerald-600" />
                {t('ai.cnn.conceptTitle')}
              </span>
              <p className="text-[10px] text-slate-500 dark:text-slate-400">
                {t('ai.cnn.conceptDesc')}
              </p>
            </div>
          </motion.div>

          {/* MODEL 2: Random Forest Weather & Propagation Index */}
          <motion.div
            variants={fadeInUp}
            whileHover={{ y: -8 }}
            transition={gentleSpring}
            className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] hover:border-amber-500 rounded-3xl p-7 space-y-5 shadow-lg hover:shadow-2xl transition-all flex flex-col justify-between"
          >
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                  <Sparkles className="w-7 h-7" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-900 dark:text-amber-300 font-mono text-[10px] font-black border border-amber-300 dark:border-amber-800">
                  {t('ai.rf.tag')}
                </span>
              </div>

              <div>
                <h3 className="text-xl font-bold text-slate-900 dark:text-white font-heading">
                  {t('ai.rf.title')}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
                  {t('ai.rf.sub')}
                </p>
              </div>

              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('ai.rf.desc')}
              </p>

              {/* Technical Performance Badges */}
              <div className="grid grid-cols-2 gap-2 pt-2 text-center font-mono">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/70 dark:border-white/5">
                  <span className="text-lg font-black text-amber-600 dark:text-amber-400 block">{t('ai.rf.kpi1Val')}</span>
                  <span className="text-[10px] text-slate-400 block">{t('ai.rf.kpi1Lbl')}</span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/70 dark:border-white/5">
                  <span className="text-lg font-black text-amber-600 dark:text-amber-400 block">{t('ai.rf.kpi2Val')}</span>
                  <span className="text-[10px] text-slate-400 block">{t('ai.rf.kpi2Lbl')}</span>
                </div>
              </div>
            </div>

            {/* Suggested Visual Concept Box */}
            <div className="p-3.5 rounded-2xl bg-amber-50/70 dark:bg-amber-950/30 border border-amber-200/70 dark:border-amber-800/40 text-[11px] text-slate-600 dark:text-slate-300 space-y-1">
              <span className="font-bold text-amber-800 dark:text-amber-300 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5 text-amber-500" />
                {t('ai.rf.conceptTitle')}
              </span>
              <p className="text-[10px] text-slate-500 dark:text-slate-400">
                {t('ai.rf.conceptDesc')}
              </p>
            </div>
          </motion.div>

          {/* MODEL 3: Gemini RAG Operations Assistant */}
          <motion.div
            variants={fadeInUp}
            whileHover={{ y: -8 }}
            transition={gentleSpring}
            className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] hover:border-cuenca rounded-3xl p-7 space-y-5 shadow-lg hover:shadow-2xl transition-all flex flex-col justify-between"
          >
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-cuenca/15 text-cuenca-dark dark:text-cuenca border border-cuenca/20">
                  <Layers className="w-7 h-7" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-cuenca/10 dark:bg-cuenca/20 text-cuenca-dark dark:text-cuenca-light font-mono text-[10px] font-black border border-cuenca/30">
                  {t('ai.rag.tag')}
                </span>
              </div>

              <div>
                <h3 className="text-xl font-bold text-slate-900 dark:text-white font-heading">
                  {t('ai.rag.title')}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
                  {t('ai.rag.sub')}
                </p>
              </div>

              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                {t('ai.rag.desc')}
              </p>

              {/* Technical Performance Badges */}
              <div className="grid grid-cols-2 gap-2 pt-2 text-center font-mono">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/70 dark:border-white/5">
                  <span className="text-lg font-black text-cuenca-dark dark:text-cuenca block">{t('ai.rag.kpi1Val')}</span>
                  <span className="text-[10px] text-slate-400 block">{t('ai.rag.kpi1Lbl')}</span>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/70 dark:border-white/5">
                  <span className="text-lg font-black text-cuenca-dark dark:text-cuenca block">{t('ai.rag.kpi2Val')}</span>
                  <span className="text-[10px] text-slate-400 block">{t('ai.rag.kpi2Lbl')}</span>
                </div>
              </div>
            </div>

            {/* Suggested Visual Concept Box */}
            <div className="p-3.5 rounded-2xl bg-cuenca/10 dark:bg-cuenca/15 border border-cuenca/30 text-[11px] text-slate-600 dark:text-slate-300 space-y-1">
              <span className="font-bold text-cuenca-dark dark:text-cuenca flex items-center gap-1.5">
                <BrainCircuit className="w-3.5 h-3.5 text-cuenca" />
                {t('ai.rag.conceptTitle')}
              </span>
              <p className="text-[10px] text-slate-500 dark:text-slate-400">
                {t('ai.rag.conceptDesc')}
              </p>
            </div>
          </motion.div>

        </motion.div>
      </section>

      {/* ========================================================================= */}
      {/* 5. «HÉROES DEL VALLE»: DIRECTORIO DE BRIGADAS Y CARRUSEL DE FOTOS         */}
      {/* ========================================================================= */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-10">
        
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 text-xs font-bold uppercase tracking-wider border border-rose-200 dark:border-rose-800/40 shadow-xs">
            <Heart className="w-4 h-4 text-rose-600 dark:text-rose-400" />
            <span>{t('heroes.badge')}</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold font-heading text-slate-900 dark:text-white">
            {t('heroes.title')}
          </h2>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
            {t('heroes.subtitle')}
          </p>
        </div>

        {/* Brigade Selector Tabs (Exact names in uppercase without photo count legend) */}
        <div className="flex items-center justify-center gap-2.5 sm:gap-3.5 flex-wrap">
          {BRIGADES.map((brigade, bIdx) => {
            const isSelected = selectedBrigadeIndex === bIdx;
            return (
              <button
                key={brigade.id}
                type="button"
                onClick={() => handleSelectBrigade(bIdx)}
                className={`px-5 sm:px-6 py-2.5 rounded-2xl font-black uppercase tracking-wider text-xs sm:text-sm font-mono transition-all cursor-pointer border ${
                  isSelected
                    ? 'bg-emerald-700 text-white border-emerald-700 shadow-lg scale-105 ring-2 ring-emerald-400/40'
                    : 'bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-white/5 hover:border-emerald-500/50'
                }`}
              >
                {brigade.selectorName}
              </button>
            );
          })}
        </div>

        {/* Brigade Feature Card + Interactive Photo Carousel */}
        <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-2xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-10 shadow-2xl grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          
          {/* Left Column: Brigade Info (Clean & Adequate Spacing) */}
          <div className="lg:col-span-5 space-y-5">
            <div>
              <h3 className="text-2xl sm:text-3xl font-extrabold font-heading text-slate-900 dark:text-white">
                {t(currentBrigade.nameKey)}
              </h3>
            </div>

            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed font-medium">
              {t(currentBrigade.descKey)}
            </p>

            {/* Photo Caption Box without redundant header */}
            <div className="p-4 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 text-xs flex items-center justify-between gap-3">
              <p className="font-semibold text-slate-800 dark:text-slate-200 text-xs leading-snug">
                {t(currentBrigade.photos[currentPhotoIndex].captionKey)}
              </p>
              <span className="font-mono font-extrabold text-emerald-600 dark:text-emerald-400 text-xs shrink-0 px-2 py-0.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                {currentPhotoIndex + 1} / {currentBrigade.photos.length}
              </span>
            </div>

            {/* Direct Official Social Media & Emergency Contact Shortcuts */}
            <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <a
                href={currentBrigade.facebookUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-md transition-all cursor-pointer hover:scale-102"
              >
                <Share2 className="w-4 h-4 text-blue-200" />
                <span>{t('heroes.btnFacebook')}</span>
                <ExternalLink className="w-3.5 h-3.5 text-blue-200" />
              </a>

              <Button
                onClick={() => navigate('/contacto')}
                variant="outline"
                className="text-xs font-bold gap-2 rounded-xl border-slate-200 dark:border-white/10 hover:border-emerald-500 cursor-pointer"
              >
                <PhoneCall className="w-3.5 h-3.5 text-emerald-600" />
                <span>{t('heroes.btnEmergency')}</span>
              </Button>
            </div>
          </div>

          {/* Right Column: Premium Photo Carousel with Controls & Auto-advance */}
          <div className="lg:col-span-7 relative rounded-3xl overflow-hidden shadow-2xl border border-slate-200/80 dark:border-white/10 group aspect-[4/3] sm:aspect-[16/10] bg-black">
            
            <AnimatePresence mode="wait">
              <motion.img
                key={`${selectedBrigadeIndex}-${currentPhotoIndex}`}
                src={currentBrigade.photos[currentPhotoIndex].src}
                alt={t(currentBrigade.photos[currentPhotoIndex].captionKey)}
                initial={{ opacity: 0, scale: 1.05 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={{ duration: 0.45 }}
                className="w-full h-full object-cover object-center"
              />
            </AnimatePresence>

            {/* Gradient Scrim for caption readability */}
            <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-black/30 pointer-events-none" />

            {/* Top Badge Overlay */}
            <div className="absolute top-4 left-4 z-10 bg-black/60 backdrop-blur-md px-3 py-1.5 rounded-full border border-white/20 text-white text-[11px] font-mono font-bold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>{currentBrigade.selectorName}</span>
            </div>

            {/* Carousel Control Buttons (Left & Right) */}
            <div className="absolute inset-y-0 left-3 flex items-center z-20">
              <button
                type="button"
                onClick={handlePrevPhoto}
                className="p-3 rounded-2xl bg-black/60 hover:bg-black/90 text-white border border-white/20 backdrop-blur-md transition-all cursor-pointer hover:scale-110 shadow-xl"
                title={t('heroes.prevPhoto')}
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
            </div>

            <div className="absolute inset-y-0 right-3 flex items-center z-20">
              <button
                type="button"
                onClick={handleNextPhoto}
                className="p-3 rounded-2xl bg-black/60 hover:bg-black/90 text-white border border-white/20 backdrop-blur-md transition-all cursor-pointer hover:scale-110 shadow-xl"
                title={t('heroes.nextPhoto')}
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>

            {/* Bottom Dots Indicator Bar (7 Dots) */}
            <div className="absolute bottom-4 left-0 right-0 z-20 flex items-center justify-center gap-2">
              {currentBrigade.photos.map((_, pIdx) => (
                <button
                  key={pIdx}
                  type="button"
                  onClick={() => setCurrentPhotoIndex(pIdx)}
                  className={`h-2 rounded-full transition-all cursor-pointer ${
                    currentPhotoIndex === pIdx
                      ? 'w-7 bg-emerald-400 shadow-md shadow-emerald-400/50'
                      : 'w-2 bg-white/40 hover:bg-white/70'
                  }`}
                  title={`${t('heroes.goToPhoto')} ${pIdx + 1}`}
                />
              ))}
            </div>

          </div>

        </div>

      </section>

      {/* ========================================================================= */}
      {/* 6. BANNER DE LLAMADO A LA ACCIÓN (CTA)                                    */}
      {/* ========================================================================= */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, scale: 0.97 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="bg-gradient-to-r from-emerald-950 via-[#14281e] to-obsidian text-white rounded-3xl p-8 sm:p-16 text-center space-y-6 shadow-[0_20px_60px_-15px_rgba(207,177,89,0.25)] relative overflow-hidden border border-pajonal/30 ring-1 ring-white/10"
        >
          <div className="space-y-3 max-w-2xl mx-auto">
            <span className="px-3.5 py-1.5 rounded-full bg-pajonal/20 text-pajonal text-xs font-extrabold uppercase tracking-wider inline-flex items-center gap-2 border border-pajonal/40 shadow-xs">
              <Flame className="w-4 h-4 text-pajonal animate-bounce" />
              {t('cta.badge')}
            </span>
            <h2 className="text-3xl sm:text-5xl font-black font-heading tracking-tight text-white">
              {t('cta.title')}
            </h2>
            <p className="text-xs sm:text-base text-slate-200 max-w-xl mx-auto leading-relaxed">
              {t('cta.subtitle')}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
            <motion.div whileHover={{ scale: 1.04, y: -2 }} whileTap={{ scale: 0.97 }}>
              <Button
                onClick={onOpenCitizenReport}
                size="lg"
                className="w-full sm:w-auto bg-rose-600 hover:bg-rose-700 text-white font-extrabold px-8 py-6 rounded-2xl shadow-xl hover:shadow-2xl transition-all gap-3 text-base cursor-pointer"
              >
                <Flame className="w-5 h-5 animate-bounce" />
                <span>{t('cta.btnReport')}</span>
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
                <span>{t('cta.btnEmergency')}</span>
              </Button>
            </motion.div>
          </div>
        </motion.div>
      </section>

    </div>
  );
};

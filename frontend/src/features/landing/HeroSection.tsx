import React, { useState, useEffect } from 'react';
import { useLanguage } from '../../context/LanguageContext';
import { Button } from '@/components/ui/button';
import { Flame, Search } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { fadeInUp, gentleSpring } from '../../lib/animations';

// 1. Paisajes Emblemáticos
import paisaje1 from '../../assets/1. Paisajes Emblemáticos/paisaje_1.jpg';
import paisaje2 from '../../assets/1. Paisajes Emblemáticos/paisaje_2.jpg';
import paisaje3 from '../../assets/1. Paisajes Emblemáticos/paisaje_3.jpg';

// 2. Guardaparques y Bomberos
import bomberos1 from '../../assets/2. Guardaparques y Bomberos/bomberos_1.webp';
import bomberos2 from '../../assets/2. Guardaparques y Bomberos/bomberos_2.webp';
import bomberos3 from '../../assets/2. Guardaparques y Bomberos/bomberos_3.jpg';

// 3. El Contraste
import contraste1 from '../../assets/3. El Contraste/contraste_1.jpg';
import contraste2 from '../../assets/3. El Contraste/contraste_2.jpg';
import contraste3 from '../../assets/3. El Contraste/contraste_3.jpg';

// 4. Vista Aérea
import aerea1 from '../../assets/4. Vista Aérea/aerea_1.jpg';
import aerea2 from '../../assets/4. Vista Aérea/aerea_2.jpg';
import aerea3 from '../../assets/4. Vista Aérea/aerea_3.jpg';

interface HeroSectionProps {
  onOpenCitizenReport: () => void;
  onOpenTrackModal: () => void;
}

const HERO_SLIDES = [
  // Paisajes
  { image: paisaje1, legendKey: 'hero.slide1' },
  { image: paisaje2, legendKey: 'hero.slide2' },
  { image: paisaje3, legendKey: 'hero.slide3' },

  // Guardaparques & Bomberos
  { image: bomberos1, legendKey: 'hero.slide4' },
  { image: bomberos2, legendKey: 'hero.slide5' },
  { image: bomberos3, legendKey: 'hero.slide6' },

  // El Contraste
  { image: contraste1, legendKey: 'hero.slide7' },
  { image: contraste2, legendKey: 'hero.slide8' },
  { image: contraste3, legendKey: 'hero.slide9' },

  // Vista Aérea
  { image: aerea1, legendKey: 'hero.slide10' },
  { image: aerea2, legendKey: 'hero.slide11' },
  { image: aerea3, legendKey: 'hero.slide12' },
];

export const HeroSection: React.FC<HeroSectionProps> = ({
  onOpenCitizenReport,
  onOpenTrackModal,
}) => {
  const { t } = useLanguage();
  const [currentSlide, setCurrentSlide] = useState(0);

  // Auto-advance slides every 6 seconds
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentSlide((prev) => (prev + 1) % HERO_SLIDES.length);
    }, 6000);
    return () => clearInterval(timer);
  }, []);

  return (
    <section className="relative min-h-screen w-full flex flex-col justify-between items-center overflow-hidden text-white select-none pt-24 sm:pt-28 pb-10">
      
      {/* Background Slideshow: Crisp, clear images without whole-screen dark scrim distortion */}
      <div className="absolute inset-0 z-0">
        {HERO_SLIDES.map((slide, index) => (
          <motion.div
            key={index}
            initial={false}
            animate={{
              opacity: index === currentSlide ? 1 : 0,
              scale: index === currentSlide ? 1.05 : 1,
            }}
            transition={{
              opacity: { duration: 1.2, ease: 'easeInOut' },
              scale: { duration: 8, ease: 'easeOut' },
            }}
            className="absolute inset-0 pointer-events-none"
          >
            <img
              src={slide.image}
              alt={t(slide.legendKey)}
              className="w-full h-full object-cover object-center"
            />
          </motion.div>
        ))}
      </div>

      {/* Seamless bottom gradient melting Hero images into page background */}
      <div className="absolute bottom-0 left-0 right-0 h-44 sm:h-64 bg-gradient-to-t from-[#f8faf7] dark:from-[#0b100d] via-[#f8faf7]/85 dark:via-[#0b100d]/85 to-transparent pointer-events-none z-10" />

      {/* Main Central Content (Centered Vertically) */}
      <div className="relative z-20 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center my-auto flex flex-col items-center space-y-6">
        
        {/* Glassmorphic Container 1: Title H1: WACHAY */}
        <motion.div
          initial={{ opacity: 0, y: -25, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="bg-black/60 dark:bg-black/70 backdrop-blur-xl rounded-3xl px-8 sm:px-14 py-4 sm:py-6 border border-white/25 shadow-2xl"
        >
          <h1 className="font-heading text-6xl sm:text-8xl lg:text-9xl font-black tracking-tight text-white drop-shadow-[0_10px_25px_rgba(0,0,0,0.8)] leading-none">
            {t('hero.title') || 'WACHAY'}
          </h1>
        </motion.div>

        {/* Glassmorphic Container 2: Narrative Subtitle & Meaning */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
          className="bg-black/60 dark:bg-black/70 backdrop-blur-xl rounded-3xl px-6 sm:px-10 py-4 sm:py-5 border border-white/25 shadow-2xl space-y-1.5 max-w-2xl"
        >
          <p className="font-mono text-sm sm:text-base lg:text-lg font-extrabold uppercase tracking-wider text-emerald-400 drop-shadow-md">
            {t('hero.subTitle') || 'Wildfire Alert & Cochabamba Heat Analysis System'}
          </p>
          <p className="text-xs sm:text-sm text-slate-200 italic font-semibold">
            {t('hero.meaningQuechua')} <span className="underline decoration-emerald-400 underline-offset-4 font-bold text-white">{t('hero.meaningDefinition')}</span>
          </p>
        </motion.div>

        {/* Primary Action Buttons (Outside of the glassmorphic scrim boxes) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2 w-full sm:w-auto"
        >
          <motion.div
            whileHover={{ scale: 1.04, y: -2 }}
            whileTap={{ scale: 0.97 }}
            transition={gentleSpring}
          >
            <Button
              onClick={onOpenCitizenReport}
              size="lg"
              className="w-full sm:w-auto bg-rose-600 hover:bg-rose-700 text-white font-extrabold px-8 py-6 rounded-2xl shadow-xl hover:shadow-rose-600/50 transition-all gap-3 text-sm sm:text-base cursor-pointer"
            >
              <Flame className="w-5 h-5 animate-bounce" />
              <span>{t('hero.btnReport') || 'Reportar Incendio (Ciudadano)'}</span>
            </Button>
          </motion.div>

          <motion.div
            whileHover={{ scale: 1.04, y: -2 }}
            whileTap={{ scale: 0.97 }}
            transition={gentleSpring}
          >
            <Button
              onClick={onOpenTrackModal}
              size="lg"
              variant="outline"
              className="w-full sm:w-auto border-2 border-white/80 bg-black/50 hover:bg-white/20 text-white font-extrabold px-8 py-6 rounded-2xl shadow-xl backdrop-blur-xl transition-all gap-3 text-sm sm:text-base cursor-pointer"
            >
              <Search className="w-5 h-5 text-emerald-300" />
              <span>{t('hero.btnTrack') || 'Rastrear Reporte'}</span>
            </Button>
          </motion.div>
        </motion.div>

      </div>

      {/* Bottom Single Legend / Caption (Animated on transition) */}
      <div className="relative z-20 w-full max-w-xl mx-auto px-4 pb-2 text-center">
        <AnimatePresence mode="wait">
          <motion.div
            key={currentSlide}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.4 }}
            className="inline-flex items-center gap-2.5 px-5 py-2 rounded-full bg-black/60 border border-white/20 backdrop-blur-xl text-white shadow-xl"
          >
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs sm:text-sm font-bold tracking-wide text-white drop-shadow">
              {t(HERO_SLIDES[currentSlide].legendKey)}
            </span>
          </motion.div>
        </AnimatePresence>
      </div>

    </section>
  );
};

import React, { useState } from 'react';
import { Phone, MapPin, Mail, Send, Shield, Clock, CheckCircle2, PhoneCall, MessageCircle, AlertTriangle, ExternalLink, HelpCircle, Building2, Radio, Compass, Sparkles, Flame } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { motion } from 'motion/react';
import { useLanguage } from '../context/LanguageContext';
import { fadeInUp, staggerContainer, gentleSpring } from '../lib/animations';

export const ContactPage: React.FC = () => {
  const { t } = useLanguage();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [subject, setSubject] = useState('denuncia');
  const [message, setMessage] = useState('');
  const [sentSuccess, setSentSuccess] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSentSuccess(true);
    setName('');
    setEmail('');
    setMessage('');
  };

  return (
    <div className="relative min-h-screen bg-[#f8faf7] dark:bg-obsidian text-slate-900 dark:text-[#f8fafc] pt-28 sm:pt-36 pb-32 overflow-hidden space-y-28 sm:space-y-36">
      
      {/* Ambient Background Glows */}
      <div className="absolute top-20 left-[-10%] w-[550px] h-[550px] rounded-full bg-cuenca/15 dark:bg-cuenca/10 blur-[140px] pointer-events-none -z-0" />
      <div className="absolute top-[1200px] right-[-10%] w-[650px] h-[650px] rounded-full bg-pajonal/15 dark:bg-pajonal/10 blur-[160px] pointer-events-none -z-0" />
      <div className="absolute top-[2200px] left-[10%] w-[750px] h-[750px] rounded-full bg-terracota/15 dark:bg-terracota/10 blur-[170px] pointer-events-none -z-0" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-28 sm:space-y-36 relative z-10">
        
        {/* HERO HEADER */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="text-center max-w-3xl mx-auto space-y-6"
        >
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cuenca/15 text-cuenca-dark dark:text-cuenca text-xs font-extrabold uppercase tracking-wider border border-cuenca/30 shadow-xs">
            <Radio className="w-4 h-4 text-cuenca animate-pulse" />
            <span>{t('contact.hero.badge')}</span>
          </div>

          <h1 className="font-heading text-4xl sm:text-6xl font-black tracking-tight text-slate-900 dark:text-white leading-tight">
            {t('contact.hero.title')}
          </h1>

          <p className="text-base sm:text-xl text-slate-600 dark:text-slate-300 leading-relaxed font-medium">
            {t('contact.hero.subtitle')}
          </p>
        </motion.div>

        {/* SECTION 1: 24/7 EMERGENCY DIRECTORY (CLICK TO CALL) */}
        <div className="space-y-8">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-200/80 dark:border-white/[0.08] pb-4">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400 flex items-center gap-2">
                <PhoneCall className="w-4 h-4 animate-bounce" />
                {t('contact.directory.badge')}
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold font-heading text-slate-900 dark:text-white mt-1">
                {t('contact.directory.title')}
              </h2>
            </div>
            <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 text-xs font-bold border border-emerald-200 dark:border-emerald-700/50">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              {t('contact.directory.activeBadge')}
            </span>
          </div>

          <motion.div
            variants={staggerContainer}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
          >
            {/* SERNAP Tunari */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-rose-200/90 dark:border-rose-900/40 rounded-3xl p-6 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-rose-50 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400">
                  <Shield className="w-6 h-6" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-rose-100 dark:bg-rose-900/50 text-rose-700 dark:text-rose-300 text-[10px] font-extrabold uppercase">
                  {t('contact.sernap.tag')}
                </span>
              </div>
              <div>
                <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('contact.sernap.name')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('contact.sernap.desc')}</p>
              </div>
              <a
                href="tel:119"
                className="flex items-center justify-between p-3 rounded-xl bg-rose-600 hover:bg-rose-700 text-white font-mono font-bold text-base transition-colors cursor-pointer"
              >
                <span>{t('contact.directory.dial')} 119</span>
                <PhoneCall className="w-4 h-4" />
              </a>
            </motion.div>

            {/* SAR-Bolivia */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-cuenca rounded-3xl p-6 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-cuenca/15 text-cuenca">
                  <Radio className="w-6 h-6" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-cuenca/20 text-cuenca-dark dark:text-cuenca-light text-[10px] font-extrabold uppercase">
                  {t('contact.sar.tag')}
                </span>
              </div>
              <div>
                <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('contact.sar.name')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('contact.sar.desc')}</p>
              </div>
              <a
                href="tel:132"
                className="flex items-center justify-between p-3 rounded-xl bg-cuenca-dark hover:bg-cuenca text-white font-mono font-bold text-base transition-colors cursor-pointer"
              >
                <span>{t('contact.directory.dial')} 132</span>
                <PhoneCall className="w-4 h-4" />
              </a>
            </motion.div>

            {/* Bomberos Policía */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-pajonal rounded-3xl p-6 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-pajonal/20 text-pajonal-dark dark:text-pajonal">
                  <Flame className="w-6 h-6" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-pajonal/20 text-pajonal-dark dark:text-pajonal text-[10px] font-extrabold uppercase">
                  {t('contact.police.tag')}
                </span>
              </div>
              <div>
                <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('contact.police.name')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('contact.police.desc')}</p>
              </div>
              <a
                href="tel:119"
                className="flex items-center justify-between p-3 rounded-xl bg-pajonal-dark hover:bg-pajonal text-white font-mono font-bold text-base transition-colors cursor-pointer"
              >
                <span>{t('contact.directory.dial')} 119</span>
                <PhoneCall className="w-4 h-4" />
              </a>
            </motion.div>

            {/* UGR Gobernación */}
            <motion.div
              variants={fadeInUp}
              whileHover={{ y: -6, scale: 1.02 }}
              transition={gentleSpring}
              className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] hover:border-terracota rounded-3xl p-6 space-y-4 shadow-xs hover:shadow-xl transition-all"
            >
              <div className="flex items-center justify-between">
                <div className="p-3 rounded-2xl bg-terracota/20 text-terracota-dark dark:text-terracota">
                  <Building2 className="w-6 h-6" />
                </div>
                <span className="px-2.5 py-1 rounded-full bg-terracota/20 text-terracota-dark dark:text-terracota text-[10px] font-extrabold uppercase">
                  {t('contact.ugr.tag')}
                </span>
              </div>
              <div>
                <h3 className="font-bold text-base text-slate-900 dark:text-white">{t('contact.ugr.name')}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('contact.ugr.desc')}</p>
              </div>
              <a
                href="tel:44500000"
                className="flex items-center justify-between p-3 rounded-xl bg-terracota-dark hover:bg-terracota text-white font-mono font-bold text-base transition-colors cursor-pointer"
              >
                <span>(4) 450-0000</span>
                <PhoneCall className="w-4 h-4" />
              </a>
            </motion.div>
          </motion.div>
        </div>

        {/* SECTION 2: CONTACT FORM & HEADQUARTERS LOCATION */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
          
          {/* Glassmorphic Contact Form */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.6 }}
            className="lg:col-span-7 bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-8 sm:p-12 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]"
          >
            <div className="space-y-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400 flex items-center gap-2">
                <Mail className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                {t('contact.form.badge')}
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold font-heading text-slate-900 dark:text-white">
                {t('contact.form.title')}
              </h2>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                {t('contact.form.subtitle')}
              </p>
            </div>

            {sentSuccess ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="p-6 rounded-2xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-700/50 text-emerald-900 dark:text-emerald-200 space-y-2"
              >
                <div className="flex items-center gap-2 font-bold text-sm">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                  <span>{t('contact.form.successTitle')}</span>
                </div>
                <p className="text-xs text-emerald-800 dark:text-emerald-300 leading-relaxed">
                  {t('contact.form.successDesc')}
                </p>
              </motion.div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">{t('contact.form.lblName')}</Label>
                    <Input
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      required
                      placeholder={t('contact.form.phName')}
                      className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-11 text-xs focus:ring-2 focus:ring-emerald-500"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">{t('contact.form.lblEmail')}</Label>
                    <Input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      placeholder={t('contact.form.phEmail')}
                      className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-11 text-xs focus:ring-2 focus:ring-emerald-500"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">{t('contact.form.lblSubject')}</Label>
                  <select
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    className="w-full h-11 px-3 rounded-xl bg-slate-50 dark:bg-surface-elevated border border-slate-200 dark:border-white/10 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-emerald-500 cursor-pointer"
                  >
                    <option value="denuncia">{t('contact.form.optDenuncia')}</option>
                    <option value="voluntariado">{t('contact.form.optVoluntariado')}</option>
                    <option value="tecnica">{t('contact.form.optTecnica')}</option>
                    <option value="prensa">{t('contact.form.optPrensa')}</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">{t('contact.form.lblMessage')}</Label>
                  <textarea
                    rows={4}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    required
                    placeholder={t('contact.form.phMessage')}
                    className="w-full p-3.5 rounded-xl text-xs bg-slate-50 dark:bg-surface-elevated border border-slate-200 dark:border-white/10 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  />
                </div>

                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Button
                    type="submit"
                    className="w-full bg-emerald-800 hover:bg-emerald-900 dark:bg-emerald-600 dark:hover:bg-emerald-500 text-white font-bold py-3.5 rounded-xl shadow-md gap-2 text-xs cursor-pointer"
                  >
                    <Send className="w-4 h-4" />
                    <span>{t('contact.form.btnSubmit')}</span>
                  </Button>
                </motion.div>
              </form>
            )}
          </motion.div>

          {/* Headquarters & Ranger Posts */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-obsidian text-white rounded-3xl p-8 border border-white/10 shadow-2xl space-y-6">
              <div className="flex items-center gap-3 border-b border-white/10 pb-4">
                <div className="p-3 rounded-2xl bg-emerald-500/15 text-emerald-400">
                  <Building2 className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="font-heading text-lg font-bold">{t('contact.hq.title')}</h3>
                  <p className="text-xs text-slate-400">{t('contact.hq.subtitle')}</p>
                </div>
              </div>

              <div className="space-y-4 text-xs text-slate-300">
                <div className="flex items-start gap-3">
                  <MapPin className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-white block">{t('contact.hq.addressLbl')}</strong>
                    <span>{t('contact.hq.addressVal')}</span>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Clock className="w-5 h-5 text-pajonal shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-white block">{t('contact.hq.hoursLbl')}</strong>
                    <span>{t('contact.hq.hoursDesk')}</span>
                    <span className="text-emerald-400 block font-semibold">{t('contact.hq.hoursGuard')}</span>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Mail className="w-5 h-5 text-cuenca shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-white block">{t('contact.hq.emailLbl')}</strong>
                    <span className="font-mono">sernap.tunari@cochabamba.gob.bo</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Puestos de Control Card */}
            <div className="bg-white dark:bg-surface-dark border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 space-y-3 shadow-xs">
              <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                <Compass className="w-4 h-4 text-cuenca" />
                {t('contact.checkpoints.title')}
              </h4>
              <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
                <li className="flex justify-between border-b border-slate-100 dark:border-white/5 pb-1.5">
                  <span>{t('contact.checkpoints.p1')}</span>
                  <strong className="font-mono text-emerald-700 dark:text-emerald-400">{t('contact.checkpoints.vhf14')}</strong>
                </li>
                <li className="flex justify-between border-b border-slate-100 dark:border-white/5 pb-1.5">
                  <span>{t('contact.checkpoints.p2')}</span>
                  <strong className="font-mono text-emerald-700 dark:text-emerald-400">{t('contact.checkpoints.vhf16')}</strong>
                </li>
                <li className="flex justify-between">
                  <span>{t('contact.checkpoints.p3')}</span>
                  <strong className="font-mono text-emerald-700 dark:text-emerald-400">{t('contact.checkpoints.vhf22')}</strong>
                </li>
              </ul>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};

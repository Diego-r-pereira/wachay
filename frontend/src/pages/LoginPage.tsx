import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ShieldAlert, LogIn, ArrowLeft, ShieldCheck, Lock, Eye, EyeOff, Sparkles, KeyRound, Radio, ChevronDown, Check } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { gentleSpring } from '../lib/animations';
import api from '../services/api';

import isoSvgGreen from '../assets/iso_svg_green.svg';
import isoSvgWhite from '../assets/iso_svg_white.svg';

const LANGUAGES = [
  { code: 'es', label: 'ES' },
  { code: 'en', label: 'EN' },
  { code: 'qu', label: 'QU' },
] as const;

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const { t, lang, setLang } = useLanguage();
  const navigate = useNavigate();

  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Language Dropdown in Login Top Bar
  const [isLangOpen, setIsLangOpen] = useState(false);
  const langRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (langRef.current && !langRef.current.contains(e.target as Node)) {
        setIsLangOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const currentLangObj = LANGUAGES.find((l) => l.code === lang) || LANGUAGES[0];

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setIsSubmitting(true);

    try {
      const formData = new URLSearchParams();
      formData.append('username', usernameInput);
      formData.append('password', passwordInput);

      const res = await api.post('/auth/login', formData, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      if (res.data && res.data.access_token) {
        const userObj = {
          id: 1,
          username: res.data.username || usernameInput,
          first_name: res.data.name || usernameInput,
          role: res.data.role,
        };

        login(res.data.access_token, userObj);

        if (res.data.role === 'admin') {
          navigate('/admin');
        } else {
          navigate('/guardaparques');
        }
      }
    } catch (err: any) {
      console.error('Login error:', err);
      setLoginError(
        err.response?.data?.detail || t('login.errorInvalid')
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b08] text-slate-100 flex items-center justify-center p-4 sm:p-6 lg:p-8 relative overflow-hidden select-none">
      
      {/* Ambient Topographic Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[600px] h-[600px] rounded-full bg-emerald-600/10 blur-[150px] pointer-events-none -z-0" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[600px] h-[600px] rounded-full bg-cuenca/10 blur-[160px] pointer-events-none -z-0" />

      {/* Main Glassmorphic Split Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        className="w-full max-w-5xl bg-[#0b100d]/90 backdrop-blur-2xl border border-white/10 rounded-3xl shadow-[0_25px_60px_-15px_rgba(0,0,0,0.8)] overflow-hidden grid grid-cols-1 lg:grid-cols-12 relative z-10 ring-1 ring-white/[0.08]"
      >
        
        {/* LEFT PANEL: Brand Identity, Logo & Storytelling (5 cols) */}
        <div className="lg:col-span-5 bg-gradient-to-b from-surface-dark via-surface-elevated to-obsidian text-white p-8 sm:p-12 flex flex-col justify-between items-center text-center relative overflow-hidden border-b lg:border-b-0 lg:border-r border-white/10">
          
          {/* Top Bar: Back Link & Language Picker */}
          <div className="w-full flex items-center justify-between gap-3">
            <button
              onClick={() => navigate('/')}
              className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-white transition-colors bg-white/[0.04] hover:bg-white/10 px-3.5 py-1.5 rounded-full border border-white/10 cursor-pointer group"
            >
              <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
              <span>{t('login.backToHome')}</span>
            </button>

            {/* Language Switcher */}
            <div className="relative" ref={langRef}>
              <button
                type="button"
                onClick={() => setIsLangOpen(!isLangOpen)}
                className="h-8 px-3 flex items-center gap-1.5 text-xs font-extrabold uppercase rounded-full transition-all cursor-pointer bg-white/[0.05] hover:bg-white/10 text-slate-300 border border-white/10"
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
                    className="absolute right-0 mt-2 w-28 bg-[#111914] border border-white/15 rounded-xl shadow-2xl py-1 z-50 overflow-hidden"
                  >
                    {LANGUAGES.map((l) => (
                      <button
                        key={l.code}
                        type="button"
                        onClick={() => {
                          setLang(l.code as 'es' | 'en' | 'qu');
                          setIsLangOpen(false);
                        }}
                        className="w-full px-3 py-1.5 text-left text-xs font-bold flex items-center justify-between hover:bg-emerald-500/20 text-slate-200 transition-colors cursor-pointer"
                      >
                        <span>{l.label}</span>
                        {lang === l.code && <Check className="w-3.5 h-3.5 text-emerald-400" />}
                      </button>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          {/* Center Brand Identity */}
          <div className="my-8 sm:my-10 flex flex-col items-center space-y-5">
            
            {/* Logo Emblem Container */}
            <motion.div
              whileHover={{ scale: 1.05 }}
              transition={gentleSpring}
              className="p-5 sm:p-6 rounded-3xl bg-emerald-950/40 border border-emerald-500/30 shadow-[0_0_40px_-10px_rgba(16,185,129,0.3)]"
            >
              <img
                src={isoSvgWhite}
                alt="WACHAY Official Emblem"
                className="h-20 sm:h-24 w-auto"
              />
            </motion.div>

            {/* WACHAY Brand Title */}
            <div className="space-y-1.5">
              <h1 className="font-heading text-4xl sm:text-5xl font-black text-white tracking-tight flex items-center justify-center gap-2">
                WACHAY
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
              </h1>
              
              {/* Meaning & Acronym */}
              <p className="text-xs sm:text-sm font-mono text-emerald-400 font-bold uppercase tracking-wider">
                {t('appSubName')}
              </p>
              <p className="text-xs text-slate-300 italic">
                {t('login.meaningQuechua')}
              </p>
            </div>

            {/* Protected Access Badges */}
            <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
              <span className="px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-[11px] text-slate-300 font-mono">
                {t('login.rangerBadge')}
              </span>
              <span className="px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-[11px] text-slate-300 font-mono">
                {t('login.adminBadge')}
              </span>
            </div>

          </div>

          {/* Bottom Security Assurance */}
          <div className="text-[11px] text-slate-400 border-t border-white/[0.08] pt-4 w-full flex items-center justify-center gap-2 font-mono">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>{t('login.secureAccess')}</span>
          </div>

        </div>

        {/* RIGHT PANEL: Sleek Login Form (7 cols) */}
        <div className="lg:col-span-7 p-8 sm:p-14 flex flex-col justify-center bg-[#0d1410] text-white">
          
          <div className="space-y-7 max-w-md mx-auto w-full">
            
            <div className="space-y-1.5">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-bold font-mono uppercase tracking-wider">
                <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
                <span>{t('login.portalBadge')}</span>
              </div>
              <h2 className="text-2xl sm:text-3xl font-extrabold font-heading text-white">
                {t('login.title')}
              </h2>
              <p className="text-xs text-slate-400">
                {t('login.subtitle')}
              </p>
            </div>

            <form onSubmit={handleLoginSubmit} className="space-y-5">
              
              {loginError && (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-4 rounded-2xl bg-rose-950/40 text-rose-300 border border-rose-800/50 text-xs font-medium flex items-center gap-3"
                >
                  <ShieldAlert className="w-5 h-5 shrink-0 text-rose-400" />
                  <span>{loginError}</span>
                </motion.div>
              )}

              <div className="space-y-2">
                <Label htmlFor="username" className="text-xs font-bold text-slate-300">
                  {t('login.usernameLabel')}
                </Label>
                <Input
                  id="username"
                  type="text"
                  required
                  placeholder={t('login.usernamePlaceholder')}
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  className="h-12 bg-surface-elevated/80 border-white/10 rounded-2xl text-xs text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 transition-all"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="text-xs font-bold text-slate-300">
                  {t('login.passwordLabel')}
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    required
                    placeholder="••••••••••••"
                    value={passwordInput}
                    onChange={(e) => setPasswordInput(e.target.value)}
                    className="h-12 pr-12 bg-surface-elevated/80 border-white/10 rounded-2xl text-xs text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 transition-all"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white transition-colors cursor-pointer p-1"
                    title={showPassword ? t('login.hidePassword') : t('login.showPassword')}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full h-12 bg-emerald-700 hover:bg-emerald-600 text-white font-extrabold text-xs rounded-2xl shadow-lg hover:shadow-emerald-600/30 transition-all gap-2 cursor-pointer mt-2"
                >
                  <Lock className="w-4 h-4" />
                  <span>{isSubmitting ? t('login.verifying') : t('login.submitBtn')}</span>
                </Button>
              </motion.div>
            </form>

            <div className="pt-2 text-center">
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {t('login.troubleText')}
              </p>
            </div>

          </div>

        </div>

      </motion.div>

    </div>
  );
};

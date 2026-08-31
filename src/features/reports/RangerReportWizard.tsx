import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { GpsPickerMap } from '../map/GpsPickerMap';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Flame, MapPin, CloudSun, ShieldAlert, CheckCircle2, ArrowRight, ArrowLeft, Radio, Compass, Send, Trees, Sparkles, Navigation } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import api from '../../services/api';
import { IncidentReport } from '../../types';

interface RangerReportWizardProps {
  onSuccess: () => void;
  existingReports: IncidentReport[];
}

export const RangerReportWizard: React.FC<RangerReportWizardProps> = ({
  onSuccess,
  existingReports,
}) => {
  const { currentUser } = useAuth();

  const [step, setStep] = useState<number>(1);
  const [rangerName, setRangerName] = useState(
    currentUser?.first_name ? `${currentUser.first_name} ${currentUser.last_name || ''}`.trim() : currentUser?.username || 'Guardaparques SERNAP'
  );

  // Form Parameters
  const [initialStatus, setInitialStatus] = useState<'Second_State' | 'First_State'>('Second_State');
  const [incType, setIncType] = useState('Incendio Forestal');
  const [severity, setSeverity] = useState('Alto');
  const [probableCause, setProbableCause] = useState('Quema Agrícola');
  const [vegType, setVegType] = useState('Bosque Seco');
  
  // Geo Location (Default Cochabamba Tunari)
  const [latVal, setLatVal] = useState<number>(-17.3935);
  const [lonVal, setLonVal] = useState<number>(-66.157);
  const [isLocating, setIsLocating] = useState(false);

  // Weather & Desc
  const [weatherVal, setWeatherVal] = useState('');
  const [descVal, setDescVal] = useState('');
  
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleGetGps = () => {
    if (!navigator.geolocation) return;
    setIsLocating(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLatVal(pos.coords.latitude);
        setLonVal(pos.coords.longitude);
        setIsLocating(false);
      },
      (err) => {
        console.error('GPS error:', err);
        setIsLocating(false);
      },
      { enableHighAccuracy: true, timeout: 8000 }
    );
  };

  const handleMapClick = (lat: number, lng: number) => {
    setLatVal(lat);
    setLonVal(lng);
  };

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setMsg(null);

    try {
      const payload = {
        ranger_name: rangerName || 'Guardaparques SERNAP',
        incident_type: incType,
        severity_level: severity,
        status: initialStatus,
        detection_time: new Date().toISOString(),
        probable_cause: probableCause,
        latitude: Number(latVal),
        longitude: Number(lonVal),
        weather_conditions: weatherVal || null,
        vegetation_type: vegType,
        description: descVal || 'Registro operativo oficial de campo SERNAP.',
      };

      const res = await api.post('/reports/', payload);
      if (res.data) {
        setMsg({
          type: 'success',
          text: `¡Foco de calor registrado exitosamente! ID #${res.data.id || 'N/A'}. Alertas despachadas en tiempo real por WhatsApp y Telegram a las brigadas de bomberos.`,
        });
        onSuccess();
        setStep(1);
      }
    } catch (err: any) {
      console.error('Submit report error:', err);
      const detail = err.response?.data?.detail;
      let errorText = 'Error al guardar el reporte. Verifique la conexión.';
      if (typeof detail === 'string') {
        errorText = detail;
      } else if (Array.isArray(detail)) {
        errorText = detail.map((d: any) => `${d.loc ? d.loc.join(' → ') : ''}: ${d.msg}`).join(' | ');
      }
      setMsg({
        type: 'error',
        text: errorText,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Wizard Steps Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-6">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full bg-rose-50 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 font-mono text-[10px] font-extrabold uppercase border border-rose-200 dark:border-rose-800">
              Patrullaje & Registro de Campo
            </span>
          </div>
          <h2 className="text-xl font-bold font-heading text-slate-900 dark:text-white flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-600 animate-pulse" />
            <span>Crear Reporte Manual de Foco de Calor</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Registro satelital asistido en 3 pasos con georreferenciación GPS y alerta automática a brigadas.
          </p>
        </div>

        {/* Step Progress Indicators */}
        <div className="flex items-center gap-2 bg-slate-100 dark:bg-surface-elevated p-1.5 rounded-2xl border border-slate-200 dark:border-white/10">
          {[
            { num: 1, label: 'Ubicación' },
            { num: 2, label: 'Parámetros' },
            { num: 3, label: 'Despacho' },
          ].map(({ num, label }) => (
            <button
              key={num}
              onClick={() => step > num && setStep(num)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl font-bold text-xs transition-all cursor-pointer ${
                step === num
                  ? 'bg-emerald-700 text-white shadow-md'
                  : step > num
                  ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300'
                  : 'text-slate-400'
              }`}
            >
              {step > num ? <CheckCircle2 className="w-3.5 h-3.5" /> : <span>{num}.</span>}
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Feedback Message */}
      {msg && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-2xl text-xs font-medium flex items-center justify-between gap-3 ${
            msg.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-900 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-800'
              : 'bg-rose-50 dark:bg-rose-950/40 text-rose-900 dark:text-rose-200 border border-rose-300 dark:border-rose-800'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {msg.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0" />
            )}
            <span>{msg.text}</span>
          </div>
          <button onClick={() => setMsg(null)} className="text-slate-400 hover:text-slate-600 text-xs font-bold">
            ✕
          </button>
        </motion.div>
      )}

      {/* STEP 1: GPS Location & Map Selection */}
      {step === 1 && (
        <motion.div
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          className="space-y-5"
        >
          {/* Minimalist Unified Coordinate Header Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-50/80 dark:bg-surface-elevated/80 backdrop-blur-md p-3.5 px-5 rounded-2xl border border-slate-200/80 dark:border-white/10">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-rose-500/10 text-rose-600 border border-rose-500/20">
                <MapPin className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Paso 1: Coordenadas de Localización del Foco
                </h3>
                <span className="text-[10px] font-mono text-slate-400">
                  Ajuste milimétrico por mapa o GPS de mano
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 bg-white dark:bg-surface-dark px-3 py-1.5 rounded-xl border border-slate-200 dark:border-white/10 shadow-xs">
                <span className="text-[10px] uppercase font-mono font-extrabold text-slate-400">Lat</span>
                <input
                  type="number"
                  step="any"
                  value={latVal}
                  onChange={(e) => setLatVal(parseFloat(e.target.value) || 0)}
                  className="font-mono text-xs font-bold text-slate-900 dark:text-white bg-transparent outline-none w-24 text-right"
                />
              </div>

              <div className="flex items-center gap-2 bg-white dark:bg-surface-dark px-3 py-1.5 rounded-xl border border-slate-200 dark:border-white/10 shadow-xs">
                <span className="text-[10px] uppercase font-mono font-extrabold text-slate-400">Lon</span>
                <input
                  type="number"
                  step="any"
                  value={lonVal}
                  onChange={(e) => setLonVal(parseFloat(e.target.value) || 0)}
                  className="font-mono text-xs font-bold text-slate-900 dark:text-white bg-transparent outline-none w-24 text-right"
                />
              </div>
            </div>
          </div>

          <div className="rounded-2xl overflow-hidden border border-slate-200 dark:border-white/10 shadow-sm">
            <GpsPickerMap
              existingReports={existingReports}
              selectedLocation={{ lat: latVal, lng: lonVal }}
              onSelectLocation={handleMapClick}
              height="400px"
              showExistingFires={true}
            />
          </div>

          <div className="flex justify-end pt-2">
            <Button
              onClick={() => setStep(2)}
              className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-5 py-2.5 rounded-xl shadow-md cursor-pointer"
            >
              <span>Continuar: Parámetros del Incidente</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </motion.div>
      )}

      {/* STEP 2: Operational Incident Parameters (Luxury Minimalist) */}
      {step === 2 && (
        <motion.div
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          className="space-y-6"
        >
          {/* Minimalist Step Header Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50/80 dark:bg-surface-elevated/80 backdrop-blur-md p-3.5 px-5 rounded-2xl border border-slate-200/80 dark:border-white/10">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">
                <Radio className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Paso 2: Parámetros del Incidente y Clasificación Táctica
                </h3>
                <span className="text-[10px] font-mono text-slate-400">
                  Evaluación de severidad y estado operativo para despacho
                </span>
              </div>
            </div>

            <span className="px-3 py-1 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 font-mono text-[10px] font-extrabold border border-emerald-200 dark:border-emerald-700/50 self-start sm:self-auto">
              Estándar SERNAP Tunari
            </span>
          </div>

          {/* Luxury Interactive Initial Status Cards */}
          <div className="space-y-2">
            <Label className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider font-mono text-[11px]">
              Estado Operativo Inicial del Foco
            </Label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              
              {/* Option 1: Foco Activo */}
              <button
                type="button"
                onClick={() => setInitialStatus('Second_State')}
                className={`p-4 rounded-2xl border text-left transition-all cursor-pointer flex items-start gap-3.5 relative overflow-hidden ${
                  initialStatus === 'Second_State'
                    ? 'bg-rose-50/90 dark:bg-rose-950/40 border-rose-500 ring-2 ring-rose-500/30 text-slate-900 dark:text-white shadow-md'
                    : 'bg-white dark:bg-surface-elevated border-slate-200/80 dark:border-white/10 text-slate-600 dark:text-slate-400 hover:border-rose-400/50'
                }`}
              >
                <div className={`p-2.5 rounded-xl shrink-0 ${
                  initialStatus === 'Second_State'
                    ? 'bg-rose-600 text-white shadow-md shadow-rose-600/30'
                    : 'bg-slate-100 dark:bg-surface-dark text-slate-400'
                }`}>
                  <Flame className="w-5 h-5 animate-pulse" />
                </div>
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <strong className="text-xs font-bold text-rose-700 dark:text-rose-300">🚨 Foco Activo</strong>
                    {initialStatus === 'Second_State' && (
                      <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                    )}
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">
                    Frente de fuego no contenido. Requiere despacho urgente a bomberos y brigadas.
                  </p>
                </div>
              </button>

              {/* Option 2: En Control */}
              <button
                type="button"
                onClick={() => setInitialStatus('First_State')}
                className={`p-4 rounded-2xl border text-left transition-all cursor-pointer flex items-start gap-3.5 relative overflow-hidden ${
                  initialStatus === 'First_State'
                    ? 'bg-amber-50/90 dark:bg-amber-950/40 border-amber-500 ring-2 ring-amber-500/30 text-slate-900 dark:text-white shadow-md'
                    : 'bg-white dark:bg-surface-elevated border-slate-200/80 dark:border-white/10 text-slate-600 dark:text-slate-400 hover:border-amber-400/50'
                }`}
              >
                <div className={`p-2.5 rounded-xl shrink-0 ${
                  initialStatus === 'First_State'
                    ? 'bg-amber-500 text-slate-950 shadow-md shadow-amber-500/30'
                    : 'bg-slate-100 dark:bg-surface-dark text-slate-400'
                }`}>
                  <Radio className="w-5 h-5" />
                </div>
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <strong className="text-xs font-bold text-amber-800 dark:text-amber-300">🟡 En Control</strong>
                    {initialStatus === 'First_State' && (
                      <span className="w-2 h-2 rounded-full bg-amber-500" />
                    )}
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">
                    Avance contenido por línea de defensa o cuadrilla de guardaparques en zona.
                  </p>
                </div>
              </button>

            </div>
          </div>

          {/* Interactive Severity Segmented Selector */}
          <div className="space-y-2">
            <Label className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider font-mono text-[11px]">
              Nivel de Gravedad / Criticidad
            </Label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {[
                { id: 'Bajo', label: 'Bajo', desc: 'Humo incipiente', color: 'emerald' },
                { id: 'Medio', label: 'Medio', desc: 'Sotobosque moderado', color: 'amber' },
                { id: 'Alto', label: 'Alto', desc: 'Copas / Viento fuerte', color: 'orange' },
                { id: 'Crítico', label: 'Crítico', desc: 'Alerta departamental', color: 'rose' },
              ].map((sev) => {
                const isSelected = severity === sev.id;
                return (
                  <button
                    key={sev.id}
                    type="button"
                    onClick={() => setSeverity(sev.id)}
                    className={`p-3 rounded-2xl border text-center transition-all cursor-pointer ${
                      isSelected
                        ? sev.color === 'rose'
                          ? 'bg-rose-600 text-white border-rose-600 shadow-md ring-2 ring-rose-400/40 font-bold'
                          : sev.color === 'orange'
                          ? 'bg-orange-600 text-white border-orange-600 shadow-md ring-2 ring-orange-400/40 font-bold'
                          : sev.color === 'amber'
                          ? 'bg-amber-500 text-slate-950 border-amber-500 shadow-md ring-2 ring-amber-400/40 font-bold'
                          : 'bg-emerald-600 text-white border-emerald-600 shadow-md ring-2 ring-emerald-400/40 font-bold'
                        : 'bg-slate-50 dark:bg-surface-elevated border-slate-200/80 dark:border-white/10 text-slate-600 dark:text-slate-400 hover:bg-slate-100'
                    }`}
                  >
                    <span className="text-xs block">{sev.label}</span>
                    <span className={`text-[10px] block opacity-80 font-mono ${isSelected ? 'text-inherit' : 'text-slate-400'}`}>
                      {sev.desc}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Form Fields Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            
            {/* Ranger Name */}
            <div className="space-y-1.5 p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
              <Label className="text-[11px] font-bold text-slate-700 dark:text-slate-300">Guardaparques</Label>
              <Input
                value={rangerName}
                onChange={(e) => setRangerName(e.target.value)}
                className="bg-white dark:bg-surface-dark border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs font-medium"
              />
            </div>

            {/* Incident Type */}
            <div className="space-y-1.5 p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
              <Label className="text-[11px] font-bold text-slate-700 dark:text-slate-300">Tipo de Incidente</Label>
              <Select value={incType} onValueChange={(val) => val && setIncType(val)}>
                <SelectTrigger className="bg-white dark:bg-surface-dark border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
                  <SelectItem value="Incendio Forestal">Incendio Forestal Mayor</SelectItem>
                  <SelectItem value="Quema Agrícola">Quema Agrícola / Chaqueo</SelectItem>
                  <SelectItem value="Foco de Calor">Foco de Calor Satelital</SelectItem>
                  <SelectItem value="Conflagración Estructural">Interfaz Urbano-Forestal</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Probable Cause */}
            <div className="space-y-1.5 p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
              <Label className="text-[11px] font-bold text-slate-700 dark:text-slate-300">Causa Probable</Label>
              <Select value={probableCause} onValueChange={(val) => val && setProbableCause(val)}>
                <SelectTrigger className="bg-white dark:bg-surface-dark border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
                  <SelectItem value="Quema Agrícola">Chaqueo no autorizado</SelectItem>
                  <SelectItem value="Negligencia">Negligencia / Fogata</SelectItem>
                  <SelectItem value="Intencional">Intencional / Sabotaje</SelectItem>
                  <SelectItem value="Natural">Natural / Sequía extrema</SelectItem>
                  <SelectItem value="Desconocido">En Investigación</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Vegetation Type */}
            <div className="space-y-1.5 p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
              <Label className="text-[11px] font-bold text-slate-700 dark:text-slate-300">Tipo de Vegetación</Label>
              <Select value={vegType} onValueChange={(val) => val && setVegType(val)}>
                <SelectTrigger className="bg-white dark:bg-surface-dark border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
                  <SelectItem value="Bosque Seco">Bosque Seco (Kewiña)</SelectItem>
                  <SelectItem value="Pastizal">Pastizal de Altura / Pajonal</SelectItem>
                  <SelectItem value="Pinar">Pinar / Eucalipto</SelectItem>
                  <SelectItem value="Matorral">Matorral Arbustivo</SelectItem>
                </SelectContent>
              </Select>
            </div>

          </div>

          {/* Navigation Buttons */}
          <div className="flex justify-between pt-4 border-t border-slate-100 dark:border-white/[0.08]">
            <Button
              variant="outline"
              onClick={() => setStep(1)}
              className="rounded-2xl text-xs gap-2 px-5 py-5 border-slate-200 dark:border-white/10 cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Atrás: Ubicación</span>
            </Button>

            <Button
              onClick={() => setStep(3)}
              className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-6 py-5 rounded-2xl shadow-md cursor-pointer transition-all hover:scale-102"
            >
              <span>Continuar: Clima & Despacho</span>
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </motion.div>
      )}

      {/* STEP 3: Weather Telemetry, Field Notes & Instant Dispatch (Luxury Minimalist) */}
      {step === 3 && (
        <motion.div
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          className="space-y-6"
        >
          {/* Minimalist Step Header Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50/80 dark:bg-surface-elevated/80 backdrop-blur-md p-3.5 px-5 rounded-2xl border border-slate-200/80 dark:border-white/10">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-amber-500/10 text-amber-600 border border-amber-500/20">
                <CloudSun className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Paso 3: Telemetría de Campo y Despacho Operativo
                </h3>
                <span className="text-[10px] font-mono text-slate-400">
                  Condiciones meteorológicas, accesibilidad y despacho automático a brigadas
                </span>
              </div>
            </div>

            <span className="px-3 py-1 rounded-full bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 font-mono text-[10px] font-extrabold border border-amber-200 dark:border-amber-700/50 self-start sm:self-auto">
              Despacho Automático WhatsApp / Telegram
            </span>
          </div>

          {/* Weather & Field Notes Inputs */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
            
            {/* Weather Telemetry */}
            <div className="space-y-2 p-4 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                  <CloudSun className="w-3.5 h-3.5 text-amber-500" />
                  <span>Condiciones Meteorológicas en Zona</span>
                </Label>
                <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-2 py-0.5 rounded-full border border-emerald-200 dark:border-emerald-800">
                  Open-Meteo Satelital
                </span>
              </div>
              <Input
                placeholder="Ej. T: 27°C, Humedad: 28%, Viento: 22 km/h NW (o dejar vacío para consulta satelital automática)"
                value={weatherVal}
                onChange={(e) => setWeatherVal(e.target.value)}
                className="bg-white dark:bg-surface-dark border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs font-mono"
              />
              <p className="text-[11px] text-slate-400">
                Si se omite, el servidor inyectará la telemetría climática exacta del satélite para estas coordenadas.
              </p>
            </div>

            {/* Field Access Notes */}
            <div className="space-y-2 p-4 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <Compass className="w-3.5 h-3.5 text-emerald-600" />
                <span>Descripción Táctica y Accesibilidad para Cuadrillas</span>
              </Label>
              <textarea
                rows={2}
                placeholder="Frente de avance, pendientes pronunciadas, vías de acceso 4x4, hidrantes o disponibilidad de agua..."
                value={descVal}
                onChange={(e) => setDescVal(e.target.value)}
                className="w-full p-2.5 rounded-xl text-xs bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 text-slate-900 dark:text-white focus:outline-emerald-600 resize-none"
              />
            </div>

          </div>

          {/* Consolidated Luxury Tactical Summary Sheet */}
          <div className="bg-slate-50/90 dark:bg-surface-elevated/90 backdrop-blur-md border border-slate-200/90 dark:border-white/10 rounded-3xl p-6 space-y-4 text-xs shadow-sm">
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200/80 dark:border-white/10 pb-3">
              <h4 className="font-extrabold text-slate-900 dark:text-white uppercase font-mono text-xs flex items-center gap-2">
                <Trees className="w-4 h-4 text-emerald-600" />
                <span>Ficha Táctica Consolidada de Despacho</span>
              </h4>
              <span className={`px-3 py-1 rounded-full font-mono text-[11px] font-black border self-start sm:self-auto ${
                initialStatus === 'Second_State'
                  ? 'bg-rose-100 text-rose-800 dark:bg-rose-950/80 dark:text-rose-300 border-rose-300 dark:border-rose-800'
                  : 'bg-amber-100 text-amber-800 dark:bg-amber-950/80 dark:text-amber-300 border-amber-300 dark:border-amber-800'
              }`}>
                {initialStatus === 'Second_State' ? '🚨 FOCO ACTIVO • DESPACHO INMEDIATO' : '🟡 EN CONTROL • MONITOREO'}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
              <div className="p-3 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/5 space-y-0.5">
                <span className="text-[10px] text-slate-400 font-mono block">REPORTANTE</span>
                <strong className="text-xs text-slate-900 dark:text-white block truncate">{rangerName}</strong>
              </div>
              <div className="p-3 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/5 space-y-0.5">
                <span className="text-[10px] text-slate-400 font-mono block">INCIDENTE</span>
                <strong className="text-xs text-slate-900 dark:text-white block truncate">{incType}</strong>
              </div>
              <div className="p-3 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/5 space-y-0.5">
                <span className="text-[10px] text-slate-400 font-mono block">GRAVEDAD</span>
                <strong className={`text-xs font-mono font-bold block ${
                  severity === 'Crítico' ? 'text-rose-600' : severity === 'Alto' ? 'text-orange-600' : 'text-amber-600'
                }`}>{severity}</strong>
              </div>
              <div className="p-3 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/5 space-y-0.5">
                <span className="text-[10px] text-slate-400 font-mono block">CAUSA</span>
                <strong className="text-xs text-slate-900 dark:text-white block truncate">{probableCause}</strong>
              </div>
              <div className="p-3 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/5 space-y-0.5">
                <span className="text-[10px] text-slate-400 font-mono block">VEGETACIÓN</span>
                <strong className="text-xs text-slate-900 dark:text-white block truncate">{vegType}</strong>
              </div>
              <div className="p-3 rounded-2xl bg-white dark:bg-surface-dark border border-slate-200/80 dark:border-white/5 space-y-0.5">
                <span className="text-[10px] text-slate-400 font-mono block">COORDENADAS GPS</span>
                <span className="font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400 block">
                  {latVal.toFixed(4)}, {lonVal.toFixed(4)}
                </span>
              </div>
            </div>

            {/* Instant Automated Brigade Dispatch Alert Notice */}
            <div className="p-3.5 rounded-2xl bg-emerald-50/80 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <Send className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <span className="text-xs">
                  Al confirmar, el servidor despachará automáticamente las coordenadas GPS vía <strong>WhatsApp</strong> y <strong>Telegram</strong> a los comandantes de brigada (SAR, GEOS, FERO, UGR).
                </span>
              </div>
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 hidden sm:inline" />
            </div>

          </div>

          {/* Navigation & Submit Buttons */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-4 border-t border-slate-100 dark:border-white/[0.08]">
            <Button
              variant="outline"
              onClick={() => setStep(2)}
              className="rounded-2xl text-xs gap-2 px-5 py-5 border-slate-200 dark:border-white/10 cursor-pointer order-2 sm:order-1"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Atrás: Parámetros</span>
            </Button>

            <Button
              onClick={handleSubmit}
              disabled={isSubmitting}
              className="bg-rose-600 hover:bg-rose-700 text-white font-extrabold px-8 py-5 rounded-2xl shadow-xl gap-2 text-xs cursor-pointer transition-all hover:scale-102 order-1 sm:order-2"
            >
              <Flame className="w-4 h-4 animate-pulse" />
              <span>{isSubmitting ? 'Registrando y Despachando Alertas...' : 'Registrar Foco e Iniciar Despacho de Brigadas'}</span>
            </Button>
          </div>
        </motion.div>
      )}

    </div>
  );
};

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Sparkles, Upload, Flame, CheckCircle2, ShieldAlert, Cpu, Zap, Activity, Clock, Layers } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import api from '../../services/api';

export const MobileNetFireClassifier: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [result, setResult] = useState<{
    label: string;
    confidence: number;
    inference_time_ms: number;
    score: number;
    fire_detected: boolean;
  } | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
    setResult(null);
    setErrorMsg('');
  };

  const handleRunInference = async () => {
    if (!selectedFile) return;

    setIsLoading(true);
    setErrorMsg('');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const res = await api.post('/ml/predict-fire-image', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      if (res.data) {
        setResult(res.data);
      }
    } catch (err: any) {
      console.error('Inference error:', err);
      setErrorMsg(
        err.response?.data?.detail || 'Error al ejecutar inferencia con MobileNetV2.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const isFire = result?.fire_detected ?? false;
  const confidencePercent = result ? Math.round(result.confidence * 100) : 0;

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 shadow-inner">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white flex items-center gap-2">
              <span>Detección de Incendios con IA</span>
              <span className="px-2 py-0.5 rounded-full bg-purple-100 dark:bg-purple-950/60 text-purple-900 dark:text-purple-300 text-[10px] font-mono font-extrabold uppercase border border-purple-300 dark:border-purple-800">
                CNN MobileNetV2
              </span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Clasificador de visión artificial convolucional para fotografías de dron y cámaras térmicas (~50ms).
            </p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-700/50">
          TensorFlow / Keras Embedded
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Upload Column */}
        <div className="space-y-4">
          <div className="border-2 border-dashed border-slate-300 dark:border-white/10 rounded-2xl p-6 text-center hover:border-emerald-500/50 hover:bg-slate-50/50 dark:hover:bg-surface-elevated/40 transition-all">
            <Upload className="w-8 h-8 text-emerald-600 dark:text-emerald-400 mx-auto mb-2 opacity-80" />
            <p className="text-xs font-bold text-slate-900 dark:text-white">
              Cargar Fotografía de Campo o Vuelo de Dron
            </p>
            <p className="text-[11px] text-slate-400 mb-3">Formatos: JPG, PNG, WEBP (resolución 180×180 px normalizada)</p>
            <Input
              type="file"
              accept="image/*"
              onChange={handleFileChange}
              className="text-xs max-w-xs mx-auto bg-white dark:bg-surface-dark border-slate-200 dark:border-white/10 rounded-xl"
            />
          </div>

          {previewUrl && (
            <div className="relative w-full h-52 rounded-2xl overflow-hidden border border-slate-200 dark:border-white/10 bg-slate-950 shadow-inner">
              <img src={previewUrl} alt="Vista previa de campo" className="w-full h-full object-cover" />
            </div>
          )}

          <Button
            onClick={handleRunInference}
            disabled={!selectedFile || isLoading}
            className="w-full bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 py-5 rounded-2xl shadow-md cursor-pointer disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4 text-amber-300" />
            <span>{isLoading ? 'Ejecutando Inferencia Neuronal...' : 'Ejecutar Inferencia MobileNetV2'}</span>
          </Button>

          {errorMsg && (
            <div className="p-3 text-xs bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-rose-900 dark:text-rose-200 rounded-2xl flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}
        </div>

        {/* Results Column */}
        <div className="bg-slate-50/80 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10 rounded-2xl p-6 flex flex-col justify-between space-y-4">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200/80 dark:border-white/10 pb-2">
              <h4 className="text-xs font-bold uppercase font-mono text-slate-400 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-600" />
                <span>Diagnóstico del Modelo</span>
              </h4>
              {result && (
                <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                  {result.inference_time_ms} ms
                </span>
              )}
            </div>

            {result ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="space-y-4"
              >
                <div
                  className={`p-5 rounded-2xl border flex items-center gap-4 ${
                    isFire
                      ? 'bg-rose-100 dark:bg-rose-950/50 border-rose-300 dark:border-rose-800 text-rose-900 dark:text-rose-200'
                      : 'bg-emerald-100 dark:bg-emerald-950/50 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
                  }`}
                >
                  {isFire ? (
                    <Flame className="w-10 h-10 text-rose-600 animate-pulse shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-10 h-10 text-emerald-600 shrink-0" />
                  )}
                  <div className="space-y-0.5">
                    <h5 className="font-extrabold text-base font-heading">{result.label}</h5>
                    <p className="text-xs opacity-90">
                      Nivel de Confianza: <strong>{confidencePercent}%</strong>
                    </p>
                  </div>
                </div>

                {/* Metric Bars */}
                <div className="space-y-3 pt-2">
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-bold">
                      <span className="text-slate-600 dark:text-slate-300">Confianza del Clasificador:</span>
                      <span className="font-mono text-emerald-600 dark:text-emerald-400">{confidencePercent}%</span>
                    </div>
                    <div className="w-full h-2.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${confidencePercent}%` }}
                        transition={{ duration: 0.6, ease: 'easeOut' }}
                        className={`h-full ${isFire ? 'bg-rose-600' : 'bg-emerald-600'}`}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2">
                    <div className="p-2.5 rounded-xl bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/5 space-y-0.5">
                      <span className="text-[10px] text-slate-400 block">Tiempo de Inferencia</span>
                      <strong className="text-slate-900 dark:text-white">{result.inference_time_ms} ms</strong>
                    </div>
                    <div className="p-2.5 rounded-xl bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/5 space-y-0.5">
                      <span className="text-[10px] text-slate-400 block">Arquitectura</span>
                      <strong className="text-slate-900 dark:text-white">MobileNetV2 Sigmoid</strong>
                    </div>
                  </div>
                </div>
              </motion.div>
            ) : (
              <div className="py-12 text-center text-slate-400 space-y-2">
                <Zap className="w-8 h-8 mx-auto opacity-40 text-emerald-600" />
                <p className="text-xs">Cargue una imagen de patrullaje para iniciar el análisis neuronal.</p>
              </div>
            )}
          </div>

          <div className="text-[11px] text-slate-400 dark:text-slate-500 pt-2 border-t border-slate-200/80 dark:border-white/10">
            * Modelo entrenado con dataset de vegetación boliviana y humo de chaqueo para evitar falsos positivos con niebla o nubes bajas.
          </div>
        </div>

      </div>

    </div>
  );
};

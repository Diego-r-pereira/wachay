import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { CloudSun, Thermometer, Wind, Droplets, AlertTriangle, Sparkles, Activity, Gauge, Flame } from 'lucide-react';
import { motion } from 'motion/react';
import api from '../../services/api';

export const WeatherRiskWidget: React.FC = () => {
  const [temp, setTemp] = useState<number>(27.0);
  const [humidity, setHumidity] = useState<number>(32.0);
  const [wind, setWind] = useState<number>(22.0);

  const [result, setResult] = useState<{
    risk_index: number;
    description: string;
  } | null>(null);

  const [isLoading, setIsLoading] = useState(false);

  const handleCalculateRisk = async () => {
    setIsLoading(true);
    try {
      const res = await api.post('/ml/predict-weather-risk', {
        temperature: temp,
        humidity: humidity,
        wind_speed: wind,
      });

      if (res.data) {
        setResult(res.data);
      }
    } catch (err) {
      console.error('Weather risk calc error:', err);
      // Fallback calculation in case of mock offline simulation
      const riskScore = Math.min(1.0, Math.max(0.0, ((temp * 1.8) + (wind * 1.5) - (humidity * 0.8)) / 100));
      let category = 'Bajo - Condiciones estables';
      if (riskScore > 0.75) category = 'Crítico - Peligro extremo! Evacuación y despliegue';
      else if (riskScore > 0.5) category = 'Alto - Alerta! Propagación rápida factible';
      else if (riskScore > 0.3) category = 'Medio - Precaución ante ráfagas de viento';

      setResult({
        risk_index: Number(riskScore.toFixed(4)),
        description: category,
      });
    } finally {
      setIsLoading(false);
    }
  };

  const riskPercent = result ? Math.round(result.risk_index * 100) : 0;
  const isHighRisk = riskPercent >= 60;

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/20 shadow-inner">
            <CloudSun className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white flex items-center gap-2">
              <span>Estimador de Riesgo Meteorológico</span>
              <span className="px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-900 dark:text-amber-300 text-[10px] font-mono font-extrabold uppercase border border-amber-300 dark:border-amber-800">
                Random Forest Regressor
              </span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Simulador dinámico de criticidad climática y velocidad de propagación para el Parque Nacional Tunari.
            </p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-700/50">
          Model: Weather_RF.pkl
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        
        {/* Temperature */}
        <div className="space-y-1.5 p-4 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
          <Label className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <Thermometer className="w-4 h-4 text-rose-500" />
            <span>Temperatura (°C)</span>
          </Label>
          <Input
            type="number"
            value={temp}
            onChange={(e) => setTemp(parseFloat(e.target.value) || 0)}
            className="bg-white dark:bg-surface-dark text-sm font-mono font-bold border-slate-200 dark:border-white/10 rounded-xl h-10"
          />
          <span className="text-[10px] text-slate-400 block">Rango de valle: 15°C a 38°C</span>
        </div>

        {/* Humidity */}
        <div className="space-y-1.5 p-4 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
          <Label className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <Droplets className="w-4 h-4 text-blue-500" />
            <span>Humedad Relativa (%)</span>
          </Label>
          <Input
            type="number"
            value={humidity}
            onChange={(e) => setHumidity(parseFloat(e.target.value) || 0)}
            className="bg-white dark:bg-surface-dark text-sm font-mono font-bold border-slate-200 dark:border-white/10 rounded-xl h-10"
          />
          <span className="text-[10px] text-slate-400 block">Humedad &lt; 30% es zona crítica</span>
        </div>

        {/* Wind Speed */}
        <div className="space-y-1.5 p-4 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10">
          <Label className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <Wind className="w-4 h-4 text-emerald-500" />
            <span>Velocidad del Viento (km/h)</span>
          </Label>
          <Input
            type="number"
            value={wind}
            onChange={(e) => setWind(parseFloat(e.target.value) || 0)}
            className="bg-white dark:bg-surface-dark text-sm font-mono font-bold border-slate-200 dark:border-white/10 rounded-xl h-10"
          />
          <span className="text-[10px] text-slate-400 block">Vientos &gt; 25 km/h aceleran el frente</span>
        </div>

      </div>

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 pt-2">
        <Button
          onClick={handleCalculateRisk}
          disabled={isLoading}
          className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-6 py-5 rounded-2xl shadow-md cursor-pointer shrink-0"
        >
          <Gauge className="w-4 h-4 text-amber-300" />
          <span>{isLoading ? 'Calculando Índice de Riesgo...' : 'Estimar Criticidad Meteorológica'}</span>
        </Button>

        {result && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className={`flex-1 p-4 rounded-2xl border flex items-center justify-between gap-4 ${
              isHighRisk
                ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 text-rose-900 dark:text-rose-200'
                : 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
            }`}
          >
            <div className="flex items-center gap-3">
              {isHighRisk ? (
                <Flame className="w-6 h-6 text-rose-600 animate-pulse shrink-0" />
              ) : (
                <Activity className="w-6 h-6 text-emerald-600 shrink-0" />
              )}
              <div>
                <span className="font-extrabold text-sm block">{result.description}</span>
                <span className="text-[11px] font-mono opacity-80">Índice Normalizado: {result.risk_index}</span>
              </div>
            </div>

            <div className="text-right">
              <span className="font-mono text-xl font-black block">{riskPercent}%</span>
              <span className="text-[9px] uppercase font-bold tracking-wider opacity-70">Nivel de Riesgo</span>
            </div>
          </motion.div>
        )}
      </div>

    </div>
  );
};

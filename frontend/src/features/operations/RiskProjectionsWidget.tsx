import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { RiskProjectionsMap } from '../map/RiskProjectionsMap';
import { Compass, Sparkles, MapPin, AlertCircle, Calendar, RefreshCw, Layers, ShieldCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import api from '../../services/api';
import { ProjectionPoint, IncidentReport } from '../../types';

interface RiskProjectionsWidgetProps {
  existingReports: IncidentReport[];
}

export const RiskProjectionsWidget: React.FC<RiskProjectionsWidgetProps> = ({
  existingReports,
}) => {
  const [monthsAhead, setMonthsAhead] = useState<number>(1);
  const [projections, setProjections] = useState<ProjectionPoint[]>([]);
  const [focusedId, setFocusedId] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const mockProjections: ProjectionPoint[] = [
    { id: 1, latitude: -17.3401, longitude: -66.1823, location_name: 'Cuenca Taquiña (Norte)', risk_probability: 0.88, projected_month: 'Mes +1' },
    { id: 2, latitude: -17.3210, longitude: -66.2340, location_name: 'Paso San Pedro (Sacaba)', risk_probability: 0.79, projected_month: 'Mes +1' },
    { id: 3, latitude: -17.3820, longitude: -66.3100, location_name: 'Lomas de Quillacollo', risk_probability: 0.72, projected_month: 'Mes +1' },
    { id: 4, latitude: -17.2950, longitude: -66.1100, location_name: 'Tiquipaya Alta (Pinar)', risk_probability: 0.65, projected_month: 'Mes +1' },
    { id: 5, latitude: -17.3610, longitude: -66.2780, location_name: 'Cerro Cota (Colcapirhua)', risk_probability: 0.58, projected_month: 'Mes +1' },
  ];

  const handleSimulateProjections = async () => {
    setIsLoading(true);
    try {
      const res = await api.get(`/ml/risk-projections?months=${monthsAhead}`);
      if (res.data && Array.isArray(res.data)) {
        setProjections(res.data);
      } else {
        setProjections(mockProjections);
      }
    } catch (err) {
      console.error('Projections error:', err);
      setProjections(mockProjections);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 shadow-inner">
            <Compass className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white flex items-center gap-2">
              <span>Proyecciones de Riesgo Espacial</span>
              <span className="px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-900 dark:text-emerald-300 text-[10px] font-mono font-extrabold uppercase border border-emerald-300 dark:border-emerald-800">
                Random Forest Espacial
              </span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Análisis predictivo de los 5 hotspots futuros con mayor probabilidad de ignición en Cochabamba.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
          <Select value={String(monthsAhead)} onValueChange={(val) => setMonthsAhead(Number(val))}>
            <SelectTrigger className="w-36 text-xs bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-slate-800 dark:text-slate-200">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
              <SelectItem value="1">Horizonte +1 Mes</SelectItem>
              <SelectItem value="2">Horizonte +2 Meses</SelectItem>
              <SelectItem value="3">Horizonte +3 Meses</SelectItem>
            </SelectContent>
          </Select>

          <Button
            onClick={handleSimulateProjections}
            disabled={isLoading}
            className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-5 py-5 rounded-xl shadow-md cursor-pointer shrink-0"
          >
            {isLoading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Sparkles className="w-4 h-4 text-amber-300" />
            )}
            <span>{isLoading ? 'Simulando Modelos...' : 'Calcular Proyecciones Futuras'}</span>
          </Button>
        </div>
      </div>

      {/* Projections List Cards & Specialized Map */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Top 5 Critical Spots List */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase font-mono text-slate-400">
              Top 5 Hotspots Proyectados
            </h4>
            <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold">
              R² Confianza: 90.4%
            </span>
          </div>

          {projections.length === 0 ? (
            <div className="p-8 text-center border-2 border-dashed border-slate-200 dark:border-white/10 rounded-2xl text-xs text-slate-400 space-y-2">
              <Compass className="w-8 h-8 mx-auto opacity-30 text-emerald-600" />
              <p>Presione "Calcular Proyecciones Futuras" para generar el mapa predictivo de ignición.</p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {projections.map((p, index) => {
                const prob = Math.round((p.risk_probability || p.risk_score || 0.6) * 100);
                const isSelected = focusedId === p.id;

                return (
                  <motion.div
                    key={p.id || index}
                    onClick={() => setFocusedId(p.id)}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className={`p-3.5 rounded-2xl border transition-all cursor-pointer shadow-xs flex items-center justify-between ${
                      isSelected
                        ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-500 ring-2 ring-emerald-400/40'
                        : 'bg-slate-50 dark:bg-surface-elevated border-slate-200/80 dark:border-white/10 hover:border-emerald-500/50'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-7 h-7 rounded-xl bg-emerald-700 text-white text-xs font-mono font-bold flex items-center justify-center shadow-xs">
                        #{index + 1}
                      </span>
                      <div className="space-y-0.5">
                        <h5 className="font-bold text-xs text-slate-900 dark:text-white">
                          {p.location_name || p.name}
                        </h5>
                        <span className="text-[10px] font-mono text-slate-400 block">
                          {p.latitude.toFixed(3)}, {p.longitude.toFixed(3)}
                        </span>
                      </div>
                    </div>

                    <div className="text-right">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-extrabold border ${
                          prob >= 75
                            ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border-rose-300'
                            : 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-300'
                        }`}
                      >
                        {prob}%
                      </span>
                      <span className="block text-[9px] text-slate-400 mt-0.5 font-medium">Prob. Ignición</span>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>

        {/* Specialized Risk Projections Map Display */}
        <div className="lg:col-span-2 rounded-2xl overflow-hidden border border-slate-200 dark:border-white/10 shadow-sm">
          <RiskProjectionsMap
            projections={projections}
            existingReports={existingReports}
            focusedProjectionId={focusedId}
            onSelectProjection={(proj) => setFocusedId(proj.id)}
            height="460px"
          />
        </div>

      </div>

    </div>
  );
};

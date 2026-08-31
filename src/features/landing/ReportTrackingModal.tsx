import React, { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Search, AlertCircle, CheckCircle2, Flame, MapPin, Calendar, Clock } from 'lucide-react';
import api from '../../services/api';
import { IncidentReport } from '../../types';

interface ReportTrackingModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ReportTrackingModal: React.FC<ReportTrackingModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [trackCode, setTrackCode] = useState('');
  const [trackedReport, setTrackedReport] = useState<IncidentReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleTrackSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!trackCode.trim()) return;

    setIsLoading(true);
    setErrorMsg('');
    setTrackedReport(null);

    try {
      const res = await api.get(`/mobile/report_status/${trackCode.trim()}`);
      if (res.data) {
        setTrackedReport({
          id: 0,
          tracking_code: trackCode.trim(),
          date_reported: 'Reciente',
          reporter_type: 'citizen',
          incident_type: 'Reporte Ciudadano',
          severity: 'Medio',
          latitude: -17.3935,
          longitude: -66.157,
          status: res.data.status,
          description: res.data.message,
        });
      } else {
        setErrorMsg('No se encontró ningún reporte con ese código de seguimiento.');
      }
    } catch (err: any) {
      console.error('Track error:', err);
      setErrorMsg(
        err.response?.data?.detail || 'Código de seguimiento no encontrado. Verifique el código e intente de nuevo.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'First_State':
        return (
          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300">
            <Clock className="w-3.5 h-3.5" />
            Pendiente de Validación / En Movilización
          </span>
        );
      case 'Second_State':
        return (
          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-300">
            <Flame className="w-3.5 h-3.5 animate-pulse" />
            Foco Activo • Guardaparques Desplegados
          </span>
        );
      case 'Attended':
        return (
          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Atendido y Extinguido
          </span>
        );
      case 'Rejected':
        return (
          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold bg-gray-100 text-gray-800 border border-gray-300">
            Desestimado / Falsa Alarma
          </span>
        );
      default:
        return <span className="text-xs font-semibold">{status}</span>;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-lg bg-[#fbfbf9] dark:bg-[#1c2c22] border-[#3f644e]/30">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Search className="w-6 h-6 text-[#3f644e]" />
            <DialogTitle className="text-xl font-bold text-[#203126] dark:text-[#fbfbf9]">
              Rastrear Reporte Ciudadano
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#77877c]">
            Ingrese el código de seguimiento (ej. WCH-XXXX) generado al registrar su reporte de incendio.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleTrackSubmit} className="space-y-4 py-2">
          <div className="flex gap-2">
            <Input
              placeholder="Ej. WCH-9876"
              value={trackCode}
              onChange={(e) => setTrackCode(e.target.value.toUpperCase())}
              required
              className="font-mono text-base tracking-wider uppercase bg-white dark:bg-slate-900 border-[#e9e8e5]"
            />
            <Button
              type="submit"
              disabled={isLoading}
              className="bg-[#3f644e] hover:bg-[#2e523b] text-white font-medium"
            >
              {isLoading ? 'Buscando...' : 'Buscar'}
            </Button>
          </div>

          {errorMsg && (
            <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMsg}</span>
            </div>
          )}

          {trackedReport && (
            <div className="bg-white dark:bg-slate-900 border border-[#e9e8e5] dark:border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between border-b pb-2">
                <span className="text-xs font-mono font-bold text-[#3f644e]">
                  {trackedReport.tracking_code}
                </span>
                {getStatusBadge(trackedReport.status)}
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-[#77877c] block">Tipo Incidente:</span>
                  <strong className="text-[#203126] dark:text-white font-medium">
                    {trackedReport.incident_type}
                  </strong>
                </div>

                <div>
                  <span className="text-[#77877c] block">Gravedad:</span>
                  <strong className="text-[#203126] dark:text-white font-medium">
                    {trackedReport.severity}
                  </strong>
                </div>

                <div>
                  <span className="text-[#77877c] block">Fecha Registro:</span>
                  <span className="text-[#203126] dark:text-white font-mono">
                    {trackedReport.date_reported || trackedReport.created_at || 'Reciente'}
                  </span>
                </div>

                <div>
                  <span className="text-[#77877c] block">Coordenadas:</span>
                  <span className="text-[#203126] dark:text-white font-mono">
                    {trackedReport.latitude?.toFixed(4)}, {trackedReport.longitude?.toFixed(4)}
                  </span>
                </div>
              </div>

              {trackedReport.description && (
                <div className="text-xs pt-1 border-t">
                  <span className="text-[#77877c] block">Detalles del Reporte:</span>
                  <p className="text-[#4a574e] dark:text-[#77877c] italic mt-0.5">
                    "{trackedReport.description}"
                  </p>
                </div>
              )}
            </div>
          )}

          <DialogFooter className="pt-2">
            <Button variant="outline" type="button" onClick={onClose} className="w-full sm:w-auto">
              Cerrar
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

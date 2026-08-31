import React, { useState } from 'react';
import { IncidentReport } from '../../types';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { CheckCircle2, XCircle, Clock, ShieldAlert, User, MapPin, Eye, ExternalLink, Image as ImageIcon } from 'lucide-react';
import { motion } from 'motion/react';
import api from '../../services/api';

interface CitizenApprovalMatrixProps {
  pendingReports: IncidentReport[];
  onRefresh: () => void;
}

export const CitizenApprovalMatrix: React.FC<CitizenApprovalMatrixProps> = ({
  pendingReports,
  onRefresh,
}) => {
  const [rejectionId, setRejectionId] = useState<number | null>(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [selectedPhoto, setSelectedPhoto] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleApprove = async (reportId: number) => {
    setIsSubmitting(true);
    try {
      await api.put(`/reports/${reportId}`, { status: 'First_State' });
      onRefresh();
    } catch (err) {
      console.error('Approve error:', err);
      alert('Error al aprobar el reporte.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRejectSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rejectionId) return;

    setIsSubmitting(true);
    try {
      await api.put(`/reports/${rejectionId}`, {
        status: 'Rejected',
        rejection_reason: rejectionReason || 'Reporte desestimado tras verificación de campo.',
      });
      setRejectionId(null);
      setRejectionReason('');
      onRefresh();
    } catch (err) {
      console.error('Reject error:', err);
      alert('Error al desestimar el reporte.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div>
          <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white flex items-center gap-2">
            <Clock className="w-5 h-5 text-amber-500" />
            Aprobación Cruzada de Denuncias Ciudadanas
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Revise las alertas enviadas por la comunidad, examine la evidencia fotográfica y autorice el despacho de brigadas.
          </p>
        </div>
        <span className="px-3.5 py-1.5 rounded-full text-xs font-bold bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-pajonal/40">
          {pendingReports.length} Denuncias en Espera
        </span>
      </div>

      <div className="overflow-x-auto rounded-2xl border border-slate-200/80 dark:border-white/10">
        <Table className="text-xs">
          <TableHeader className="bg-slate-50/90 dark:bg-surface-elevated">
            <TableRow className="border-b border-slate-200/80 dark:border-white/10">
              <TableHead className="font-bold text-slate-900 dark:text-white">Código</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Ciudadano</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Tipo / Gravedad</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Ubicación GPS</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Detalles & Evidencia</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white text-right">Acciones</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pendingReports.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-10 text-slate-400">
                  <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                  No hay denuncias ciudadanas pendientes de validación en este momento.
                </TableCell>
              </TableRow>
            ) : (
              pendingReports.map((rep) => {
                const citizenName = rep.citizen_name || rep.reporter_name || 'Ciudadano Anónimo';
                const citizenEmail = rep.citizen_email || rep.reporter_email;
                const sev = rep.severity_level || rep.severity || 'Medio';
                const hasPhoto = !!rep.photo_path;

                return (
                  <TableRow key={rep.id} className="hover:bg-slate-50/80 dark:hover:bg-surface-elevated/50 transition-colors border-b border-slate-100 dark:border-white/5">
                    <TableCell className="font-mono font-bold text-emerald-700 dark:text-emerald-400">
                      {rep.tracking_code}
                    </TableCell>
                    <TableCell>
                      <div className="font-medium text-slate-900 dark:text-white flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-slate-400" />
                        {citizenName}
                      </div>
                      {citizenEmail && (
                        <span className="text-[10px] text-slate-400 block font-mono">{citizenEmail}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="font-semibold text-slate-900 dark:text-white">{rep.incident_type}</div>
                      <span className="text-[10px] font-bold text-rose-600 uppercase">{sev}</span>
                    </TableCell>
                    <TableCell className="font-mono text-[11px]">
                      <a
                        href={`https://www.google.com/maps/search/?api=1&query=${rep.latitude},${rep.longitude}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-cuenca-dark dark:text-cuenca hover:underline"
                      >
                        <MapPin className="w-3 h-3" />
                        {rep.latitude?.toFixed(4)}, {rep.longitude?.toFixed(4)}
                      </a>
                    </TableCell>
                    <TableCell className="max-w-xs text-[11px] text-slate-600 dark:text-slate-300">
                      <p className="truncate italic">"{rep.description || 'Sin descripción adicional'}"</p>
                      {hasPhoto && (
                        <button
                          onClick={() => setSelectedPhoto(rep.photo_path || null)}
                          className="mt-1 inline-flex items-center gap-1 text-[10px] font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                        >
                          <ImageIcon className="w-3 h-3" />
                          <span>Ver Foto Adjunta</span>
                        </button>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          size="sm"
                          onClick={() => handleApprove(rep.id)}
                          disabled={isSubmitting}
                          className="bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] h-8 px-3 rounded-xl gap-1 font-bold shadow-xs cursor-pointer"
                          title="Aprobar y despachar brigadas"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Aprobar</span>
                        </Button>

                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setRejectionId(rep.id)}
                          disabled={isSubmitting}
                          className="border-rose-200 dark:border-rose-800/40 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/30 text-[11px] h-8 px-3 rounded-xl gap-1 font-bold cursor-pointer"
                          title="Desestimar denuncia"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          <span>Rechazar</span>
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {/* Photo Preview Dialog */}
      <Dialog open={!!selectedPhoto} onOpenChange={() => setSelectedPhoto(null)}>
        <DialogContent className="sm:max-w-lg bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 shadow-2xl">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <ImageIcon className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              Evidencia Fotográfica de la Denuncia
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Fotografía capturada en campo por el ciudadano reportante.
            </DialogDescription>
          </DialogHeader>

          {selectedPhoto && (
            <div className="py-2 rounded-2xl overflow-hidden bg-slate-950 flex items-center justify-center">
              <img
                src={`http://localhost:8000/${selectedPhoto}`}
                alt="Evidencia del ciudadano"
                className="max-h-96 w-auto object-contain rounded-xl"
                onError={(e) => {
                  (e.target as HTMLElement).style.display = 'none';
                }}
              />
            </div>
          )}

          <DialogFooter>
            <Button type="button" onClick={() => setSelectedPhoto(null)} className="bg-slate-900 dark:bg-white text-white dark:text-slate-950 font-bold rounded-xl text-xs">
              Cerrar Vista Previa
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rejection Dialog */}
      <Dialog open={!!rejectionId} onOpenChange={() => setRejectionId(null)}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 shadow-2xl">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white">
              Motivo de Desestimación de Denuncia
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Indique la razón técnica por la que se desestima el reporte (ej. vapor de agua, quema con autorización ABT).
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleRejectSubmit} className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Razón / Observación</Label>
              <textarea
                rows={3}
                placeholder="Ej. Verificación de campo negativa. Quema controlada comunitaria con permiso ABT."
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                required
                className="w-full p-3 rounded-xl text-xs bg-slate-50 dark:bg-surface-elevated border border-slate-200 dark:border-white/10 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-rose-500"
              />
            </div>

            <DialogFooter className="gap-2 sm:gap-0">
              <Button type="button" variant="outline" onClick={() => setRejectionId(null)} className="rounded-xl text-xs">
                Cancelar
              </Button>
              <Button type="submit" disabled={isSubmitting} className="bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-xl text-xs">
                Confirmar Desestimación
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

    </div>
  );
};

import React, { useState } from 'react';
import { IncidentReport } from '../../types';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import {
  Flame,
  CheckCircle2,
  Clock,
  Search,
  Filter,
  AlertTriangle,
  FileText,
  Send,
  Radio,
  Compass,
  MapPin,
  Trash2,
  Eye,
  Image as ImageIcon,
  Trees,
  CloudRain,
  User,
  ShieldCheck
} from 'lucide-react';
import { motion } from 'motion/react';
import api from '../../services/api';

interface ReportTableProps {
  reports: IncidentReport[];
  onRefresh: () => void;
  onOpenExportModal?: () => void;
  isAdmin?: boolean;
}

export const ReportTable: React.FC<ReportTableProps> = ({
  reports,
  onRefresh,
  onOpenExportModal,
  isAdmin = false,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [updatingId, setUpdatingId] = useState<number | null>(null);

  // Modals
  const [detailReport, setDetailReport] = useState<IncidentReport | null>(null);
  const [photoPreview, setPhotoPreview] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);

  const filteredReports = reports.filter((r) => {
    const matchesSearch =
      (r.tracking_code || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.incident_type || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.reporter_name || r.ranger_name || r.citizen_name || '').toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'all' || r.status === statusFilter;
    const matchesSeverity = severityFilter === 'all' || (r.severity_level || r.severity) === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const handleUpdateStatus = async (reportId: number, newStatus: string) => {
    setUpdatingId(reportId);
    try {
      await api.patch(`/reports/${reportId}/status`, { status: newStatus });
      onRefresh();
    } catch (err) {
      console.error('Error updating status:', err);
      // Fallback to PUT
      try {
        await api.put(`/reports/${reportId}`, { status: newStatus });
        onRefresh();
      } catch (err2) {
        console.error('Fallback PUT failed:', err2);
      }
    } finally {
      setUpdatingId(null);
    }
  };

  const handleDeleteReport = async (reportId: number) => {
    try {
      await api.delete(`/reports/${reportId}`);
      setDeleteConfirmId(null);
      onRefresh();
    } catch (err) {
      console.error('Error deleting report:', err);
      alert('Error al eliminar el reporte.');
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Crítico':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-extrabold bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800 font-mono">CRÍTICO</span>;
      case 'Alto':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-orange-100 dark:bg-orange-950/60 text-orange-800 dark:text-orange-300 border border-orange-300 dark:border-orange-800 font-mono">ALTO</span>;
      case 'Medio':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 font-mono">MEDIO</span>;
      default:
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 font-mono">BAJO</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'First_State':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-100 dark:bg-amber-950/60 text-amber-900 dark:text-amber-300 border border-amber-300 dark:border-amber-800 flex items-center gap-1 w-fit"><Clock className="w-3 h-3 text-amber-600" /> En Control</span>;
      case 'Second_State':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-rose-100 dark:bg-rose-950/60 text-rose-900 dark:text-rose-300 border border-rose-300 dark:border-rose-800 flex items-center gap-1 w-fit"><Flame className="w-3 h-3 text-rose-600 animate-pulse" /> Activo</span>;
      case 'Attended':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-900 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 flex items-center gap-1 w-fit"><CheckCircle2 className="w-3 h-3 text-emerald-600" /> Sofocado</span>;
      case 'Rejected':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-medium bg-slate-100 dark:bg-surface-elevated text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-white/10 w-fit">Desestimado</span>;
      default:
        return <span className="text-xs">{status}</span>;
    }
  };

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header Filters & Actions */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <Input
              placeholder="Buscar por código, tipo, nombre..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 text-xs bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10"
            />
          </div>

          <Select value={statusFilter} onValueChange={(val) => val && setStatusFilter(val)}>
            <SelectTrigger className="w-36 text-xs bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-slate-800 dark:text-slate-200">
              <SelectValue placeholder="Estado" />
            </SelectTrigger>
            <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
              <SelectItem value="all">Todos Estados</SelectItem>
              <SelectItem value="Second_State">🚨 Focos Activos</SelectItem>
              <SelectItem value="First_State">🟡 En Control</SelectItem>
              <SelectItem value="Attended">🟢 Sofocados</SelectItem>
            </SelectContent>
          </Select>

          <Select value={severityFilter} onValueChange={(val) => val && setSeverityFilter(val)}>
            <SelectTrigger className="w-32 text-xs bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-slate-800 dark:text-slate-200">
              <SelectValue placeholder="Gravedad" />
            </SelectTrigger>
            <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
              <SelectItem value="all">Toda Gravedad</SelectItem>
              <SelectItem value="Crítico">Crítico</SelectItem>
              <SelectItem value="Alto">Alto</SelectItem>
              <SelectItem value="Medio">Medio</SelectItem>
              <SelectItem value="Bajo">Bajo</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {onOpenExportModal && (
          <Button
            onClick={onOpenExportModal}
            className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-4 py-2 rounded-xl shadow-md cursor-pointer shrink-0"
          >
            <FileText className="w-4 h-4" />
            <span>Configurar Exportación</span>
          </Button>
        )}
      </div>

      {/* Table Data */}
      <div className="overflow-x-auto rounded-2xl border border-slate-200/80 dark:border-white/10">
        <Table className="text-xs">
          <TableHeader className="bg-slate-50/90 dark:bg-surface-elevated">
            <TableRow className="border-b border-slate-200/80 dark:border-white/10">
              <TableHead className="font-bold text-slate-900 dark:text-white">Código / ID</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Fecha</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Tipo Incidente</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Ubicación GPS</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Gravedad</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Estado</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white text-right">Acciones Operativas</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredReports.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-10 text-slate-400">
                  No se encontraron registros de focos con los filtros actuales.
                </TableCell>
              </TableRow>
            ) : (
              filteredReports.map((rep) => {
                const sev = rep.severity_level || rep.severity || 'Medio';
                const hasPhoto = !!rep.photo_path;

                return (
                  <TableRow key={rep.id} className="hover:bg-slate-50/80 dark:hover:bg-surface-elevated/50 transition-colors border-b border-slate-100 dark:border-white/5">
                    <TableCell className="font-mono font-bold text-emerald-700 dark:text-emerald-400">
                      <div className="flex items-center gap-1.5">
                        <span>{rep.tracking_code || `ID #${rep.id}`}</span>
                        {hasPhoto && (
                          <button
                            onClick={() => setPhotoPreview(rep.photo_path || null)}
                            className="text-emerald-600 hover:text-emerald-700 p-0.5 cursor-pointer"
                            title="Ver fotografía adjunta"
                          >
                            <ImageIcon className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {rep.detection_time ? new Date(rep.detection_time).toLocaleDateString() : rep.date_reported || rep.created_at || 'Reciente'}
                    </TableCell>
                    <TableCell className="font-medium text-slate-900 dark:text-white">
                      <div className="flex flex-col">
                        <span>{rep.incident_type}</span>
                        <span className="text-[10px] text-slate-400 font-normal">
                          {rep.ranger_name ? `Guardaparques: ${rep.ranger_name}` : rep.citizen_name ? `Ciudadano: ${rep.citizen_name}` : 'Fuente SERNAP'}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-[11px]">
                      <a
                        href={`https://www.google.com/maps/search/?api=1&query=${rep.latitude},${rep.longitude}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-cuenca-dark dark:text-cuenca hover:underline"
                        title="Ver en Google Maps"
                      >
                        <MapPin className="w-3 h-3" />
                        <span>{rep.latitude?.toFixed(4)}, {rep.longitude?.toFixed(4)}</span>
                      </a>
                    </TableCell>
                    <TableCell>{getSeverityBadge(sev)}</TableCell>
                    <TableCell>{getStatusBadge(rep.status)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        
                        {/* View Technical Sheet Detail */}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setDetailReport(rep)}
                          className="h-8 w-8 p-0 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-surface-elevated cursor-pointer"
                          title="Ver Ficha Técnica Completa"
                        >
                          <Eye className="w-4 h-4" />
                        </Button>

                        {/* Status Toggle Buttons */}
                        {rep.status === 'First_State' && (
                          <div className="flex items-center gap-1">
                            <Button
                              size="sm"
                              onClick={() => handleUpdateStatus(rep.id, 'Second_State')}
                              disabled={updatingId === rep.id}
                              className="bg-rose-600 hover:bg-rose-700 text-white text-[10px] h-7 px-2.5 rounded-lg font-bold shadow-xs cursor-pointer"
                              title="Pasa el foco a estado Activo"
                            >
                              Activar Foco
                            </Button>
                            <Button
                              size="sm"
                              onClick={() => handleUpdateStatus(rep.id, 'Attended')}
                              disabled={updatingId === rep.id}
                              className="bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] h-7 px-2.5 rounded-lg font-bold shadow-xs cursor-pointer"
                              title="Marcar como Extinguido / Sofocado"
                            >
                              Sofocar
                            </Button>
                          </div>
                        )}

                        {rep.status === 'Second_State' && (
                          <div className="flex items-center gap-1">
                            <Button
                              size="sm"
                              onClick={() => handleUpdateStatus(rep.id, 'First_State')}
                              disabled={updatingId === rep.id}
                              className="bg-amber-500 hover:bg-amber-600 text-slate-950 text-[10px] h-7 px-2.5 rounded-lg font-bold shadow-xs cursor-pointer"
                              title="Pasa el foco a estado En Control"
                            >
                              En Control
                            </Button>
                            <Button
                              size="sm"
                              onClick={() => handleUpdateStatus(rep.id, 'Attended')}
                              disabled={updatingId === rep.id}
                              className="bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] h-7 px-2.5 rounded-lg font-bold shadow-xs cursor-pointer"
                              title="Marcar como Extinguido / Sofocado"
                            >
                              Sofocar
                            </Button>
                          </div>
                        )}

                        {rep.status === 'Attended' && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleUpdateStatus(rep.id, 'Second_State')}
                            disabled={updatingId === rep.id}
                            className="border-amber-400/50 hover:bg-amber-50 dark:hover:bg-amber-950/30 text-amber-800 dark:text-amber-300 text-[10px] h-7 px-2 rounded-lg font-bold shadow-xs cursor-pointer"
                            title="Reactivar foco en caso de rebrote"
                          >
                            Reactivar
                          </Button>
                        )}

                        {/* Admin Delete Action */}
                        {isAdmin && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setDeleteConfirmId(rep.id)}
                            className="h-8 w-8 p-0 rounded-lg text-rose-500 hover:text-rose-700 hover:bg-rose-50 dark:hover:bg-rose-950/30 cursor-pointer"
                            title="Eliminar registro"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        )}

                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {/* Technical Sheet Detail Modal */}
      <Dialog open={!!detailReport} onOpenChange={() => setDetailReport(null)}>
        <DialogContent className="sm:max-w-xl bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-4">
          {detailReport && (
            <>
              <DialogHeader>
                <div className="flex items-center justify-between">
                  <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200">
                    {detailReport.tracking_code || `ID #${detailReport.id}`}
                  </span>
                  {getSeverityBadge(detailReport.severity_level || detailReport.severity || 'Medio')}
                </div>
                <DialogTitle className="text-xl font-bold text-slate-900 dark:text-white pt-2">
                  {detailReport.incident_type}
                </DialogTitle>
                <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
                  Ficha técnica oficial consolidada en el servidor WACHAY SERNAP.
                </DialogDescription>
              </DialogHeader>

              <div className="grid grid-cols-2 gap-3 text-xs pt-2">
                <div className="p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Estado Actual</span>
                  {getStatusBadge(detailReport.status)}
                </div>

                <div className="p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Origen & Reportante</span>
                  <p className="font-semibold text-slate-900 dark:text-white">
                    {detailReport.ranger_name || detailReport.citizen_name || 'Personal SERNAP'}
                  </p>
                </div>

                <div className="p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Ubicación Satelital</span>
                  <a
                    href={`https://www.google.com/maps/search/?api=1&query=${detailReport.latitude},${detailReport.longitude}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-emerald-600 hover:underline flex items-center gap-1"
                  >
                    <MapPin className="w-3.5 h-3.5" />
                    <span>{detailReport.latitude?.toFixed(4)}, {detailReport.longitude?.toFixed(4)}</span>
                  </a>
                </div>

                <div className="p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Vegetación</span>
                  <p className="font-medium text-slate-800 dark:text-slate-200 flex items-center gap-1">
                    <Trees className="w-3.5 h-3.5 text-emerald-600" />
                    <span>{detailReport.vegetation_type || 'Bosque Seco / Pajonal'}</span>
                  </p>
                </div>
              </div>

              {detailReport.weather_conditions && (
                <div className="p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 text-xs space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Condiciones Meteorológicas</span>
                  <p className="text-slate-700 dark:text-slate-300 font-mono text-[11px]">
                    {detailReport.weather_conditions}
                  </p>
                </div>
              )}

              {detailReport.description && (
                <div className="p-3 rounded-2xl bg-slate-50 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/5 text-xs space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Descripción Detallada</span>
                  <p className="text-slate-700 dark:text-slate-300 italic">
                    "{detailReport.description}"
                  </p>
                </div>
              )}

              <DialogFooter className="pt-2">
                <Button
                  onClick={() => setDetailReport(null)}
                  className="w-full bg-slate-900 dark:bg-white text-white dark:text-slate-950 font-bold rounded-xl text-xs h-10"
                >
                  Cerrar Ficha
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Photo Preview Modal */}
      <Dialog open={!!photoPreview} onOpenChange={() => setPhotoPreview(null)}>
        <DialogContent className="sm:max-w-lg bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 shadow-2xl">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <ImageIcon className="w-5 h-5 text-emerald-600" />
              Evidencia Fotográfica
            </DialogTitle>
          </DialogHeader>

          {photoPreview && (
            <div className="py-2 rounded-2xl overflow-hidden bg-slate-950 flex items-center justify-center">
              <img
                src={`http://localhost:8000/${photoPreview}`}
                alt="Evidencia fotográfica"
                className="max-h-96 w-auto object-contain rounded-xl"
                onError={(e) => {
                  (e.target as HTMLElement).style.display = 'none';
                }}
              />
            </div>
          )}

          <DialogFooter>
            <Button onClick={() => setPhotoPreview(null)} className="rounded-xl text-xs">
              Cerrar
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteConfirmId} onOpenChange={() => setDeleteConfirmId(null)}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 shadow-2xl space-y-3">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-rose-600 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-rose-600" />
              ¿Eliminar Foco de Incidente?
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Esta acción eliminará de forma permanente el registro de la base de datos y de las estadísticas departamentales.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={() => setDeleteConfirmId(null)} className="rounded-xl text-xs">
              Cancelar
            </Button>
            <Button
              onClick={() => deleteConfirmId && handleDeleteReport(deleteConfirmId)}
              className="bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-xl text-xs"
            >
              Confirmar Eliminación
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </div>
  );
};

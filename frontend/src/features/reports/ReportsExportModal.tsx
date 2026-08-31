import React, { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { FileText, Download, Calendar, Filter, FileSpreadsheet, RefreshCw } from 'lucide-react';
import api from '../../services/api';

interface ReportsExportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ReportsExportModal: React.FC<ReportsExportModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [status, setStatus] = useState('all');
  const [incidentType, setIncidentType] = useState('all');
  const [reporterType, setReporterType] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async (format: 'pdf' | 'excel') => {
    setIsExporting(true);
    try {
      const params = new URLSearchParams();
      if (startDate) params.append('start_date', startDate);
      if (endDate) params.append('end_date', endDate);
      if (status !== 'all') params.append('status', status);
      if (incidentType !== 'all') params.append('incident_type', incidentType);
      if (reporterType !== 'all') params.append('reporter_type', reporterType);
      if (severity !== 'all') params.append('severity', severity);

      const endpoint = format === 'pdf' ? `/reports/export/pdf?${params.toString()}` : `/reports/export/excel?${params.toString()}`;
      
      const response = await api.get(endpoint, {
        responseType: 'blob',
      });

      const blob = new Blob([response.data], {
        type: format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      });

      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `reporte_wachay_${new Date().toISOString().slice(0, 10)}.${format === 'pdf' ? 'pdf' : 'xlsx'}`);
      document.body.appendChild(link);
      link.click();
      link.remove();

      onClose();
    } catch (err) {
      console.error('Export error:', err);
      alert('Error al generar la exportación del reporte.');
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl">
        <DialogHeader>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
              <FileText className="w-5 h-5" />
            </div>
            <DialogTitle className="text-lg font-bold text-slate-900 dark:text-white">
              Exportar Reportes Oficiales
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
            Filtre las fechas y criticidad para generar el informe oficial en PDF o Excel.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2 text-xs">
          
          {/* Date range */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Fecha Inicio</Label>
              <Input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl text-xs h-10 text-slate-800 dark:text-slate-200"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Fecha Fin</Label>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl text-xs h-10 text-slate-800 dark:text-slate-200"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Estado del Foco</Label>
              <Select value={status} onValueChange={(val) => val && setStatus(val)}>
                <SelectTrigger className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl text-xs h-10 text-slate-800 dark:text-slate-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
                  <SelectItem value="all">Todos los Estados</SelectItem>
                  <SelectItem value="Second_State">Focos Activos</SelectItem>
                  <SelectItem value="First_State">En Control</SelectItem>
                  <SelectItem value="Attended">Sofocados</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Nivel de Gravedad</Label>
              <Select value={severity} onValueChange={(val) => val && setSeverity(val)}>
                <SelectTrigger className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl text-xs h-10 text-slate-800 dark:text-slate-200">
                  <SelectValue />
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
          </div>

        </div>

        <DialogFooter className="pt-2 flex-col sm:flex-row gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => handleExport('pdf')}
            disabled={isExporting}
            className="w-full sm:w-auto bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800/40 hover:bg-rose-100 font-bold gap-2 text-xs rounded-xl h-10 cursor-pointer"
          >
            {isExporting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            <span>Exportar PDF</span>
          </Button>

          <Button
            type="button"
            onClick={() => handleExport('excel')}
            disabled={isExporting}
            className="w-full sm:w-auto bg-emerald-700 hover:bg-emerald-800 text-white font-bold gap-2 text-xs rounded-xl h-10 cursor-pointer shadow-md"
          >
            {isExporting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FileSpreadsheet className="w-4 h-4" />}
            <span>Exportar Excel (.xlsx)</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

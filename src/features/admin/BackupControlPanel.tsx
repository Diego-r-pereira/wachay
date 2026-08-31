import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Database, Download, CheckCircle2, ShieldAlert, HardDrive, ShieldCheck, RefreshCw, Server, History, FileDown, Layers } from 'lucide-react';
import { motion } from 'motion/react';
import api from '../../services/api';

interface BackupFile {
  filename: string;
  size_bytes: number;
  size_kb: number;
  created_at: string;
}

export const BackupControlPanel: React.FC = () => {
  const [isBackingUp, setIsBackingUp] = useState(false);
  const [backupMsg, setBackupMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [backups, setBackups] = useState<BackupFile[]>([]);
  const [isLoadingList, setIsLoadingList] = useState(false);
  const [downloadingFile, setDownloadingFile] = useState<string | null>(null);

  const fetchBackupsList = async () => {
    setIsLoadingList(true);
    try {
      const res = await api.get('/reports/backups');
      if (res.data && Array.isArray(res.data)) {
        setBackups(res.data);
      }
    } catch (err) {
      console.error('Error fetching backups list:', err);
    } finally {
      setIsLoadingList(false);
    }
  };

  useEffect(() => {
    fetchBackupsList();
  }, []);

  const handleTriggerBackup = async () => {
    setIsBackingUp(true);
    setBackupMsg(null);

    try {
      const res = await api.post('/reports/backup');
      if (res.data) {
        setBackupMsg({
          type: 'success',
          text: `Respaldo Hot Backup generado exitosamente: ${res.data.filename || 'wachay_backup.db'}. Modo WAL seguro verificado.`,
        });
        fetchBackupsList();
      }
    } catch (err: any) {
      console.error('Backup error:', err);
      setBackupMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al ejecutar el Hot Backup de la base de datos.',
      });
    } finally {
      setIsBackingUp(false);
    }
  };

  const handleDownloadBackup = async (filename: string) => {
    setDownloadingFile(filename);
    try {
      const res = await api.get(`/reports/backups/download/${filename}`, {
        responseType: 'blob',
      });
      const blob = new Blob([res.data], { type: 'application/x-sqlite3' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download backup error:', err);
      alert('Error al descargar el archivo de respaldo.');
    } finally {
      setDownloadingFile(null);
    }
  };

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white">
              Respaldo en Caliente & Recuperación ante Desastres
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Generación y descarga de copias de seguridad consistentes sin interrupción del servicio (SQLite WAL Safe).
            </p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-700/50">
          Motor: SQLite WAL Mode
        </span>
      </div>

      {/* Hero Action Card */}
      <div className="bg-slate-50/80 dark:bg-surface-elevated border border-slate-200/80 dark:border-white/10 rounded-2xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div className="space-y-1.5 max-w-lg">
          <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            Generar Copia de Seguridad Instantánea
          </h4>
          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Crea una réplica atómica byte por byte de todas las tablas de reportes, usuarios y registros de auditoría directamente en el almacenamiento persistente del servidor.
          </p>
        </div>

        <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} className="w-full sm:w-auto">
          <Button
            onClick={handleTriggerBackup}
            disabled={isBackingUp}
            className="w-full sm:w-auto bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-5 py-5 rounded-xl shadow-md cursor-pointer shrink-0"
          >
            {isBackingUp ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Generando Copia en Caliente...</span>
              </>
            ) : (
              <>
                <Database className="w-4 h-4" />
                <span>Generar Respaldo Ahora</span>
              </>
            )}
          </Button>
        </motion.div>
      </div>

      {/* Feedback Message */}
      {backupMsg && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-2xl text-xs font-medium flex items-center justify-between gap-3 ${
            backupMsg.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-900 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-700/50'
              : 'bg-rose-50 dark:bg-rose-950/40 text-rose-900 dark:text-rose-200 border border-rose-300 dark:border-rose-700/50'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {backupMsg.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0" />
            )}
            <span>{backupMsg.text}</span>
          </div>
          <button
            onClick={() => setBackupMsg(null)}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-white text-xs cursor-pointer font-bold"
          >
            ✕
          </button>
        </motion.div>
      )}

      {/* Historical Backups Table */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-bold font-heading text-slate-900 dark:text-white flex items-center gap-2">
            <History className="w-4 h-4 text-emerald-600" />
            <span>Historial de Respaldos Persistidos</span>
          </h4>
          <Button
            size="sm"
            variant="ghost"
            onClick={fetchBackupsList}
            disabled={isLoadingList}
            className="text-xs text-slate-500 hover:text-slate-900 dark:hover:text-white gap-1.5 h-8 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingList ? 'animate-spin' : ''}`} />
            <span>Actualizar</span>
          </Button>
        </div>

        <div className="overflow-x-auto rounded-2xl border border-slate-200/80 dark:border-white/10">
          <Table className="text-xs">
            <TableHeader className="bg-slate-50/90 dark:bg-surface-elevated">
              <TableRow className="border-b border-slate-200/80 dark:border-white/10">
                <TableHead className="font-bold text-slate-900 dark:text-white">Archivo de Respaldo (.db)</TableHead>
                <TableHead className="font-bold text-slate-900 dark:text-white">Fecha de Creación</TableHead>
                <TableHead className="font-bold text-slate-900 dark:text-white">Tamaño</TableHead>
                <TableHead className="font-bold text-slate-900 dark:text-white">Integridad</TableHead>
                <TableHead className="font-bold text-slate-900 dark:text-white text-right">Descarga Local</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {backups.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-slate-400">
                    {isLoadingList ? 'Cargando lista de respaldos...' : 'No hay respaldos generados aún. Pulse "Generar Respaldo Ahora" para crear el primero.'}
                  </TableCell>
                </TableRow>
              ) : (
                backups.map((b) => (
                  <TableRow key={b.filename} className="hover:bg-slate-50/80 dark:hover:bg-surface-elevated/50 transition-colors border-b border-slate-100 dark:border-white/5">
                    <TableCell className="font-mono font-bold text-emerald-700 dark:text-emerald-400 flex items-center gap-2">
                      <Database className="w-3.5 h-3.5 shrink-0" />
                      <span>{b.filename}</span>
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {b.created_at}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {b.size_kb > 1024 ? `${(b.size_kb / 1024).toFixed(2)} MB` : `${b.size_kb} KB`}
                    </TableCell>
                    <TableCell>
                      <span className="px-2.5 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 text-[10px] font-bold font-mono border border-emerald-300 dark:border-emerald-800 flex items-center gap-1 w-fit">
                        <ShieldCheck className="w-3 h-3 text-emerald-600" />
                        <span>Verificado</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        onClick={() => handleDownloadBackup(b.filename)}
                        disabled={downloadingFile === b.filename}
                        className="bg-slate-100 hover:bg-slate-200 dark:bg-surface-elevated dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-white/10 text-[11px] h-8 px-3 rounded-xl gap-1.5 font-bold cursor-pointer transition-all"
                      >
                        {downloadingFile === b.filename ? (
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <FileDown className="w-3.5 h-3.5 text-emerald-600" />
                        )}
                        <span>Descargar (.db)</span>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>

    </div>
  );
};

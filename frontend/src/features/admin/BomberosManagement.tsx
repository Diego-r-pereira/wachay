import React, { useState, useEffect } from 'react';
import { Bombero } from '../../types';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Shield, Plus, Trash2, Edit, Phone, MessageSquare, Send, HeartHandshake, PhoneCall, CheckCircle2, ShieldAlert, AlertTriangle, Search } from 'lucide-react';
import { motion } from 'motion/react';
import api from '../../services/api';

export const BomberosManagement: React.FC = () => {
  const [bomberos, setBomberos] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Search & Filter
  const [searchTerm, setSearchTerm] = useState('');
  const [unitFilter, setUnitFilter] = useState('all');

  // Create Modal states
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [whatsapp, setWhatsapp] = useState('');
  const [unit, setUnit] = useState('SAR-Bolivia');
  const [isLeader, setIsLeader] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Edit Modal states
  const [editBombero, setEditBombero] = useState<any | null>(null);
  const [editFirstName, setEditFirstName] = useState('');
  const [editLastName, setEditLastName] = useState('');
  const [editWhatsapp, setEditWhatsapp] = useState('');
  const [editUnit, setEditUnit] = useState('SAR-Bolivia');
  const [editIsLeader, setEditIsLeader] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  // Delete Modal state
  const [deleteConfirmBombero, setDeleteConfirmBombero] = useState<any | null>(null);

  const fetchBomberos = async () => {
    setIsLoading(true);
    try {
      const res = await api.get('/bomberos/');
      if (res.data && Array.isArray(res.data)) {
        setBomberos(res.data);
      }
    } catch (err) {
      console.error('Fetch bomberos error:', err);
      // Fallback
      setBomberos([
        { id: 1, name: 'Carlos', last_name: 'Vargas', whatsapp_number: '59171234567', fire_unit: 'SAR-Bolivia', is_leader: true },
        { id: 2, name: 'Roberto', last_name: 'Gutiérrez', whatsapp_number: '59172345678', fire_unit: 'Bomberos GEOS', is_leader: false },
        { id: 3, name: 'María', last_name: 'Mamani', whatsapp_number: '59173456789', fire_unit: 'UGR Departamental', is_leader: true },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchBomberos();
  }, []);

  const handleCreateBombero = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setFeedbackMsg(null);

    try {
      await api.post('/bomberos/', {
        name: firstName.trim(),
        last_name: lastName.trim(),
        whatsapp_number: whatsapp.trim() || null,
        fire_unit: unit.trim(),
        is_leader: isLeader,
      });

      setFeedbackMsg({ type: 'success', text: `Brigadista ${firstName} ${lastName} registrado exitosamente.` });
      setIsCreateOpen(false);
      resetForm();
      fetchBomberos();
    } catch (err: any) {
      console.error('Create bombero error:', err);
      setFeedbackMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al registrar brigadista.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOpenEdit = (b: any) => {
    setEditBombero(b);
    setEditFirstName(b.name || b.first_name || '');
    setEditLastName(b.last_name || '');
    setEditWhatsapp(b.whatsapp_number || b.whatsapp || '');
    setEditUnit(b.fire_unit || b.unit || 'SAR-Bolivia');
    setEditIsLeader(!!b.is_leader);
  };

  const handleUpdateBombero = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editBombero) return;

    setIsEditing(true);
    setFeedbackMsg(null);

    try {
      await api.put(`/bomberos/${editBombero.id}`, {
        name: editFirstName.trim(),
        last_name: editLastName.trim(),
        whatsapp_number: editWhatsapp.trim() || null,
        fire_unit: editUnit.trim(),
        is_leader: editIsLeader,
      });

      setFeedbackMsg({ type: 'success', text: `Datos del brigadista actualizados con éxito.` });
      setEditBombero(null);
      fetchBomberos();
    } catch (err: any) {
      console.error('Update bombero error:', err);
      setFeedbackMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al actualizar brigadista.',
      });
    } finally {
      setIsEditing(false);
    }
  };

  const handleDeleteBombero = async (id: number) => {
    try {
      await api.delete(`/bomberos/${id}`);
      setFeedbackMsg({ type: 'success', text: 'Brigadista removido de la lista de despacho.' });
      setDeleteConfirmBombero(null);
      fetchBomberos();
    } catch (err: any) {
      console.error('Delete bombero error:', err);
      setFeedbackMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al eliminar brigadista.',
      });
    }
  };

  const handleSendWhatsAppNotice = (phone: string, name: string) => {
    const text = encodeURIComponent(`🚨 WACHAY - ALERTA OPERATIVA 🚨\nHola ${name}, desde el Centro de Mando SERNAP notificamos activación de foco de calor en el Parque Nacional Tunari. Por favor revisar coordenadas en el portal oficial.`);
    window.open(`https://wa.me/${phone}?text=${text}`, '_blank');
  };

  const resetForm = () => {
    setFirstName('');
    setLastName('');
    setWhatsapp('');
    setUnit('SAR-Bolivia');
    setIsLeader(false);
  };

  const filteredBomberos = bomberos.filter((b) => {
    const nameStr = `${b.name || b.first_name || ''} ${b.last_name || ''}`.toLowerCase();
    const matchesSearch = nameStr.includes(searchTerm.toLowerCase()) || (b.whatsapp_number || b.whatsapp || '').includes(searchTerm);
    const matchesUnit = unitFilter === 'all' || (b.fire_unit || b.unit) === unitFilter;
    return matchesSearch && matchesUnit;
  });

  const uniqueUnits = Array.from(new Set(bomberos.map((b) => b.fire_unit || b.unit).filter(Boolean)));

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-rose-500/15 text-rose-600 dark:text-rose-400">
            <HeartHandshake className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white">
              Directorio de Brigadas de Bomberos & Despacho
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Red de combate contra incendios: SAR-Bolivia, GEOS, FERO, UGR y Bomberos Policía.
            </p>
          </div>
        </div>

        <Button
          onClick={() => setIsCreateOpen(true)}
          className="bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs gap-2 px-4 py-2.5 rounded-xl shadow-md cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>Agregar Brigadista</span>
        </Button>
      </div>

      {/* Feedback Banner */}
      {feedbackMsg && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className={`p-4 rounded-2xl text-xs font-medium flex items-center justify-between gap-3 ${
            feedbackMsg.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-900 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-800'
              : 'bg-rose-50 dark:bg-rose-950/40 text-rose-900 dark:text-rose-200 border border-rose-300 dark:border-rose-800'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedbackMsg.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
            )}
            <span>{feedbackMsg.text}</span>
          </div>
          <button
            onClick={() => setFeedbackMsg(null)}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-white text-xs cursor-pointer font-bold"
          >
            ✕
          </button>
        </motion.div>
      )}

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <Input
            placeholder="Buscar por nombre o teléfono..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 text-xs bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10"
          />
        </div>

        <Select value={unitFilter} onValueChange={(val) => val && setUnitFilter(val)}>
          <SelectTrigger className="w-44 text-xs bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-slate-800 dark:text-slate-200">
            <SelectValue placeholder="Filtrar por Brigada" />
          </SelectTrigger>
          <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
            <SelectItem value="all">Todas las Brigadas</SelectItem>
            {uniqueUnits.map((u) => (
              <SelectItem key={u} value={u}>
                {u}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-2xl border border-slate-200/80 dark:border-white/10">
        <Table className="text-xs">
          <TableHeader className="bg-slate-50/90 dark:bg-surface-elevated">
            <TableRow className="border-b border-slate-200/80 dark:border-white/10">
              <TableHead className="font-bold text-slate-900 dark:text-white">Nombre Completo</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Unidad / Brigada</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">WhatsApp Oficial</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Rango / Jerarquía</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Despacho Inmediato</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white text-right">Acciones</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredBomberos.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-10 text-slate-400">
                  {isLoading ? 'Cargando directorio de bomberos...' : 'No se encontraron brigadistas registrados con los filtros seleccionados.'}
                </TableCell>
              </TableRow>
            ) : (
              filteredBomberos.map((b) => {
                const fullName = `${b.name || b.first_name || ''} ${b.last_name || ''}`.trim();
                const unitName = b.fire_unit || b.unit || 'SAR-Bolivia';
                const phone = b.whatsapp_number || b.whatsapp || '';

                return (
                  <TableRow key={b.id} className="hover:bg-slate-50/80 dark:hover:bg-surface-elevated/50 transition-colors border-b border-slate-100 dark:border-white/5">
                    <TableCell className="font-bold text-slate-900 dark:text-white">
                      {fullName}
                    </TableCell>
                    <TableCell className="font-medium text-emerald-700 dark:text-emerald-400 font-mono">
                      {unitName}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {phone || '-'}
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase font-mono ${
                          b.is_leader
                            ? 'bg-rose-100 text-rose-900 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-300 dark:border-rose-800'
                            : 'bg-emerald-100 text-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                        }`}
                      >
                        {b.is_leader ? 'Jefe de Brigada' : 'Combatiente'}
                      </span>
                    </TableCell>
                    <TableCell>
                      {phone ? (
                        <Button
                          size="sm"
                          onClick={() => handleSendWhatsAppNotice(phone, fullName)}
                          className="bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] h-8 px-3 rounded-xl gap-1.5 font-bold shadow-xs cursor-pointer"
                        >
                          <Send className="w-3.5 h-3.5" />
                          <span>WhatsApp Alerta</span>
                        </Button>
                      ) : (
                        <span className="text-[11px] text-slate-400 italic">Sin WhatsApp</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        
                        {/* Edit Button */}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleOpenEdit(b)}
                          className="h-8 w-8 p-0 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-surface-elevated cursor-pointer"
                          title="Editar brigadista"
                        >
                          <Edit className="w-3.5 h-3.5" />
                        </Button>

                        {/* Delete Button */}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setDeleteConfirmBombero(b)}
                          className="h-8 w-8 p-0 rounded-lg text-rose-500 hover:text-rose-700 hover:bg-rose-50 dark:hover:bg-rose-950/30 cursor-pointer"
                          title="Eliminar brigadista"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
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

      {/* Add Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-4">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Plus className="w-5 h-5 text-rose-600" />
              Agregar Brigadista / Bombero Voluntario
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Registre los datos para el despacho directo de coordenadas satelitales vía WhatsApp.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateBombero} className="space-y-4 py-1 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Nombre</Label>
                <Input
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  required
                  placeholder="Ej. Carlos"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Apellido</Label>
                <Input
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  required
                  placeholder="Ej. Vargas"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Unidad / Brigada</Label>
                <Input
                  value={unit}
                  onChange={(e) => setUnit(e.target.value)}
                  placeholder="Ej. SAR-Bolivia, GEOS, FERO"
                  required
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">WhatsApp (591...)</Label>
                <Input
                  value={whatsapp}
                  onChange={(e) => setWhatsapp(e.target.value)}
                  placeholder="59171234567"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 pt-1">
              <input
                type="checkbox"
                id="isLeader"
                checked={isLeader}
                onChange={(e) => setIsLeader(e.target.checked)}
                className="w-4 h-4 text-rose-600 border-gray-300 rounded cursor-pointer"
              />
              <Label htmlFor="isLeader" className="text-xs font-semibold cursor-pointer text-slate-700 dark:text-slate-300">
                Asignar como Jefe de Brigada (Recibe alertas automáticas prioritarias)
              </Label>
            </div>

            <DialogFooter className="pt-3 gap-2 sm:gap-0">
              <Button type="button" variant="outline" onClick={() => setIsCreateOpen(false)} className="rounded-xl text-xs">
                Cancelar
              </Button>
              <Button type="submit" disabled={isSubmitting} className="bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-xl text-xs">
                {isSubmitting ? 'Guardando...' : 'Guardar Contacto'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editBombero} onOpenChange={() => setEditBombero(null)}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-4">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Edit className="w-5 h-5 text-emerald-600" />
              Editar Datos del Brigadista
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Actualice el número de teléfono, unidad o rango de comando.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleUpdateBombero} className="space-y-4 py-1 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Nombre</Label>
                <Input
                  value={editFirstName}
                  onChange={(e) => setEditFirstName(e.target.value)}
                  required
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Apellido</Label>
                <Input
                  value={editLastName}
                  onChange={(e) => setEditLastName(e.target.value)}
                  required
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Unidad / Brigada</Label>
                <Input
                  value={editUnit}
                  onChange={(e) => setEditUnit(e.target.value)}
                  required
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">WhatsApp</Label>
                <Input
                  value={editWhatsapp}
                  onChange={(e) => setEditWhatsapp(e.target.value)}
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 pt-1">
              <input
                type="checkbox"
                id="editIsLeader"
                checked={editIsLeader}
                onChange={(e) => setEditIsLeader(e.target.checked)}
                className="w-4 h-4 text-rose-600 border-gray-300 rounded cursor-pointer"
              />
              <Label htmlFor="editIsLeader" className="text-xs font-semibold cursor-pointer text-slate-700 dark:text-slate-300">
                Asignar como Jefe de Brigada (Notificación Prioritaria)
              </Label>
            </div>

            <DialogFooter className="pt-3 gap-2 sm:gap-0">
              <Button type="button" variant="outline" onClick={() => setEditBombero(null)} className="rounded-xl text-xs">
                Cancelar
              </Button>
              <Button type="submit" disabled={isEditing} className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold rounded-xl text-xs">
                {isEditing ? 'Guardando...' : 'Guardar Cambios'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteConfirmBombero} onOpenChange={() => setDeleteConfirmBombero(null)}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 shadow-2xl space-y-3">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-rose-600 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-rose-600" />
              ¿Eliminar Brigadista del Directorio?
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Se removerá a <strong className="text-slate-900 dark:text-white">{deleteConfirmBombero?.name} {deleteConfirmBombero?.last_name}</strong> ({deleteConfirmBombero?.fire_unit || deleteConfirmBombero?.unit}) de las listas de notificación.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={() => setDeleteConfirmBombero(null)} className="rounded-xl text-xs">
              Cancelar
            </Button>
            <Button
              onClick={() => deleteConfirmBombero && handleDeleteBombero(deleteConfirmBombero.id)}
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

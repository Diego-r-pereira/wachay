import React, { useState, useEffect } from 'react';
import { User } from '../../types';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Users, UserPlus, Edit, Trash2, Shield, Phone, MessageSquare, KeyRound, CheckCircle2, ShieldAlert, Lock, AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import api from '../../services/api';

export const UserManagement: React.FC = () => {
  const [users, setUsers] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Create Modal states
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [role, setRole] = useState<'admin' | 'ranger'>('ranger');
  const [whatsapp, setWhatsapp] = useState('');
  const [telegramId, setTelegramId] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Edit Modal states
  const [editUser, setEditUser] = useState<any | null>(null);
  const [editFirstName, setEditFirstName] = useState('');
  const [editLastName, setEditLastName] = useState('');
  const [editRole, setEditRole] = useState<'admin' | 'ranger'>('ranger');
  const [editWhatsapp, setEditWhatsapp] = useState('');
  const [editTelegramId, setEditTelegramId] = useState('');
  const [editNewPassword, setEditNewPassword] = useState('');
  const [isEditing, setIsEditing] = useState(false);

  // Delete Modal state
  const [deleteConfirmUser, setDeleteConfirmUser] = useState<any | null>(null);

  const fetchUsers = async () => {
    setIsLoading(true);
    try {
      const res = await api.get('/auth/users');
      if (res.data && Array.isArray(res.data)) {
        setUsers(res.data);
      }
    } catch (err) {
      console.error('Fetch users error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setFeedbackMsg(null);

    try {
      await api.post('/auth/users', {
        username,
        password,
        name: firstName,
        last_name: lastName,
        role,
        whatsapp_number: whatsapp || null,
        telegram_id: telegramId || null,
      });

      setFeedbackMsg({ type: 'success', text: `Usuario @${username} registrado exitosamente.` });
      setIsCreateOpen(false);
      resetForm();
      fetchUsers();
    } catch (err: any) {
      console.error('Create user error:', err);
      setFeedbackMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al registrar usuario.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOpenEdit = (u: any) => {
    setEditUser(u);
    setEditFirstName(u.name || u.first_name || '');
    setEditLastName(u.last_name || '');
    setEditRole(u.role || 'ranger');
    setEditWhatsapp(u.whatsapp_number || u.whatsapp || '');
    setEditTelegramId(u.telegram_id || '');
    setEditNewPassword('');
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editUser) return;

    setIsEditing(true);
    setFeedbackMsg(null);

    try {
      const payload: any = {
        name: editFirstName,
        last_name: editLastName,
        role: editRole,
        whatsapp_number: editWhatsapp || null,
        telegram_id: editTelegramId || null,
      };

      if (editNewPassword.trim()) {
        payload.password = editNewPassword;
      }

      await api.put(`/auth/users/${editUser.id}`, payload);

      setFeedbackMsg({ type: 'success', text: `Personal @${editUser.username} actualizado correctamente.` });
      setEditUser(null);
      fetchUsers();
    } catch (err: any) {
      console.error('Update user error:', err);
      setFeedbackMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al actualizar usuario.',
      });
    } finally {
      setIsEditing(false);
    }
  };

  const handleDeleteUser = async (userId: number) => {
    try {
      await api.delete(`/auth/users/${userId}`);
      setFeedbackMsg({ type: 'success', text: 'Usuario eliminado del personal.' });
      setDeleteConfirmUser(null);
      fetchUsers();
    } catch (err: any) {
      console.error('Delete user error:', err);
      setFeedbackMsg({
        type: 'error',
        text: err.response?.data?.detail || 'Error al eliminar usuario.',
      });
    }
  };

  const resetForm = () => {
    setUsername('');
    setPassword('');
    setFirstName('');
    setLastName('');
    setRole('ranger');
    setWhatsapp('');
    setTelegramId('');
  };

  return (
    <div className="bg-white/95 dark:bg-surface-dark/95 backdrop-blur-xl border border-slate-200/90 dark:border-white/[0.08] rounded-3xl p-6 sm:p-8 shadow-xl space-y-6 ring-1 ring-black/5 dark:ring-white/[0.08]">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-white/[0.08] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-2xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold font-heading text-slate-900 dark:text-white">
              Gestión de Personal & Roles SERNAP
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Administración de cuentas, niveles de acceso y números de notificación operativa.
            </p>
          </div>
        </div>

        <Button
          onClick={() => setIsCreateOpen(true)}
          className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold text-xs gap-2 px-4 py-2.5 rounded-xl shadow-md cursor-pointer"
        >
          <UserPlus className="w-4 h-4" />
          <span>Registrar Nuevo Personal</span>
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

      {/* Table */}
      <div className="overflow-x-auto rounded-2xl border border-slate-200/80 dark:border-white/10">
        <Table className="text-xs">
          <TableHeader className="bg-slate-50/90 dark:bg-surface-elevated">
            <TableRow className="border-b border-slate-200/80 dark:border-white/10">
              <TableHead className="font-bold text-slate-900 dark:text-white">Usuario</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Nombre Completo</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Rol Asignado</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">WhatsApp Oficial</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white">Telegram ID</TableHead>
              <TableHead className="font-bold text-slate-900 dark:text-white text-right">Acciones</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-10 text-slate-400">
                  {isLoading ? 'Cargando personal registrado...' : 'No hay usuarios registrados.'}
                </TableCell>
              </TableRow>
            ) : (
              users.map((u) => {
                const fullName = `${u.name || u.first_name || ''} ${u.last_name || ''}`.trim() || 'Sin nombre';
                const whatsappDisplay = u.whatsapp_number || u.whatsapp || '-';
                const isDefaultAdmin = u.username === 'admin';

                return (
                  <TableRow key={u.id} className="hover:bg-slate-50/80 dark:hover:bg-surface-elevated/50 transition-colors border-b border-slate-100 dark:border-white/5">
                    <TableCell className="font-mono font-bold text-emerald-700 dark:text-emerald-400">
                      @{u.username}
                    </TableCell>
                    <TableCell className="font-medium text-slate-900 dark:text-white">
                      {fullName}
                    </TableCell>
                    <TableCell>
                      <span
                        className={`px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase font-mono ${
                          u.role === 'admin'
                            ? 'bg-purple-100 text-purple-900 dark:bg-purple-950/60 dark:text-purple-300 border border-purple-300 dark:border-purple-800'
                            : 'bg-emerald-100 text-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                        }`}
                      >
                        {u.role === 'admin' ? 'Administrador' : 'Guardaparques'}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {whatsappDisplay}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {u.telegram_id || '-'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        
                        {/* Edit Button */}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleOpenEdit(u)}
                          className="h-8 w-8 p-0 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-surface-elevated cursor-pointer"
                          title="Editar datos del personal"
                        >
                          <Edit className="w-3.5 h-3.5" />
                        </Button>

                        {/* Delete Button */}
                        {!isDefaultAdmin && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setDeleteConfirmUser(u)}
                            className="h-8 w-8 p-0 rounded-lg text-rose-500 hover:text-rose-700 hover:bg-rose-50 dark:hover:bg-rose-950/30 cursor-pointer"
                            title="Eliminar usuario"
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

      {/* Create User Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-4">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              Registrar Nuevo Personal SERNAP
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Complete los datos del funcionario o combatiente para otorgar acceso al sistema.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateUser} className="space-y-4 py-1 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Nombre</Label>
                <Input
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  required
                  placeholder="Ej. Rodrigo"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Apellido</Label>
                <Input
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  required
                  placeholder="Ej. Rojas"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Usuario</Label>
                <Input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  placeholder="Ej. rrojas"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Contraseña</Label>
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Rol Operativo</Label>
              <Select value={role} onValueChange={(val) => val && setRole(val as 'admin' | 'ranger')}>
                <SelectTrigger className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs text-slate-800 dark:text-slate-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
                  <SelectItem value="ranger">Guardaparques</SelectItem>
                  <SelectItem value="admin">Administrador SERNAP</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">WhatsApp (591...)</Label>
                <Input
                  value={whatsapp}
                  onChange={(e) => setWhatsapp(e.target.value)}
                  placeholder="59171234567"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Telegram Chat ID</Label>
                <Input
                  value={telegramId}
                  onChange={(e) => setTelegramId(e.target.value)}
                  placeholder="123456789"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <DialogFooter className="pt-3 gap-2 sm:gap-0">
              <Button type="button" variant="outline" onClick={() => setIsCreateOpen(false)} className="rounded-xl text-xs">
                Cancelar
              </Button>
              <Button type="submit" disabled={isSubmitting} className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold rounded-xl text-xs">
                {isSubmitting ? 'Registrando...' : 'Guardar Personal'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={!!editUser} onOpenChange={() => setEditUser(null)}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-4">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Edit className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              Editar Personal @{editUser?.username}
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Actualice los datos o reasigne roles y canales de notificación.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleUpdateUser} className="space-y-4 py-1 text-xs">
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

            <div className="space-y-1.5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Rol Operativo</Label>
              <Select value={editRole} onValueChange={(val) => val && setEditRole(val as 'admin' | 'ranger')}>
                <SelectTrigger className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs text-slate-800 dark:text-slate-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-white dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl">
                  <SelectItem value="ranger">Guardaparques</SelectItem>
                  <SelectItem value="admin">Administrador SERNAP</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">WhatsApp</Label>
                <Input
                  value={editWhatsapp}
                  onChange={(e) => setEditWhatsapp(e.target.value)}
                  placeholder="59171234567"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-bold text-slate-700 dark:text-slate-300">Telegram Chat ID</Label>
                <Input
                  value={editTelegramId}
                  onChange={(e) => setEditTelegramId(e.target.value)}
                  placeholder="123456789"
                  className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
                />
              </div>
            </div>

            <div className="space-y-1.5 pt-1 border-t border-slate-200/60 dark:border-white/5">
              <Label className="text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-400" />
                <span>Nueva Contraseña (Opcional)</span>
              </Label>
              <Input
                type="password"
                value={editNewPassword}
                onChange={(e) => setEditNewPassword(e.target.value)}
                placeholder="Dejar en blanco para mantener la actual"
                className="bg-slate-50 dark:bg-surface-elevated border-slate-200 dark:border-white/10 rounded-xl h-10 text-xs"
              />
            </div>

            <DialogFooter className="pt-3 gap-2 sm:gap-0">
              <Button type="button" variant="outline" onClick={() => setEditUser(null)} className="rounded-xl text-xs">
                Cancelar
              </Button>
              <Button type="submit" disabled={isEditing} className="bg-emerald-700 hover:bg-emerald-800 text-white font-bold rounded-xl text-xs">
                {isEditing ? 'Guardando Cambios...' : 'Guardar Cambios'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete User Confirmation Dialog */}
      <Dialog open={!!deleteConfirmUser} onOpenChange={() => setDeleteConfirmUser(null)}>
        <DialogContent className="sm:max-w-md bg-white dark:bg-surface-dark border border-slate-200 dark:border-white/10 rounded-3xl p-6 shadow-2xl space-y-3">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-rose-600 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-rose-600" />
              ¿Eliminar Acceso al Personal?
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Se revocará el acceso al sistema para el usuario <strong className="text-slate-900 dark:text-white">@{deleteConfirmUser?.username}</strong> ({deleteConfirmUser?.name} {deleteConfirmUser?.last_name}).
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={() => setDeleteConfirmUser(null)} className="rounded-xl text-xs">
              Cancelar
            </Button>
            <Button
              onClick={() => deleteConfirmUser && handleDeleteUser(deleteConfirmUser.id)}
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

import React, { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Flame, Upload, MapPin, CheckCircle2, ShieldAlert, Camera } from 'lucide-react';
import api from '../../services/api';

interface CitizenReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (trackingCode: string) => void;
}

export const CitizenReportModal: React.FC<CitizenReportModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [citizenName, setCitizenName] = useState('');
  const [citizenEmail, setCitizenEmail] = useState('');
  const [citizenDesc, setCitizenDesc] = useState('');
  const [latitude, setLatitude] = useState<number>(-17.3935);
  const [longitude, setLongitude] = useState<number>(-66.157);
  const [incidentType, setIncidentType] = useState('Incendio Forestal');
  const [severity, setSeverity] = useState('Medio');
  const [probableCause, setProbableCause] = useState('Quema Agrícola');
  const [vegetationType, setVegetationType] = useState('Bosque Seco');
  const [photoBase64, setPhotoBase64] = useState<string>('');
  
  const [isLocating, setIsLocating] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleGetCurrentGps = () => {
    if (!navigator.geolocation) {
      setErrorMsg('Geolocalización no soportada en este navegador.');
      return;
    }
    setIsLocating(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLatitude(pos.coords.latitude);
        setLongitude(pos.coords.longitude);
        setIsLocating(false);
      },
      (err) => {
        console.error(err);
        setErrorMsg('No se pudo obtener la posición GPS actual.');
        setIsLocating(false);
      }
    );
  };

  const handlePhotoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onloadend = () => {
      setPhotoBase64(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMsg('');

    try {
      const payload = {
        citizen_name: citizenName || 'Ciudadano Anónimo',
        citizen_email: citizenEmail || undefined,
        photo: photoBase64 || undefined,
        incident_type: incidentType,
        severity_level: severity,
        detection_time: new Date().toISOString(),
        probable_cause: probableCause,
        vegetation_type: vegetationType,
        latitude: latitude,
        longitude: longitude,
        description: citizenDesc,
      };

      const res = await api.post('/mobile/register_report', payload);

      if (res.data && res.data.tracking_code) {
        onSuccess(res.data.tracking_code);
        onClose();
        // Reset form
        setCitizenName('');
        setCitizenEmail('');
        setCitizenDesc('');
        setPhotoBase64('');
      } else {
        setErrorMsg('Error al generar el reporte.');
      }
    } catch (err: any) {
      console.error('Citizen report submit error:', err);
      setErrorMsg(err.response?.data?.detail || 'No se pudo enviar el reporte. Verifique su conexión.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto bg-[#fbfbf9] dark:bg-[#1c2c22] border-[#3f644e]/30">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Flame className="w-6 h-6 text-rose-600 animate-pulse" />
            <DialogTitle className="text-xl font-bold text-[#203126] dark:text-[#fbfbf9]">
              Reporte Ciudadano de Incendio
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#77877c]">
            Complete la información para notificar inmediatamente a las brigadas de guardaparques del SERNAP.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4 py-2">
          {errorMsg && (
            <div className="p-3 text-xs bg-rose-100 text-rose-800 rounded-lg flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Contact Details */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Nombre Completo (Opcional)</Label>
              <Input
                placeholder="Ej. Juan Pérez"
                value={citizenName}
                onChange={(e) => setCitizenName(e.target.value)}
                className="bg-white dark:bg-slate-900 border-[#e9e8e5]"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Correo Electrónico (Opcional)</Label>
              <Input
                type="email"
                placeholder="juan@ejemplo.com"
                value={citizenEmail}
                onChange={(e) => setCitizenEmail(e.target.value)}
                className="bg-white dark:bg-slate-900 border-[#e9e8e5]"
              />
            </div>
          </div>

          {/* Incident Type & Severity */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Tipo de Incidente</Label>
              <Select value={incidentType} onValueChange={(val) => val && setIncidentType(val)}>
                <SelectTrigger className="bg-white dark:bg-slate-900">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Incendio Forestal">Incendio Forestal</SelectItem>
                  <SelectItem value="Quema Descontrolada">Quema Descontrolada (Chaqueo)</SelectItem>
                  <SelectItem value="Foco de Calor">Foco de Calor Sospechoso</SelectItem>
                  <SelectItem value="Conflagración Estructural">Conflagración en Interfaz</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1">
              <Label className="text-xs">Nivel de Gravedad</Label>
              <Select value={severity} onValueChange={(val) => val && setSeverity(val)}>
                <SelectTrigger className="bg-white dark:bg-slate-900">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Bajo">Bajo (Humo leve)</SelectItem>
                  <SelectItem value="Medio">Medio (Llamas visibles &lt; 2m)</SelectItem>
                  <SelectItem value="Alto">Alto (Propagación rápida)</SelectItem>
                  <SelectItem value="Crítico">Crítico (Riesgo a viviendas/bosque)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Vegetation & Cause */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">Causa Probable</Label>
              <Select value={probableCause} onValueChange={(val) => val && setProbableCause(val)}>
                <SelectTrigger className="bg-white dark:bg-slate-900">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Quema Agrícola">Quema Agrícola / Chaqueo</SelectItem>
                  <SelectItem value="Negligencia">Negligencia / Fogata</SelectItem>
                  <SelectItem value="Intencional">Intencional</SelectItem>
                  <SelectItem value="Desconocido">Desconocido</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1">
              <Label className="text-xs">Tipo de Vegetación</Label>
              <Select value={vegetationType} onValueChange={(val) => val && setVegetationType(val)}>
                <SelectTrigger className="bg-white dark:bg-slate-900">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Bosque Seco">Bosque Seco / Nativo</SelectItem>
                  <SelectItem value="Pastizal">Pastizal / Pajonal</SelectItem>
                  <SelectItem value="Pinar">Pinar / Eucaliptal</SelectItem>
                  <SelectItem value="Matorral">Matorral Arbustivo</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Location GPS */}
          <div className="space-y-1.5 p-3 rounded-xl bg-white dark:bg-slate-900 border border-[#e9e8e5]">
            <div className="flex items-center justify-between">
              <Label className="text-xs font-bold text-[#203126] dark:text-white flex items-center gap-1.5">
                <MapPin className="w-4 h-4 text-rose-600" /> Coordenadas de Ubicación
              </Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleGetCurrentGps}
                disabled={isLocating}
                className="text-xs text-[#3f644e] border-[#3f644e]/30"
              >
                {isLocating ? 'Obteniendo GPS...' : 'Obtener GPS Actual'}
              </Button>
            </div>

            <div className="grid grid-cols-2 gap-2 font-mono text-xs pt-1">
              <div>
                <span className="text-[#77877c]">Latitud:</span>
                <Input
                  type="number"
                  step="any"
                  value={latitude}
                  onChange={(e) => setLatitude(parseFloat(e.target.value))}
                  className="mt-0.5 bg-gray-50 dark:bg-slate-800"
                />
              </div>
              <div>
                <span className="text-[#77877c]">Longitud:</span>
                <Input
                  type="number"
                  step="any"
                  value={longitude}
                  onChange={(e) => setLongitude(parseFloat(e.target.value))}
                  className="mt-0.5 bg-gray-50 dark:bg-slate-800"
                />
              </div>
            </div>
          </div>

          {/* Description */}
          <div className="space-y-1">
            <Label className="text-xs">Descripción de la Emergencia</Label>
            <textarea
              rows={3}
              placeholder="Describa el estado del fuego, viento o puntos de referencia..."
              value={citizenDesc}
              onChange={(e) => setCitizenDesc(e.target.value)}
              className="w-full p-2.5 rounded-lg text-xs bg-white dark:bg-slate-900 border border-[#e9e8e5] dark:border-slate-800 focus:ring-2 focus:ring-[#3f644e]"
            />
          </div>

          {/* Photo Upload */}
          <div className="space-y-1">
            <Label className="text-xs flex items-center gap-1.5">
              <Camera className="w-4 h-4 text-[#3f644e]" /> Fotografía del Fuego (Opcional)
            </Label>
            <Input
              type="file"
              accept="image/*"
              onChange={handlePhotoUpload}
              className="text-xs bg-white dark:bg-slate-900"
            />
            {photoBase64 && (
              <div className="mt-2 relative w-24 h-24 rounded-lg overflow-hidden border border-[#3f644e]">
                <img src={photoBase64} alt="Preview" className="w-full h-full object-cover" />
              </div>
            )}
          </div>

          <DialogFooter className="pt-3">
            <Button type="button" variant="outline" onClick={onClose} className="w-full sm:w-auto">
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={isSubmitting}
              className="w-full sm:w-auto bg-rose-600 hover:bg-rose-700 text-white font-bold"
            >
              {isSubmitting ? 'Enviando Alerta...' : 'Enviar Alerta de Incendio'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

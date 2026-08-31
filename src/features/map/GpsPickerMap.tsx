import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { BaseMapContainer } from './BaseMapContainer';
import { IncidentReport } from '../../types';
import { Navigation, Crosshair } from 'lucide-react';

interface GpsPickerMapProps {
  selectedLocation?: { lat: number; lng: number } | null;
  onSelectLocation: (lat: number, lng: number) => void;
  existingReports?: IncidentReport[];
  height?: string;
  showExistingFires?: boolean;
}

export const GpsPickerMap: React.FC<GpsPickerMapProps> = ({
  selectedLocation,
  onSelectLocation,
  existingReports = [],
  height = '420px',
  showExistingFires = true,
}) => {
  const [map, setMap] = useState<L.Map | null>(null);
  const pickerMarkerRef = useRef<L.Marker | null>(null);
  const backgroundFiresGroupRef = useRef<L.LayerGroup | null>(null);
  const [isLocating, setIsLocating] = useState(false);

  // Ref to always hold the latest callback
  const onSelectLocationRef = useRef(onSelectLocation);
  useEffect(() => {
    onSelectLocationRef.current = onSelectLocation;
  }, [onSelectLocation]);

  // Custom GPS Selection Pin with Radar Ripple
  const createLocationPinIcon = () => {
    return L.divIcon({
      className: 'custom-location-pin-marker !bg-transparent !border-0',
      html: `
        <div style="position: relative; width: 36px; height: 46px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; cursor: grab; overflow: visible;">
          <!-- Radar Pulse Dot at Anchor Base -->
          <span style="position: absolute; bottom: -2px; left: 50%; transform: translateX(-50%); width: 24px; height: 24px; border-radius: 50%; background: rgba(16, 185, 129, 0.5); animation: ping 1.4s cubic-bezier(0, 0, 0.2, 1) infinite; pointer-events: none;"></span>
          <span style="position: absolute; bottom: 0px; left: 50%; transform: translateX(-50%); width: 8px; height: 8px; border-radius: 50%; background: #34d399; box-shadow: 0 0 12px #10b981; pointer-events: none;"></span>
          
          <!-- Glowing Location Pin Body -->
          <div style="width: 36px; height: 36px; border-radius: 12px; background: linear-gradient(135deg, #10b981 0%, #047857 100%); display: flex; align-items: center; justify-content: center; color: #ffffff; box-shadow: 0 4px 20px rgba(16,185,129,0.9); border: 2.5px solid #ffffff; z-index: 2;">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/>
              <circle cx="12" cy="10" r="3" fill="currentColor"/>
            </svg>
          </div>
          
          <!-- Pointer Tip Accent -->
          <div style="width: 10px; height: 10px; background: #047857; transform: rotate(45deg); margin-top: -5px; border-right: 2.5px solid #ffffff; border-bottom: 2.5px solid #ffffff; z-index: 1;"></div>
        </div>
      `,
      iconSize: [36, 46],
      iconAnchor: [18, 44],
      popupAnchor: [0, -48],
    });
  };

  // Background fire icon (Subtle low-opacity to avoid visual clutter)
  const createSubtleFireIcon = (status: string) => {
    const isAttended = status === 'Attended';
    const color = isAttended ? '#059669' : '#e11d48';

    return L.divIcon({
      className: 'custom-subtle-fire !bg-transparent !border-0',
      html: `
        <div style="width: 14px; height: 14px; border-radius: 50%; background: ${color}; opacity: 0.65; border: 1.5px solid white; box-shadow: 0 0 8px ${color};"></div>
      `,
      iconSize: [14, 14],
      iconAnchor: [7, 7],
    });
  };

  const handleMapReady = (mapInstance: L.Map) => {
    // Attach layer groups
    const bgGroup = L.layerGroup().addTo(mapInstance);
    backgroundFiresGroupRef.current = bgGroup;

    // Global Click Handler for coordinate picking
    mapInstance.on('click', (e: L.LeafletMouseEvent) => {
      if (onSelectLocationRef.current) {
        onSelectLocationRef.current(e.latlng.lat, e.latlng.lng);
      }
    });

    setMap(mapInstance);
  };

  // Capture device GPS directly
  const handleGetGps = () => {
    if (!navigator.geolocation) return;
    setIsLocating(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const lat = pos.coords.latitude;
        const lng = pos.coords.longitude;
        if (onSelectLocationRef.current) {
          onSelectLocationRef.current(lat, lng);
        }
        setIsLocating(false);
      },
      (err) => {
        console.error('GPS error:', err);
        setIsLocating(false);
      },
      { enableHighAccuracy: true, timeout: 8000 }
    );
  };

  // Render Background Fires (Contextual Reference)
  useEffect(() => {
    if (!map || !backgroundFiresGroupRef.current || !showExistingFires) return;
    backgroundFiresGroupRef.current.clearLayers();

    existingReports.forEach((rep) => {
      if (!rep.latitude || !rep.longitude) return;
      const marker = L.marker([rep.latitude, rep.longitude], {
        icon: createSubtleFireIcon(rep.status),
      });

      marker.bindPopup(`
        <div style="font-family: system-ui, sans-serif; font-size: 11px; padding: 2px;">
          <strong style="color: #ffffff;">Foco #${rep.id} (${rep.incident_type})</strong><br/>
          <span style="color: #94a3b8;">Estado: ${rep.status === 'Attended' ? 'Sofocado' : 'Activo'}</span>
        </div>
      `, { className: 'custom-leaflet-glass-popup' });

      backgroundFiresGroupRef.current?.addLayer(marker);
    });
  }, [map, existingReports, showExistingFires]);

  // Reactive Selected Location Pin Effect (Runs as soon as map is ready and selectedLocation changes)
  useEffect(() => {
    if (!map) return;

    map.invalidateSize();

    if (selectedLocation && typeof selectedLocation.lat === 'number' && typeof selectedLocation.lng === 'number') {
      const lat = selectedLocation.lat;
      const lng = selectedLocation.lng;

      const pickerPopupHtml = `
        <div style="font-family: system-ui, -apple-system, sans-serif; padding: 6px 10px; text-align: center; min-width: 190px; color: #ffffff;">
          <div style="display: flex; align-items: center; justify-content: center; gap: 5px; color: #34d399; font-weight: 800; font-size: 12px; margin-bottom: 4px;">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>
            <span>Ubicación Seleccionada</span>
          </div>
          <div style="font-family: ui-monospace, SFMono-Regular, monospace; font-size: 11px; font-weight: 700; background: rgba(0,0,0,0.5); padding: 5px 8px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.12); margin: 4px 0;">
            <span style="color: #f1f5f9;">Lat: ${lat.toFixed(5)}</span><br/>
            <span style="color: #f1f5f9;">Lon: ${lng.toFixed(5)}</span>
          </div>
          <span style="font-size: 9.5px; color: #94a3b8; display: block; margin-top: 4px;">
            (Arrastre el pin para ajuste fino)
          </span>
        </div>
      `;

      if (!pickerMarkerRef.current) {
        const marker = L.marker([lat, lng], {
          icon: createLocationPinIcon(),
          draggable: true,
          zIndexOffset: 1000,
        }).addTo(map);

        marker.on('dragend', (event) => {
          const markerPos = event.target.getLatLng();
          if (onSelectLocationRef.current) {
            onSelectLocationRef.current(markerPos.lat, markerPos.lng);
          }
        });

        marker.bindPopup(pickerPopupHtml, {
          className: 'custom-leaflet-glass-popup',
          offset: [0, 4],
        });

        pickerMarkerRef.current = marker;
        setTimeout(() => {
          if (pickerMarkerRef.current) {
            pickerMarkerRef.current.openPopup();
          }
        }, 300);
      } else {
        pickerMarkerRef.current.setLatLng([lat, lng]);
        pickerMarkerRef.current.setPopupContent(pickerPopupHtml);
        pickerMarkerRef.current.openPopup();
      }

      // Smooth pan to the selected pin
      map.panTo([lat, lng], { animate: true, duration: 0.6 });
    } else {
      if (pickerMarkerRef.current) {
        pickerMarkerRef.current.remove();
        pickerMarkerRef.current = null;
      }
    }
  }, [map, selectedLocation]);

  return (
    <BaseMapContainer
      height={height}
      onMapReady={handleMapReady}
      showTileSelector={true}
      showTunariRecenter={true}
      recenterPosition="bottom-right"
      extraControls={
        <button
          type="button"
          onClick={handleGetGps}
          disabled={isLocating}
          className="px-3.5 py-2 rounded-2xl bg-emerald-700 hover:bg-emerald-800 text-white shadow-xl text-xs font-bold flex items-center gap-2 cursor-pointer transition-all hover:scale-105"
          title="Capturar ubicación GPS del dispositivo"
        >
          <Navigation className={`w-4 h-4 ${isLocating ? 'animate-spin' : ''}`} />
          <span>{isLocating ? 'Obteniendo GPS...' : 'Mi Posición GPS'}</span>
        </button>
      }
    >
      {/* Esquina Inferior Izquierda: Insignia Guía de Selección */}
      <div className="absolute bottom-4 left-4 z-20 bg-black/80 dark:bg-obsidian/90 backdrop-blur-xl px-3.5 py-2 rounded-2xl border border-white/15 text-[11px] text-slate-300 flex items-center gap-2 shadow-xl pointer-events-none">
        <Crosshair className="w-3.5 h-3.5 text-emerald-400" />
        <span>Haz clic en el mapa o arrastra el pin para situar el foco</span>
      </div>
    </BaseMapContainer>
  );
};

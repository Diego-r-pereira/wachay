import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { IncidentReport, ProjectionPoint } from '../../types';
import { Layers, MapPin, Flame, Compass, Maximize2, ShieldAlert, CheckCircle2, Navigation } from 'lucide-react';
import { useLanguage } from '../../context/LanguageContext';

interface LeafletMapProps {
  reports: IncidentReport[];
  projections?: ProjectionPoint[];
  selectedLocation?: { lat: number; lng: number } | null;
  onSelectLocation?: (lat: number, lng: number) => void;
  height?: string;
  activeFilter?: 'all' | 'active' | 'controlled' | 'closed';
  focusedReportId?: number | null;
}

export const LeafletMap: React.FC<LeafletMapProps> = ({
  reports,
  projections = [],
  selectedLocation,
  onSelectLocation,
  height = '600px',
  activeFilter = 'all',
  focusedReportId = null,
}) => {
  const { t } = useLanguage();
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markersGroupRef = useRef<L.LayerGroup | null>(null);
  const projectionGroupRef = useRef<L.LayerGroup | null>(null);
  const pickerMarkerRef = useRef<L.Marker | null>(null);
  const markersMapRef = useRef<Map<number, L.Marker>>(new Map());

  // Ref to always hold the latest onSelectLocation callback
  const onSelectLocationRef = useRef(onSelectLocation);
  useEffect(() => {
    onSelectLocationRef.current = onSelectLocation;
  }, [onSelectLocation]);

  const [activeTileLayer, setActiveTileLayer] = useState<'satellite' | 'street' | 'dark'>('satellite');

  // Tile layer URIs
  const tileLayers = {
    satellite: {
      url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
      attribution: 'Tiles &copy; Esri &mdash; High-Resolution Satellite',
    },
    street: {
      url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
      attribution: '&copy; OpenStreetMap contributors',
    },
    dark: {
      url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      attribution: '&copy; OpenStreetMap &copy; CARTO Dark Matter',
    },
  };

  // Custom Leaflet Icons with Radar Pulse
  const createFireIcon = (severity: string, status: string, isFocused: boolean = false) => {
    let bgPulse = 'bg-rose-600 shadow-[0_0_20px_rgba(225,29,72,0.8)]';
    let ringColor = 'border-rose-400';
    let badgeText = 'FUEGO';

    if (status === 'Attended') {
      bgPulse = 'bg-emerald-600 shadow-[0_0_15px_rgba(16,185,129,0.7)]';
      ringColor = 'border-emerald-300';
      badgeText = 'OK';
    } else if (status === 'First_State') {
      bgPulse = 'bg-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.7)]';
      ringColor = 'border-amber-300';
      badgeText = 'CONTROL';
    }

    const scaleClass = isFocused ? 'scale-125 z-50 ring-4 ring-white' : 'hover:scale-115';

    return L.divIcon({
      className: 'custom-fire-marker !bg-transparent !border-0',
      html: `
        <div class="relative flex items-center justify-center w-9 h-9 ${scaleClass} transition-all cursor-pointer">
          ${
            status === 'Second_State'
              ? '<span class="absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75 animate-ping"></span>'
              : ''
          }
          <div class="relative flex items-center justify-center w-8 h-8 rounded-full border-2 ${ringColor} ${bgPulse} text-white shadow-2xl">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 3z"/></svg>
          </div>
        </div>
      `,
      iconSize: [36, 36],
      iconAnchor: [18, 18],
    });
  };

  // Custom GPS Selection Pin with Radar Ripple (Precisely Centered Anchor)
  const createLocationPinIcon = () => {
    return L.divIcon({
      className: 'custom-location-pin-marker !bg-transparent !border-0',
      html: `
        <div style="position: relative; width: 36px; height: 46px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; cursor: grab;">
          <!-- Radar Pulse Dot at Anchor Base -->
          <span style="position: absolute; bottom: -2px; left: 50%; transform: translateX(-50%); width: 22px; height: 22px; border-radius: 50%; background: rgba(16, 185, 129, 0.45); animation: ping 1.4s cubic-bezier(0, 0, 0.2, 1) infinite; pointer-events: none;"></span>
          <span style="position: absolute; bottom: 0px; left: 50%; transform: translateX(-50%); width: 8px; height: 8px; border-radius: 50%; background: #34d399; box-shadow: 0 0 10px #10b981; pointer-events: none;"></span>
          
          <!-- Glowing Location Pin Body -->
          <div style="width: 36px; height: 36px; border-radius: 12px; background: linear-gradient(135deg, #10b981 0%, #047857 100%); display: flex; align-items: center; justify-content: center; color: #ffffff; box-shadow: 0 4px 20px rgba(16,185,129,0.85); border: 2px solid #ffffff; z-index: 2;">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/>
              <circle cx="12" cy="10" r="3" fill="currentColor"/>
            </svg>
          </div>
          
          <!-- Pointer Tip Accent -->
          <div style="width: 10px; height: 10px; background: #047857; transform: rotate(45deg); margin-top: -5px; border-right: 2px solid #ffffff; border-bottom: 2px solid #ffffff; z-index: 1;"></div>
        </div>
      `,
      iconSize: [36, 46],
      iconAnchor: [18, 44], // Bottom-center pointer tip
      popupAnchor: [0, -48], // Perfectly centered above the pin
    });
  };

  // Center on Parque Tunari
  const handleRecenterTunari = () => {
    if (!mapInstanceRef.current) return;
    mapInstanceRef.current.flyTo([-17.34, -66.18], 12, { duration: 1.5 });
  };

  // Initialize Leaflet Map Instance
  useEffect(() => {
    if (!mapContainerRef.current) return;

    const map = L.map(mapContainerRef.current, {
      center: [-17.34, -66.18],
      zoom: 12,
      zoomControl: false,
    });

    // Custom Zoom control at top-left
    L.control.zoom({ position: 'topleft' }).addTo(map);

    L.tileLayer(tileLayers[activeTileLayer].url, {
      attribution: tileLayers[activeTileLayer].attribution,
      maxZoom: 19,
    }).addTo(map);

    markersGroupRef.current = L.layerGroup().addTo(map);
    projectionGroupRef.current = L.layerGroup().addTo(map);

    // Global Click Handler for Map Picking
    map.on('click', (e: L.LeafletMouseEvent) => {
      if (onSelectLocationRef.current) {
        onSelectLocationRef.current(e.latlng.lat, e.latlng.lng);
      }
    });

    mapInstanceRef.current = map;

    // Invalidate map size to ensure rendering within animated tabs
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 250);

    const handleResize = () => {
      map.invalidateSize();
    };
    window.addEventListener('resize', handleResize);

    return () => {
      clearTimeout(timer);
      window.removeEventListener('resize', handleResize);
      map.remove();
      mapInstanceRef.current = null;
    };
  }, []);

  // Invalidate size on tab activation or container resize
  useEffect(() => {
    if (mapInstanceRef.current) {
      mapInstanceRef.current.invalidateSize();
    }
  }, [height]);

  // Update Tile Layer
  useEffect(() => {
    if (!mapInstanceRef.current) return;
    const map = mapInstanceRef.current;

    map.eachLayer((layer) => {
      if (layer instanceof L.TileLayer) {
        map.removeLayer(layer);
      }
    });

    const selectedConfig = tileLayers[activeTileLayer];
    L.tileLayer(selectedConfig.url, {
      attribution: selectedConfig.attribution,
      maxZoom: 19,
    }).addTo(map);
  }, [activeTileLayer]);

  // Update Fire Markers Layer based on filter and focused report
  useEffect(() => {
    if (!markersGroupRef.current) return;
    markersGroupRef.current.clearLayers();
    markersMapRef.current.clear();

    const filteredReports = reports.filter((rep) => {
      if (activeFilter === 'active') return rep.status === 'Second_State';
      if (activeFilter === 'controlled') return rep.status === 'First_State';
      if (activeFilter === 'closed') return rep.status === 'Attended';
      return true;
    });

    filteredReports.forEach((rep) => {
      if (!rep.latitude || !rep.longitude) return;

      const isFocused = focusedReportId === rep.id;
      const sev = rep.severity_level || rep.severity || 'Medio';
      const marker = L.marker([rep.latitude, rep.longitude], {
        icon: createFireIcon(sev, rep.status, isFocused),
      });

      const popupContent = `
        <div style="font-family: system-ui, -apple-system, sans-serif; min-width: 240px; padding: 4px;">
          <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.15); padding-bottom: 6px; margin-bottom: 8px;">
            <span style="font-family: monospace; font-weight: 800; font-size: 13px; color: #10b981;">
              ${rep.tracking_code || 'ID #' + rep.id}
            </span>
            <span style="font-size: 10px; font-weight: 800; text-transform: uppercase; padding: 2px 8px; border-radius: 9999px; background-color: ${
              sev === 'Crítico' ? '#f43f5e' : sev === 'Alto' ? '#ea580c' : '#f59e0b'
            }; color: white;">
              ${sev}
            </span>
          </div>

          <h4 style="font-weight: 800; font-size: 14px; margin: 0 0 6px 0; color: #ffffff;">
            ${rep.incident_type}
          </h4>

          <div style="font-size: 12px; line-height: 1.5; color: #cbd5e1; margin-bottom: 8px;">
            <p style="margin: 2px 0;"><strong>Estado:</strong> ${
              rep.status === 'Second_State'
                ? '🚨 Foco Activo'
                : rep.status === 'First_State'
                ? '🟡 En Control'
                : '🟢 Sofocado'
            }</p>
            ${
              rep.vegetation_type
                ? `<p style="margin: 2px 0;"><strong>Vegetación:</strong> ${rep.vegetation_type}</p>`
                : ''
            }
            <p style="margin: 2px 0; font-family: monospace; font-size: 11px; color: #94a3b8;">
              GPS: ${rep.latitude.toFixed(4)}, ${rep.longitude.toFixed(4)}
            </p>
          </div>

          <div style="display: flex; gap: 6px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.1);">
            <a 
              href="https://www.google.com/maps/dir/?api=1&destination=${rep.latitude},${rep.longitude}" 
              target="_blank" 
              rel="noopener noreferrer"
              style="display: flex; align-items: center; justify-content: center; gap: 4px; width: 100%; padding: 6px 10px; background-color: #059669; color: white; border-radius: 8px; font-weight: 700; font-size: 11px; text-decoration: none;"
            >
              Navegar con GPS →
            </a>
          </div>
        </div>
      `;

      marker.bindPopup(popupContent, {
        className: 'custom-leaflet-glass-popup',
      });

      markersGroupRef.current?.addLayer(marker);
      markersMapRef.current.set(rep.id, marker);
    });
  }, [reports, activeFilter, focusedReportId]);

  // Smooth flyTo when focusedReportId changes
  useEffect(() => {
    if (!mapInstanceRef.current || !focusedReportId) return;
    const report = reports.find((r) => r.id === focusedReportId);
    if (report && report.latitude && report.longitude) {
      mapInstanceRef.current.flyTo([report.latitude, report.longitude], 15, {
        duration: 1.2,
      });
      const marker = markersMapRef.current.get(focusedReportId);
      if (marker) {
        setTimeout(() => marker.openPopup(), 600);
      }
    }
  }, [focusedReportId, reports]);

  // Reactive Selected Location Pin (GPS or Map Click)
  useEffect(() => {
    if (!mapInstanceRef.current) return;
    const map = mapInstanceRef.current;

    // Trigger invalidateSize to ensure correct tile rendering inside wizard
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
  }, [selectedLocation]);

  return (
    <div className="relative rounded-3xl overflow-hidden shadow-2xl border border-white/10" style={{ height }}>
      
      {/* Leaflet DOM container */}
      <div ref={mapContainerRef} className="w-full h-full z-10" />

      {/* Floating Map Tile Layer Controls (Glassmorphic Pill) */}
      <div className="absolute top-4 right-4 z-20 bg-black/75 dark:bg-obsidian/85 backdrop-blur-xl p-1.5 rounded-2xl border border-white/20 shadow-2xl flex items-center gap-1.5 text-xs text-white">
        <span className="text-[10px] font-bold text-slate-300 px-2 flex items-center gap-1 uppercase tracking-wider font-mono">
          <Layers className="w-3.5 h-3.5 text-emerald-400" />
        </span>
        {(['satellite', 'street', 'dark'] as const).map((mode) => (
          <button
            key={mode}
            onClick={() => setActiveTileLayer(mode)}
            className={`px-3 py-1.5 rounded-xl font-bold capitalize transition-all cursor-pointer ${
              activeTileLayer === mode
                ? 'bg-emerald-600 text-white shadow-md'
                : 'text-slate-300 hover:bg-white/10 hover:text-white'
            }`}
          >
            {mode === 'satellite' ? t('map.layerSat') : mode === 'street' ? t('map.layerStreet') : t('map.layerDark')}
          </button>
        ))}
      </div>

      {/* Floating Center on Tunari Button */}
      <div className="absolute top-4 left-16 z-20">
        <button
          onClick={handleRecenterTunari}
          className="px-3.5 py-2 rounded-2xl bg-black/75 dark:bg-obsidian/85 backdrop-blur-xl border border-white/20 text-white hover:bg-white/15 shadow-xl text-xs font-bold flex items-center gap-2 cursor-pointer transition-all hover:scale-105"
          title={t('map.recenter')}
        >
          <Compass className="w-4 h-4 text-pajonal animate-spin-slow" />
          <span className="hidden sm:inline">{t('map.recenter')}</span>
        </button>
      </div>

      {/* Map Legend (Bottom Right Glass Card) */}
      <div className="absolute bottom-4 right-4 z-20 bg-black/80 dark:bg-obsidian/90 backdrop-blur-xl px-4 py-2.5 rounded-2xl border border-white/20 shadow-2xl flex items-center gap-4 text-xs text-white">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-rose-600 shadow-[0_0_8px_rgba(225,29,72,0.8)] animate-pulse"></span>
          <span className="font-bold text-rose-400">{t('liveMap.filterActive')}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]"></span>
          <span className="font-bold text-amber-400">{t('liveMap.filterControlled')}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>
          <span className="font-bold text-emerald-400">{t('liveMap.filterClosed')}</span>
        </div>
      </div>

    </div>
  );
};

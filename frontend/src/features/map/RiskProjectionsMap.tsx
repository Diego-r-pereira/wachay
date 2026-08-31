import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { BaseMapContainer } from './BaseMapContainer';
import { ProjectionPoint, IncidentReport } from '../../types';
import { Compass, Sparkles, Activity, ShieldAlert } from 'lucide-react';

interface RiskProjectionsMapProps {
  projections: ProjectionPoint[];
  existingReports?: IncidentReport[];
  height?: string;
  focusedProjectionId?: number | null;
  onSelectProjection?: (proj: ProjectionPoint) => void;
}

export const RiskProjectionsMap: React.FC<RiskProjectionsMapProps> = ({
  projections,
  existingReports = [],
  height = '480px',
  focusedProjectionId = null,
  onSelectProjection,
}) => {
  const [map, setMap] = useState<L.Map | null>(null);
  const projectionsGroupRef = useRef<L.LayerGroup | null>(null);
  const bufferCirclesGroupRef = useRef<L.LayerGroup | null>(null);
  const historicalFiresGroupRef = useRef<L.LayerGroup | null>(null);
  const markersMapRef = useRef<Map<number, L.Marker>>(new Map());

  // Numbered Hotspot Icon with glowing radar buffer
  const createHotspotIcon = (index: number, prob: number, isFocused: boolean = false) => {
    const isCritical = prob >= 0.75;
    const isHigh = prob >= 0.60;
    const bgGradient = isCritical
      ? 'from-rose-600 to-rose-800 border-rose-300'
      : isHigh
      ? 'from-amber-500 to-amber-700 border-amber-300'
      : 'from-emerald-600 to-emerald-800 border-emerald-300';

    const glowColor = isCritical ? 'rgba(225, 29, 72, 0.8)' : 'rgba(245, 158, 11, 0.8)';
    const scaleClass = isFocused ? 'scale-125 ring-4 ring-white z-50' : 'hover:scale-115';

    return L.divIcon({
      className: 'custom-hotspot-marker !bg-transparent !border-0',
      html: `
        <div class="relative flex items-center justify-center w-10 h-10 ${scaleClass} transition-all cursor-pointer overflow-visible">
          <!-- Outer Pulsing Radar Ring -->
          <span class="absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping" style="background-color: ${glowColor};"></span>
          
          <!-- Numbered Badge Core -->
          <div class="relative flex items-center justify-center w-8 h-8 rounded-2xl bg-gradient-to-br ${bgGradient} text-white font-mono font-black text-xs border-2 shadow-xl" style="box-shadow: 0 0 16px ${glowColor};">
            #${index + 1}
          </div>
        </div>
      `,
      iconSize: [40, 40],
      iconAnchor: [20, 20],
      popupAnchor: [0, -22],
    });
  };

  const handleMapReady = (mapInstance: L.Map) => {
    bufferCirclesGroupRef.current = L.layerGroup().addTo(mapInstance);
    historicalFiresGroupRef.current = L.layerGroup().addTo(mapInstance);
    projectionsGroupRef.current = L.layerGroup().addTo(mapInstance);
    setMap(mapInstance);
  };

  // Render Historical Fires Context Layer
  useEffect(() => {
    if (!map || !historicalFiresGroupRef.current) return;
    historicalFiresGroupRef.current.clearLayers();

    existingReports.forEach((rep) => {
      if (!rep.latitude || !rep.longitude) return;

      const marker = L.circleMarker([rep.latitude, rep.longitude], {
        radius: 4,
        fillColor: '#94a3b8',
        color: '#ffffff',
        weight: 1,
        opacity: 0.8,
        fillOpacity: 0.5,
      });

      marker.bindPopup(`
        <div style="font-family: system-ui, sans-serif; font-size: 11px; padding: 2px;">
          <strong>Foco Histórico #${rep.id}</strong><br/>
          <span>${rep.incident_type} (${rep.status === 'Attended' ? 'Sofocado' : 'Activo'})</span>
        </div>
      `, { className: 'custom-leaflet-glass-popup' });

      historicalFiresGroupRef.current?.addLayer(marker);
    });
  }, [map, existingReports]);

  // Render AI Projected Hotspots and Concentric Risk Buffers
  useEffect(() => {
    if (!map || !projectionsGroupRef.current || !bufferCirclesGroupRef.current) return;
    projectionsGroupRef.current.clearLayers();
    bufferCirclesGroupRef.current.clearLayers();
    markersMapRef.current.clear();

    if (projections.length === 0) return;

    projections.forEach((p, idx) => {
      if (!p.latitude || !p.longitude) return;
      const prob = p.risk_probability || p.risk_score || 0.6;
      const probPercent = Math.round(prob * 100);
      const isFocused = focusedProjectionId === p.id;

      // 1. Concentric Risk Propagation Buffer
      const bufferRadiusMeters = 800 + (prob * 1200); // 800m - 2000m buffer
      const bufferCircle = L.circle([p.latitude, p.longitude], {
        radius: bufferRadiusMeters,
        color: prob >= 0.75 ? '#f43f5e' : '#f59e0b',
        weight: 1.5,
        dashArray: '4, 6',
        fillColor: prob >= 0.75 ? '#e11d48' : '#d97706',
        fillOpacity: 0.15 + (prob * 0.15),
      });
      bufferCirclesGroupRef.current?.addLayer(bufferCircle);

      // 2. Hotspot Marker Pin
      const marker = L.marker([p.latitude, p.longitude], {
        icon: createHotspotIcon(idx, prob, isFocused),
        zIndexOffset: 500 + idx,
      });

      const popupHtml = `
        <div style="font-family: system-ui, -apple-system, sans-serif; padding: 6px 10px; min-width: 210px; color: #ffffff;">
          <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.15); padding-bottom: 4px; margin-bottom: 6px;">
            <span style="font-family: monospace; font-weight: 800; font-size: 12px; color: #34d399;">
              HOTSPOT #${idx + 1}
            </span>
            <span style="font-size: 10px; font-weight: 800; font-family: monospace; padding: 2px 6px; border-radius: 6px; background-color: ${
              prob >= 0.75 ? '#e11d48' : '#d97706'
            }; color: white;">
              ${probPercent}% RIESGO
            </span>
          </div>

          <h5 style="font-weight: 800; font-size: 13px; margin: 0 0 4px 0; color: #ffffff;">
            ${p.location_name || p.name || 'Zona Proyectada'}
          </h5>

          <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4; margin-bottom: 6px;">
            <p style="margin: 2px 0;"><strong>Horizonte:</strong> ${p.projected_month || 'Próximo Mes'}</p>
            <p style="margin: 2px 0; font-family: monospace; font-size: 10px; color: #94a3b8;">
              GPS: ${p.latitude.toFixed(4)}, ${p.longitude.toFixed(4)}
            </p>
          </div>

          <div style="font-size: 9.5px; color: #a7f3d0; background: rgba(16, 185, 129, 0.15); padding: 4px 6px; border-radius: 6px; border: 1px solid rgba(16, 185, 129, 0.3);">
            Modelo: Random Forest (Confianza R²: ${(p.confidence ? (p.confidence * 100).toFixed(1) : '90.4')}%)
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml, { className: 'custom-leaflet-glass-popup' });

      marker.on('click', () => {
        if (onSelectProjection) {
          onSelectProjection(p);
        }
      });

      projectionsGroupRef.current?.addLayer(marker);
      if (p.id) {
        markersMapRef.current.set(p.id, marker);
      }
    });
  }, [map, projections, focusedProjectionId]);

  return (
    <BaseMapContainer height={height} onMapReady={handleMapReady}>
      {/* Legend Badge Overlay */}
      <div className="absolute bottom-4 right-4 z-20 bg-black/85 dark:bg-obsidian/90 backdrop-blur-xl px-4 py-2.5 rounded-2xl border border-white/15 text-xs text-white flex items-center gap-4 shadow-2xl">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-rose-600 shadow-[0_0_8px_rgba(225,29,72,0.8)] animate-pulse"></span>
          <span className="font-bold text-rose-400">&gt; 75% Extremo</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]"></span>
          <span className="font-bold text-amber-400">60-75% Alto</span>
        </div>
      </div>
    </BaseMapContainer>
  );
};

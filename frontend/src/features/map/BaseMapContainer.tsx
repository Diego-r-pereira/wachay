import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Layers, Compass } from 'lucide-react';

export interface BaseMapContainerProps {
  height?: string;
  initialCenter?: [number, number];
  initialZoom?: number;
  onMapReady?: (map: L.Map) => void;
  children?: React.ReactNode;
  className?: string;
  extraControls?: React.ReactNode;
  showTileSelector?: boolean;
  showTunariRecenter?: boolean;
  recenterPosition?: 'top-left' | 'bottom-right';
}

export const BaseMapContainer: React.FC<BaseMapContainerProps> = ({
  height = '500px',
  initialCenter = [-17.34, -66.18],
  initialZoom = 12,
  onMapReady,
  children,
  className = '',
  extraControls,
  showTileSelector = true,
  showTunariRecenter = true,
  recenterPosition = 'bottom-right',
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
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

  // Center on Parque Tunari
  const handleRecenterTunari = () => {
    if (!mapInstanceRef.current) return;
    mapInstanceRef.current.flyTo(initialCenter, initialZoom, { duration: 1.5 });
  };

  // Initialize Map Instance
  useEffect(() => {
    if (!mapContainerRef.current) return;

    const map = L.map(mapContainerRef.current, {
      center: initialCenter,
      zoom: initialZoom,
      zoomControl: false,
    });

    // Custom Zoom control at top-left
    L.control.zoom({ position: 'topleft' }).addTo(map);

    // Initial tile layer
    L.tileLayer(tileLayers[activeTileLayer].url, {
      attribution: tileLayers[activeTileLayer].attribution,
      maxZoom: 19,
    }).addTo(map);

    mapInstanceRef.current = map;

    // Trigger onMapReady callback
    if (onMapReady) {
      onMapReady(map);
    }

    // Invalidate size on mount and after render cycles
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

  // Invalidate size if height prop changes
  useEffect(() => {
    if (mapInstanceRef.current) {
      mapInstanceRef.current.invalidateSize();
    }
  }, [height]);

  return (
    <div
      className={`relative rounded-3xl overflow-hidden shadow-2xl border border-white/10 ${className}`}
      style={{ height }}
    >
      {/* Leaflet DOM container */}
      <div ref={mapContainerRef} className="w-full h-full z-10" />

      {/* Esquina Superior Izquierda: Controles Adicionales (Ej. Mi Posición GPS) */}
      {extraControls && (
        <div className="absolute top-4 left-14 z-20">
          {extraControls}
        </div>
      )}

      {/* Esquina Superior Derecha: Selector de Capas */}
      {showTileSelector && (
        <div className="absolute top-4 right-4 z-20 bg-black/75 dark:bg-obsidian/85 backdrop-blur-xl p-1.5 rounded-2xl border border-white/20 shadow-2xl flex items-center gap-1.5 text-xs text-white">
          <span className="text-[10px] font-bold text-slate-300 px-2 flex items-center gap-1 uppercase tracking-wider font-mono">
            <Layers className="w-3.5 h-3.5 text-emerald-400" /> Capa
          </span>
          {(['satellite', 'street', 'dark'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setActiveTileLayer(mode)}
              className={`px-3 py-1.5 rounded-xl font-bold capitalize transition-all cursor-pointer ${
                activeTileLayer === mode
                  ? 'bg-emerald-600 text-white shadow-md'
                  : 'text-slate-300 hover:bg-white/10 hover:text-white'
              }`}
            >
              {mode === 'satellite' ? 'Satélite HD' : mode === 'street' ? 'Calles' : 'Oscuro'}
            </button>
          ))}
        </div>
      )}

      {/* Recenter Button (Top Left or Bottom Right) */}
      {showTunariRecenter && recenterPosition === 'top-left' && (
        <div className="absolute top-4 left-16 z-20">
          <button
            type="button"
            onClick={handleRecenterTunari}
            className="px-3.5 py-2 rounded-2xl bg-black/75 dark:bg-obsidian/85 backdrop-blur-xl border border-white/20 text-white hover:bg-white/15 shadow-xl text-xs font-bold flex items-center gap-2 cursor-pointer transition-all hover:scale-105"
            title="Centrar mapa en Parque Nacional Tunari"
          >
            <Compass className="w-4 h-4 text-pajonal animate-spin-slow" />
            <span className="hidden sm:inline">Centrar en Tunari</span>
          </button>
        </div>
      )}

      {showTunariRecenter && recenterPosition === 'bottom-right' && (
        <div className="absolute bottom-4 right-4 z-20">
          <button
            type="button"
            onClick={handleRecenterTunari}
            className="px-3.5 py-2 rounded-2xl bg-black/80 dark:bg-obsidian/90 backdrop-blur-xl border border-white/20 text-white hover:bg-white/15 shadow-xl text-xs font-bold flex items-center gap-2 cursor-pointer transition-all hover:scale-105"
            title="Centrar mapa en Parque Nacional Tunari"
          >
            <Compass className="w-4 h-4 text-pajonal animate-spin-slow" />
            <span>Centrar en Tunari</span>
          </button>
        </div>
      )}

      {children}
    </div>
  );
};

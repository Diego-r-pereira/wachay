import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Dimensions,
  ActivityIndicator,
  Platform,
} from 'react-native';
import { WebView } from 'react-native-webview';
import { BrandColors } from '@/constants/theme';
import { GlassCard } from '../ui/GlassCard';
import { PillBadge } from '../ui/PillBadge';
import { DbReport } from '../dashboard/CommandCenter';
import { useLanguage } from '@/i18n/LanguageContext';

const { width } = Dimensions.get('window');

interface IncidentMapViewProps {
  userCoords: { latitude: number; longitude: number } | null;
  dbReports: DbReport[];
  dbLoading: boolean;
  onReportIncident: () => void;
}

export const IncidentMapView: React.FC<IncidentMapViewProps> = ({
  userCoords,
  dbReports,
  dbLoading,
  onReportIncident,
}) => {
  const { t, language } = useLanguage();
  const [filter, setFilter] = useState<'all' | 'Second_State' | 'First_State' | 'Attended' | 'Citizen_Pending'>('all');
  const [selectedReport, setSelectedReport] = useState<DbReport | null>(dbReports[0] || null);
  const [mapLayer, setMapLayer] = useState<'dark' | 'terrain'>('dark');
  const webViewRef = useRef<WebView>(null);

  // Filtered reports
  const filteredReports = dbReports.filter((r) => {
    if (filter === 'all') return true;
    return r.status === filter;
  });

  // Default coordinates centered in Cochabamba
  const defaultLat = userCoords?.latitude || -17.3935;
  const defaultLng = userCoords?.longitude || -66.1570;

  // Generate Leaflet HTML for WebView
  const generateMapHtml = () => {
    const userLat = userCoords ? userCoords.latitude : defaultLat;
    const userLng = userCoords ? userCoords.longitude : defaultLng;

    const reportsJson = JSON.stringify(
      filteredReports.map((r) => ({
        id: r.id,
        tracking_code: r.tracking_code,
        type: r.incident_type,
        severity: r.severity_level || r.severity || 'Medio',
        status: r.status,
        lat: r.latitude || (defaultLat + (Math.random() - 0.5) * 0.08),
        lng: r.longitude || (defaultLng + (Math.random() - 0.5) * 0.08),
      }))
    );

    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
          <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
          <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            html, body, #map { width: 100%; height: 100%; background: #0E1410; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
            
            /* Custom User GPS Marker */
            .user-pulse {
              width: 22px;
              height: 22px;
              border-radius: 50%;
              background: rgba(86, 134, 143, 0.45);
              border: 2px solid #56868F;
              box-shadow: 0 0 14px #56868F;
              animation: pulse 1.8s infinite;
              display: flex;
              align-items: center;
              justify-content: center;
            }
            .user-dot {
              width: 8px;
              height: 8px;
              border-radius: 50%;
              background: #FFFFFF;
            }
            @keyframes pulse {
              0% { transform: scale(0.9); opacity: 0.9; }
              50% { transform: scale(1.35); opacity: 0.4; }
              100% { transform: scale(0.9); opacity: 0.9; }
            }

            /* Fire Hotspot Marker */
            .fire-marker {
              display: flex;
              align-items: center;
              justify-content: center;
              width: 38px;
              height: 38px;
              border-radius: 19px;
              background: rgba(21, 31, 24, 0.92);
              border: 2px solid #C49164;
              box-shadow: 0 0 12px rgba(196, 145, 100, 0.6);
              cursor: pointer;
              transition: transform 0.2s;
            }
            .fire-marker.active-fire {
              border-color: #E55353;
              box-shadow: 0 0 14px rgba(229, 83, 83, 0.8);
              animation: flameGlow 1.5s infinite alternate;
            }
            .fire-marker.selected {
              transform: scale(1.25);
              border-color: #CFB159;
              box-shadow: 0 0 18px #CFB159;
            }
            @keyframes flameGlow {
              from { box-shadow: 0 0 8px rgba(229, 83, 83, 0.6); }
              to { box-shadow: 0 0 18px rgba(229, 83, 83, 1); }
            }
            .marker-icon {
              font-size: 18px;
            }
            .leaflet-control-attribution { display: none !important; }
          </style>
        </head>
        <body>
          <div id="map"></div>
          <script>
            const map = L.map('map', {
              center: [${userLat}, ${userLng}],
              zoom: 13,
              zoomControl: false,
              attributionControl: false
            });

            // Tile layers
            const darkTiles = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
              maxZoom: 19,
              subdomains: 'abcd'
            });

            const terrainTiles = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
              maxZoom: 19
            });

            ${mapLayer === 'dark' ? 'darkTiles.addTo(map);' : 'terrainTiles.addTo(map);'}

            // User GPS Marker
            const userIcon = L.divIcon({
              className: 'custom-user-icon',
              html: '<div class="user-pulse"><div class="user-dot"></div></div>',
              iconSize: [22, 22],
              iconAnchor: [11, 11]
            });
            L.marker([${userLat}, ${userLng}], { icon: userIcon }).addTo(map);

            // DB Incidents Markers
            const reports = ${reportsJson};
            const selectedId = ${selectedReport ? selectedReport.id : 'null'};

            reports.forEach(r => {
              const isSelected = selectedId === r.id;
              const isCritical = r.severity === 'Alto' || r.status === 'Second_State';
              const iconEmoji = isCritical ? '🔥' : '⚠️';
              const markerClass = 'fire-marker ' + (isCritical ? 'active-fire ' : '') + (isSelected ? 'selected' : '');

              const fireIcon = L.divIcon({
                className: 'custom-fire-icon',
                html: '<div class="' + markerClass + '"><span class="marker-icon">' + iconEmoji + '</span></div>',
                iconSize: [38, 38],
                iconAnchor: [19, 19]
              });

              const marker = L.marker([r.lat, r.lng], { icon: fireIcon }).addTo(map);
              marker.on('click', () => {
                window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'SELECT_REPORT', id: r.id }));
              });
            });

            // Pan to user position
            window.centerOnUser = function() {
              map.flyTo([${userLat}, ${userLng}], 15, { duration: 1.2 });
            };

            // Fit all markers
            window.fitAll = function() {
              if (reports.length > 0) {
                const group = new L.featureGroup(reports.map(r => L.marker([r.lat, r.lng])));
                map.fitBounds(group.getBounds().pad(0.3));
              } else {
                map.flyTo([${defaultLat}, ${defaultLng}], 13);
              }
            };
          </script>
        </body>
      </html>
    `;
  };

  const handleMessage = (event: any) => {
    try {
      const data = JSON.parse(event.nativeEvent.data);
      if (data.type === 'SELECT_REPORT') {
        const found = dbReports.find((r) => r.id === data.id);
        if (found) {
          setSelectedReport(found);
        }
      }
    } catch (e) {
      console.log('Error parsing map message', e);
    }
  };

  const centerOnUser = () => {
    webViewRef.current?.injectJavaScript('window.centerOnUser && window.centerOnUser(); true;');
  };

  const fitAllMarkers = () => {
    webViewRef.current?.injectJavaScript('window.fitAll && window.fitAll(); true;');
  };

  const toggleLayer = () => {
    setMapLayer(mapLayer === 'dark' ? 'terrain' : 'dark');
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'Second_State':
        return t.mapView.statusActive;
      case 'First_State':
        return t.mapView.statusControlled;
      case 'Attended':
        return t.mapView.statusClosed;
      case 'Citizen_Pending':
        return t.mapView.statusPending;
      default:
        return status;
    }
  };

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'Second_State':
        return 'danger';
      case 'First_State':
        return 'gold';
      case 'Attended':
        return 'sage';
      default:
        return 'neutral';
    }
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <View>
          <Text style={styles.title}>{t.mapView.title}</Text>
          <Text style={styles.subtitle}>{t.mapView.subtitle}</Text>
        </View>
        <PillBadge label={`${dbReports.length} ${t.mapView.inDb}`} variant="gold" />
      </View>

      {/* Interactive Map Canvas */}
      <View style={styles.mapCanvasWrapper}>
        <WebView
          ref={webViewRef}
          originWhitelist={['*']}
          source={{ html: generateMapHtml() }}
          style={styles.webView}
          onMessage={handleMessage}
          javaScriptEnabled={true}
          domStorageEnabled={true}
          scrollEnabled={false}
          scalesPageToFit={true}
        />

        {/* Floating Interactive Controls */}
        <View style={styles.mapControlsOverlay}>
          <TouchableOpacity style={styles.controlBtn} onPress={centerOnUser}>
            <Text style={styles.controlBtnIcon}>🎯</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.controlBtn} onPress={fitAllMarkers}>
            <Text style={styles.controlBtnIcon}>🗺️</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.controlBtn} onPress={toggleLayer}>
            <Text style={styles.controlBtnIcon}>{mapLayer === 'dark' ? '🌓' : '☀️'}</Text>
          </TouchableOpacity>
        </View>

        {/* Real GPS Coordinates Tag */}
        <View style={styles.mapCoordinatesTag}>
          <Text style={styles.coordinatesText}>
            GPS: {userCoords ? `${userCoords.latitude.toFixed(4)}, ${userCoords.longitude.toFixed(4)}` : 'Cochabamba'}
          </Text>
        </View>
      </View>

      {/* Filter Tabs */}
      <View style={styles.filterRow}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.filterScroll}>
          {[
            { key: 'all', label: t.mapView.filterAll },
            { key: 'Second_State', label: t.mapView.filterActive },
            { key: 'First_State', label: t.mapView.filterControlled },
            { key: 'Citizen_Pending', label: t.mapView.filterPending },
            { key: 'Attended', label: t.mapView.filterClosed },
          ].map((tab) => (
            <TouchableOpacity
              key={tab.key}
              style={[
                styles.filterTab,
                filter === tab.key && styles.filterTabActive,
              ]}
              onPress={() => setFilter(tab.key as any)}
            >
              <Text
                style={[
                  styles.filterTabText,
                  filter === tab.key && styles.filterTabTextActive,
                ]}
              >
                {tab.label}
              </Text>
            </TouchableOpacity>
          ))}
        </ScrollView>
      </View>

      {/* Selected Incident Detail Sheet */}
      {selectedReport ? (
        <GlassCard
          variant={selectedReport.status === 'Second_State' ? 'danger' : 'gold'}
          style={styles.detailSheet}
        >
          <View style={styles.detailHeader}>
            <View style={{ flex: 1 }}>
              <Text style={styles.detailType}>{selectedReport.incident_type}</Text>
              <Text style={styles.detailCode}>
                {language === 'es' ? 'Código:' : 'Code:'} {selectedReport.tracking_code ? `#${selectedReport.tracking_code}` : `ID ${selectedReport.id}`}
              </Text>
            </View>
            <PillBadge
              label={getStatusLabel(selectedReport.status)}
              variant={getStatusVariant(selectedReport.status) as any}
            />
          </View>

          <View style={styles.detailGrid}>
            <View style={styles.detailItem}>
              <Text style={styles.detailLabel}>{t.mapView.severityLabel}</Text>
              <Text style={[styles.detailValue, { color: BrandColors.terracotta }]}>
                {selectedReport.severity_level || selectedReport.severity || t.types.medium}
              </Text>
            </View>
            <View style={styles.detailItem}>
              <Text style={styles.detailLabel}>{t.mapView.dateLabel}</Text>
              <Text style={styles.detailValue}>
                {selectedReport.date_reported || (selectedReport.detection_time ? new Date(selectedReport.detection_time).toLocaleDateString() : t.common.today)}
              </Text>
            </View>
            <View style={styles.detailItem}>
              <Text style={styles.detailLabel}>{t.mapView.vegLabel}</Text>
              <Text style={styles.detailValue}>
                {selectedReport.vegetation_type || t.types.nativeShrub}
              </Text>
            </View>
          </View>

          <TouchableOpacity style={styles.reportSupportBtn} onPress={onReportIncident}>
            <Text style={styles.reportSupportBtnText}>{t.mapView.supportBtn}</Text>
          </TouchableOpacity>
        </GlassCard>
      ) : (
        <GlassCard variant="default" style={styles.detailSheet}>
          <Text style={{ color: BrandColors.textSecondary, textAlign: 'center', fontSize: 12 }}>
            {t.mapView.emptySelection}
          </Text>
        </GlassCard>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: BrandColors.darkObsidian,
    paddingHorizontal: 20,
    paddingTop: 10,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
    paddingTop: 8,
  },
  title: {
    fontSize: 18,
    fontWeight: '900',
    color: BrandColors.textPrimary,
    letterSpacing: 1,
  },
  subtitle: {
    fontSize: 11,
    color: BrandColors.textSecondary,
    fontWeight: '600',
  },
  mapCanvasWrapper: {
    height: 230,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: 'rgba(63, 100, 78, 0.4)',
    overflow: 'hidden',
    position: 'relative',
    backgroundColor: '#0E1410',
    marginBottom: 12,
  },
  webView: {
    flex: 1,
    backgroundColor: '#0E1410',
  },
  mapControlsOverlay: {
    position: 'absolute',
    top: 10,
    right: 10,
    gap: 8,
  },
  controlBtn: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: 'rgba(21, 31, 24, 0.85)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.15)',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.4,
    shadowRadius: 4,
    elevation: 4,
  },
  controlBtnIcon: {
    fontSize: 16,
  },
  mapCoordinatesTag: {
    position: 'absolute',
    bottom: 8,
    left: 10,
    backgroundColor: 'rgba(0, 0, 0, 0.75)',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.08)',
  },
  coordinatesText: {
    fontSize: 9,
    color: BrandColors.textMuted,
    fontFamily: 'monospace',
  },
  filterRow: {
    marginBottom: 12,
  },
  filterScroll: {
    gap: 8,
  },
  filterTab: {
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 12,
    backgroundColor: BrandColors.surface,
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
  },
  filterTabActive: {
    backgroundColor: BrandColors.forestSage,
    borderColor: BrandColors.forestSage,
  },
  filterTabText: {
    fontSize: 11,
    fontWeight: '600',
    color: BrandColors.textSecondary,
  },
  filterTabTextActive: {
    color: '#FFFFFF',
    fontWeight: '800',
  },
  detailSheet: {
    padding: 14,
    marginBottom: 20,
  },
  detailHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  detailType: {
    fontSize: 14,
    fontWeight: '800',
    color: BrandColors.textPrimary,
  },
  detailCode: {
    fontSize: 11,
    color: BrandColors.gold,
    fontFamily: 'monospace',
    marginTop: 2,
  },
  detailGrid: {
    flexDirection: 'row',
    backgroundColor: 'rgba(0,0,0,0.25)',
    borderRadius: 10,
    padding: 10,
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  detailItem: {
    alignItems: 'center',
  },
  detailLabel: {
    fontSize: 9,
    fontWeight: '700',
    color: BrandColors.textMuted,
    marginBottom: 2,
  },
  detailValue: {
    fontSize: 11,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  reportSupportBtn: {
    backgroundColor: BrandColors.terracotta,
    paddingVertical: 10,
    borderRadius: 12,
    alignItems: 'center',
  },
  reportSupportBtnText: {
    color: '#FFFFFF',
    fontSize: 12,
    fontWeight: '800',
  },
});

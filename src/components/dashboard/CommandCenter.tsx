import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Image,
  ActivityIndicator,
} from 'react-native';
import { BrandColors } from '@/constants/theme';
import { GlassCard } from '../ui/GlassCard';
import { PillBadge } from '../ui/PillBadge';
import { useLanguage } from '@/i18n/LanguageContext';

export interface DbReport {
  id: number;
  tracking_code?: string;
  incident_type: string;
  severity_level?: string;
  severity?: string;
  status: string;
  latitude?: number;
  longitude?: number;
  detection_time?: string;
  date_reported?: string;
  vegetation_type?: string;
}

export interface DbStats {
  total: number;
  active: number;
  controlled: number;
  closed: number;
}

interface CommandCenterProps {
  coords: { latitude: number; longitude: number } | null;
  locationLoading: boolean;
  weatherText: string;
  offlineQueueCount: number;
  syncing: boolean;
  dbStats: DbStats;
  dbReports: DbReport[];
  dbLoading: boolean;
  onOpenReport: () => void;
  onOpenMap: () => void;
  onOpenChat: () => void;
  onOpenTracking: () => void;
  onOpenOnboarding: () => void;
  onSyncQueue: () => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  coords,
  locationLoading,
  weatherText,
  offlineQueueCount,
  syncing,
  dbStats,
  dbReports,
  dbLoading,
  onOpenReport,
  onOpenMap,
  onOpenChat,
  onOpenTracking,
  onOpenOnboarding,
  onSyncQueue,
}) => {
  const { t, language, toggleLanguage } = useLanguage();

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.scrollContent}
      showsVerticalScrollIndicator={false}
    >
      {/* Top Header Bar */}
      <View style={styles.topHeader}>
        <View style={styles.headerLeft}>
          <Image
            source={require('@/assets/images/iso.jpg')}
            style={styles.headerLogo}
          />
          <View>
            <Text style={styles.appName}>{t.brand.name}</Text>
            <Text style={styles.appSub}>{t.dashboard.appSub}</Text>
          </View>
        </View>

        <View style={styles.headerRight}>
          {/* Language Toggle Button */}
          <TouchableOpacity style={styles.langToggleBtn} onPress={toggleLanguage}>
            <Text style={styles.langToggleText}>
              🌐 {language === 'es' ? 'EN' : 'ES'}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.infoBtn} onPress={onOpenOnboarding}>
            <Text style={styles.infoBtnText}>{t.common.guide}</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Slogan Banner */}
      <View style={styles.sloganCard}>
        <Text style={styles.sloganText}>{t.brand.slogan}</Text>
      </View>

      {/* Offline Queue Notification (if pending items) */}
      {offlineQueueCount > 0 && (
        <TouchableOpacity
          style={styles.offlineBanner}
          onPress={onSyncQueue}
          disabled={syncing}
        >
          <View style={styles.offlineBannerLeft}>
            <Text style={styles.offlinePulse}>⚠️</Text>
            <View>
              <Text style={styles.offlineTitle}>
                {offlineQueueCount} {t.dashboard.offlineAlertTitle}
              </Text>
              <Text style={styles.offlineSub}>{t.dashboard.offlineAlertSub}</Text>
            </View>
          </View>
          {syncing ? (
            <ActivityIndicator size="small" color="#FFFFFF" />
          ) : (
            <View style={styles.syncBtnPill}>
              <Text style={styles.syncBtnText}>{t.dashboard.syncBtn}</Text>
            </View>
          )}
        </TouchableOpacity>
      )}

      {/* Live DB Statistics Counter Grid */}
      <View style={styles.statsSection}>
        <View style={styles.statsHeaderRow}>
          <Text style={styles.sectionHeaderTitle}>{t.dashboard.statsHeader}</Text>
          {dbLoading && <ActivityIndicator size="small" color={BrandColors.terracotta} />}
        </View>

        <View style={styles.statsGrid}>
          <GlassCard variant="danger" style={styles.statCard}>
            <Text style={styles.statNumber}>{dbStats.active}</Text>
            <Text style={styles.statLabel}>{t.dashboard.statActive}</Text>
          </GlassCard>

          <GlassCard variant="gold" style={styles.statCard}>
            <Text style={[styles.statNumber, { color: BrandColors.gold }]}>{dbStats.controlled}</Text>
            <Text style={styles.statLabel}>{t.dashboard.statControlled}</Text>
          </GlassCard>

          <GlassCard variant="teal" style={styles.statCard}>
            <Text style={[styles.statNumber, { color: BrandColors.teal }]}>{dbStats.closed}</Text>
            <Text style={styles.statLabel}>{t.dashboard.statClosed}</Text>
          </GlassCard>

          <GlassCard variant="default" style={styles.statCard}>
            <Text style={styles.statNumber}>{dbStats.total}</Text>
            <Text style={styles.statLabel}>{t.dashboard.statTotal}</Text>
          </GlassCard>
        </View>
      </View>

      {/* Hero Emergency CTA */}
      <TouchableOpacity
        style={styles.heroReportButton}
        activeOpacity={0.88}
        onPress={onOpenReport}
      >
        <View style={styles.heroContent}>
          <View style={styles.heroIconCircle}>
            <Text style={styles.heroIcon}>🚨</Text>
          </View>
          <View style={styles.heroTextWrapper}>
            <Text style={styles.heroTitle}>{t.dashboard.heroTitle}</Text>
            <Text style={styles.heroSubtitle}>{t.dashboard.heroSub}</Text>
          </View>
          <Text style={styles.heroArrow}>➔</Text>
        </View>
      </TouchableOpacity>

      {/* Live GPS & Field Telemetry */}
      <GlassCard variant="elevated" style={styles.telemetryCard}>
        <View style={styles.telemetryHeader}>
          <Text style={styles.sectionHeaderTitle}>{t.dashboard.telemetryTitle}</Text>
          <PillBadge
            label={coords ? t.dashboard.gpsLocked : t.dashboard.gpsSearching}
            variant={coords ? 'sage' : 'terracotta'}
          />
        </View>

        <View style={styles.telemetryGrid}>
          <View style={styles.telemetryItem}>
            <Text style={styles.telemetryLabel}>{t.dashboard.coordsLabel}</Text>
            {locationLoading ? (
              <ActivityIndicator size="small" color={BrandColors.forestSage} />
            ) : coords ? (
              <Text style={styles.telemetryValue}>
                Lat: {coords.latitude.toFixed(5)}, Lon: {coords.longitude.toFixed(5)}
              </Text>
            ) : (
              <Text style={[styles.telemetryValue, { color: BrandColors.danger }]}>
                {t.dashboard.gpsSearchingText}
              </Text>
            )}
          </View>

          <View style={styles.telemetryItem}>
            <Text style={styles.telemetryLabel}>{t.dashboard.weatherLabel}</Text>
            <Text style={[styles.telemetryValue, { color: BrandColors.teal }]}>
              {weatherText || (language === 'es' ? 'Temp: 24.5°C • Viento: 14 km/h • Humedad: 38%' : 'Temp: 24.5°C • Wind: 14 km/h • Humidity: 38%')}
            </Text>
          </View>
        </View>
      </GlassCard>

      {/* Quick Action Buttons */}
      <Text style={styles.sectionTitle}>{t.dashboard.quickActionsTitle}</Text>
      <View style={styles.actionsGrid}>
        <TouchableOpacity style={styles.actionCard} onPress={onOpenMap}>
          <View style={[styles.actionIconCircle, { backgroundColor: 'rgba(207, 177, 89, 0.15)' }]}>
            <Text style={styles.actionEmoji}>🗺️</Text>
          </View>
          <Text style={styles.actionCardTitle}>{t.dashboard.actionMapTitle}</Text>
          <Text style={styles.actionCardSub}>{t.dashboard.actionMapSub}</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.actionCard} onPress={onOpenChat}>
          <View style={[styles.actionIconCircle, { backgroundColor: 'rgba(86, 134, 143, 0.15)' }]}>
            <Text style={styles.actionEmoji}>🤖</Text>
          </View>
          <Text style={styles.actionCardTitle}>{t.dashboard.actionChatTitle}</Text>
          <Text style={styles.actionCardSub}>{t.dashboard.actionChatSub}</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.actionCard} onPress={onOpenTracking}>
          <View style={[styles.actionIconCircle, { backgroundColor: 'rgba(63, 100, 78, 0.2)' }]}>
            <Text style={styles.actionEmoji}>🔍</Text>
          </View>
          <Text style={styles.actionCardTitle}>{t.dashboard.actionTrackingTitle}</Text>
          <Text style={styles.actionCardSub}>{t.dashboard.actionTrackingSub}</Text>
        </TouchableOpacity>
      </View>

      {/* Live Recent Incident Feed from Real DB */}
      <View style={styles.recentSection}>
        <View style={styles.recentHeaderRow}>
          <Text style={styles.sectionTitle}>{t.dashboard.recentSectionTitle}</Text>
          <TouchableOpacity onPress={onOpenMap}>
            <Text style={styles.viewAllText}>{t.dashboard.viewOnMap}</Text>
          </TouchableOpacity>
        </View>

        {dbReports.length === 0 ? (
          <GlassCard variant="default" style={{ padding: 16, alignItems: 'center' }}>
            <Text style={{ color: BrandColors.textSecondary, fontSize: 12 }}>
              {dbLoading ? t.dashboard.loadingReports : t.dashboard.noReports}
            </Text>
          </GlassCard>
        ) : (
          dbReports.slice(0, 4).map((r) => {
            const sev = r.severity_level || r.severity || 'Medio';
            const variant = sev === 'Alto' ? 'danger' : sev === 'Medio' ? 'gold' : 'sage';
            const sevDisplay = language === 'en' 
              ? (sev === 'Alto' ? t.types.high : sev === 'Medio' ? t.types.medium : t.types.low)
              : sev;

            return (
              <GlassCard key={r.id} variant="default" style={styles.reportItemCard}>
                <View style={styles.reportLeft}>
                  <Text style={styles.reportType}>{r.incident_type}</Text>
                  <Text style={styles.reportDate}>
                    {r.date_reported || (r.detection_time ? new Date(r.detection_time).toLocaleDateString() : t.common.today)}
                    {r.vegetation_type ? ` • ${r.vegetation_type}` : ''}
                  </Text>
                </View>
                <View style={{ alignItems: 'flex-end', gap: 4 }}>
                  <PillBadge label={sevDisplay} variant={variant} />
                  {r.tracking_code && (
                    <Text style={styles.trackingCodeSmall}>#{r.tracking_code}</Text>
                  )}
                </View>
              </GlassCard>
            );
          })
        )}
      </View>

      <View style={{ height: 65 }} />
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: BrandColors.darkObsidian,
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingTop: 10,
    paddingBottom: 40,
  },
  topHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
    paddingTop: 8,
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  headerLogo: {
    width: 42,
    height: 42,
    borderRadius: 21,
    borderWidth: 1.5,
    borderColor: BrandColors.terracotta,
  },
  appName: {
    fontSize: 20,
    fontWeight: '900',
    color: BrandColors.textPrimary,
    letterSpacing: 2,
  },
  appSub: {
    fontSize: 9,
    fontWeight: '800',
    color: BrandColors.textSecondary,
    letterSpacing: 0.8,
  },
  langToggleBtn: {
    paddingVertical: 5,
    paddingHorizontal: 10,
    backgroundColor: 'rgba(196, 145, 100, 0.15)',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: BrandColors.terracotta,
  },
  langToggleText: {
    color: BrandColors.terracotta,
    fontSize: 11,
    fontWeight: '800',
  },
  infoBtn: {
    paddingVertical: 5,
    paddingHorizontal: 10,
    backgroundColor: 'rgba(255, 255, 255, 0.07)',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.12)',
  },
  infoBtnText: {
    color: BrandColors.textPrimary,
    fontSize: 11,
    fontWeight: '600',
  },
  sloganCard: {
    backgroundColor: 'rgba(207, 177, 89, 0.08)',
    borderWidth: 1,
    borderColor: 'rgba(207, 177, 89, 0.25)',
    borderRadius: 10,
    paddingVertical: 6,
    paddingHorizontal: 12,
    marginBottom: 16,
  },
  sloganText: {
    fontSize: 10,
    color: BrandColors.gold,
    fontWeight: '700',
    letterSpacing: 0.5,
    textAlign: 'center',
  },
  offlineBanner: {
    backgroundColor: 'rgba(196, 145, 100, 0.2)',
    borderWidth: 1,
    borderColor: BrandColors.terracotta,
    borderRadius: 14,
    padding: 12,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  offlineBannerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    flex: 1,
  },
  offlinePulse: {
    fontSize: 20,
  },
  offlineTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  offlineSub: {
    fontSize: 11,
    color: BrandColors.textSecondary,
  },
  syncBtnPill: {
    backgroundColor: BrandColors.terracotta,
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 12,
  },
  syncBtnText: {
    color: '#FFFFFF',
    fontSize: 11,
    fontWeight: '700',
  },
  statsSection: {
    marginBottom: 18,
  },
  statsHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  statsGrid: {
    flexDirection: 'row',
    gap: 8,
  },
  statCard: {
    flex: 1,
    padding: 10,
    alignItems: 'center',
    borderRadius: 12,
  },
  statNumber: {
    fontSize: 18,
    fontWeight: '900',
    color: BrandColors.textPrimary,
  },
  statLabel: {
    fontSize: 9,
    fontWeight: '700',
    color: BrandColors.textSecondary,
    marginTop: 2,
    textAlign: 'center',
  },
  heroReportButton: {
    backgroundColor: BrandColors.terracotta,
    borderRadius: 16,
    padding: 16,
    marginBottom: 18,
    shadowColor: BrandColors.terracotta,
    shadowOffset: { width: 0, height: 5 },
    shadowOpacity: 0.45,
    shadowRadius: 12,
    elevation: 8,
  },
  heroContent: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  heroIconCircle: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  heroIcon: {
    fontSize: 22,
  },
  heroTextWrapper: {
    flex: 1,
  },
  heroTitle: {
    fontSize: 15,
    fontWeight: '900',
    color: '#FFFFFF',
    letterSpacing: 0.8,
  },
  heroSubtitle: {
    fontSize: 11,
    color: 'rgba(255, 255, 255, 0.85)',
    fontWeight: '500',
    marginTop: 2,
  },
  heroArrow: {
    fontSize: 18,
    color: '#FFFFFF',
    fontWeight: 'bold',
    marginLeft: 6,
  },
  telemetryCard: {
    marginBottom: 20,
    padding: 14,
  },
  telemetryHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  sectionHeaderTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  telemetryGrid: {
    gap: 10,
  },
  telemetryItem: {
    backgroundColor: 'rgba(0, 0, 0, 0.25)',
    borderRadius: 10,
    padding: 10,
  },
  telemetryLabel: {
    fontSize: 9,
    fontWeight: '700',
    color: BrandColors.textMuted,
    letterSpacing: 0.8,
    marginBottom: 4,
  },
  telemetryValue: {
    fontSize: 12,
    fontWeight: '700',
    color: BrandColors.textPrimary,
    fontFamily: 'monospace',
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: '800',
    color: BrandColors.textPrimary,
    letterSpacing: 0.5,
    marginBottom: 10,
  },
  actionsGrid: {
    flexDirection: 'row',
    gap: 10,
    marginBottom: 20,
  },
  actionCard: {
    flex: 1,
    backgroundColor: BrandColors.surface,
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
    borderRadius: 14,
    padding: 12,
    alignItems: 'center',
  },
  actionIconCircle: {
    width: 38,
    height: 38,
    borderRadius: 19,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 6,
  },
  actionEmoji: {
    fontSize: 18,
  },
  actionCardTitle: {
    fontSize: 11,
    fontWeight: '700',
    color: BrandColors.textPrimary,
    marginBottom: 2,
  },
  actionCardSub: {
    fontSize: 9,
    color: BrandColors.textSecondary,
  },
  recentSection: {
    marginBottom: 20,
  },
  recentHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  viewAllText: {
    fontSize: 12,
    color: BrandColors.terracotta,
    fontWeight: '700',
  },
  reportItemCard: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 12,
    marginBottom: 8,
  },
  reportLeft: {
    flex: 1,
    gap: 3,
  },
  reportType: {
    fontSize: 13,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  reportDate: {
    fontSize: 11,
    color: BrandColors.textSecondary,
  },
  trackingCodeSmall: {
    fontSize: 10,
    color: BrandColors.gold,
    fontFamily: 'monospace',
  },
});

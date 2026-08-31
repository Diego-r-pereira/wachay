import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { BrandColors } from '@/constants/theme';
import { GlassCard } from '../ui/GlassCard';
import { PillBadge } from '../ui/PillBadge';
import { useLanguage } from '@/i18n/LanguageContext';

interface OfflineReportItem {
  id: string;
  citizen_name: string;
  incident_type: string;
  severity_level: string;
  description: string;
  detection_time: string;
}

interface SyncedHistoryItem {
  tracking_code: string;
  incident_type: string;
  date: string;
}

interface TrackingHubProps {
  trackingCodeInput: string;
  trackingStatusText: string;
  trackingLoading: boolean;
  offlineQueue: OfflineReportItem[];
  historyList: SyncedHistoryItem[];
  syncing: boolean;
  onTrackingInputChange: (text: string) => void;
  onCheckStatus: () => void;
  onSyncQueue: () => void;
}

export const TrackingHub: React.FC<TrackingHubProps> = ({
  trackingCodeInput,
  trackingStatusText,
  trackingLoading,
  offlineQueue,
  historyList,
  syncing,
  onTrackingInputChange,
  onCheckStatus,
  onSyncQueue,
}) => {
  const { t, language } = useLanguage();

  const timelineSteps = [
    { title: t.tracking.step1, done: true },
    { title: t.tracking.step2, done: true },
    { title: t.tracking.step3, done: false },
    { title: t.tracking.step4, done: false },
  ];

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.scrollContent}
      showsVerticalScrollIndicator={false}
    >
      {/* Header */}
      <View style={styles.header}>
        <View>
          <Text style={styles.title}>{t.tracking.title}</Text>
          <Text style={styles.subtitle}>{t.tracking.subtitle}</Text>
        </View>
        <PillBadge label={t.tracking.badge} variant="sage" />
      </View>

      {/* Code Lookup Search Box */}
      <GlassCard variant="elevated" style={styles.searchCard}>
        <Text style={styles.searchLabel}>{t.tracking.inputLabel}</Text>
        <View style={styles.searchRow}>
          <TextInput
            style={styles.searchInput}
            value={trackingCodeInput}
            onChangeText={onTrackingInputChange}
            placeholder={t.tracking.inputPlaceholder}
            placeholderTextColor={BrandColors.textMuted}
            autoCapitalize="characters"
          />
          <TouchableOpacity
            style={[styles.searchButton, (!trackingCodeInput.trim() || trackingLoading) && styles.searchButtonDisabled]}
            onPress={onCheckStatus}
            disabled={!trackingCodeInput.trim() || trackingLoading}
          >
            {trackingLoading ? (
              <ActivityIndicator size="small" color="#FFFFFF" />
            ) : (
              <Text style={styles.searchButtonText}>{t.tracking.searchBtn}</Text>
            )}
          </TouchableOpacity>
        </View>

        {/* Result Box if searched */}
        {trackingStatusText ? (
          <View style={styles.resultBox}>
            <View style={styles.resultHeader}>
              <Text style={styles.resultTag}>{t.tracking.responseTitle}</Text>
              <PillBadge label={t.tracking.verifiedBadge} variant="gold" />
            </View>
            <Text style={styles.resultBody}>{trackingStatusText}</Text>

            {/* Visual Step Timeline */}
            <View style={styles.timelineContainer}>
              {timelineSteps.map((step, idx) => (
                <View key={idx} style={styles.timelineStep}>
                  <View
                    style={[
                      styles.timelineDot,
                      step.done ? styles.timelineDotDone : styles.timelineDotPending,
                    ]}
                  />
                  <Text
                    style={[
                      styles.timelineStepText,
                      step.done && { color: BrandColors.textPrimary, fontWeight: '700' },
                    ]}
                  >
                    {step.title}
                  </Text>
                </View>
              ))}
            </View>
          </View>
        ) : null}
      </GlassCard>

      {/* Offline Queue Section */}
      <View style={styles.section}>
        <View style={styles.sectionHeaderRow}>
          <View>
            <Text style={styles.sectionTitle}>{t.tracking.queueTitle}</Text>
            <Text style={styles.sectionSub}>{t.tracking.queueSub}</Text>
          </View>
          {offlineQueue.length > 0 && (
            <TouchableOpacity
              style={styles.syncAllButton}
              onPress={onSyncQueue}
              disabled={syncing}
            >
              {syncing ? (
                <ActivityIndicator size="small" color="#FFFFFF" />
              ) : (
                <Text style={styles.syncAllButtonText}>{t.common.sync}</Text>
              )}
            </TouchableOpacity>
          )}
        </View>

        {offlineQueue.length === 0 ? (
          <GlassCard variant="default" style={styles.emptyCard}>
            <Text style={styles.emptyIcon}>✅</Text>
            <Text style={styles.emptyText}>{t.tracking.queueEmpty}</Text>
          </GlassCard>
        ) : (
          offlineQueue.map((rep) => (
            <GlassCard key={rep.id} variant="terracotta" style={styles.queueItemCard}>
              <View style={styles.queueItemHeader}>
                <Text style={styles.queueItemType}>{rep.incident_type}</Text>
                <PillBadge label={rep.severity_level} variant="terracotta" />
              </View>
              <Text style={styles.queueItemDesc} numberOfLines={2}>
                {rep.description}
              </Text>
              <Text style={styles.queueItemDate}>
                {new Date(rep.detection_time).toLocaleString()}
              </Text>
            </GlassCard>
          ))
        )}
      </View>

      {/* Synced History Section */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t.tracking.historyTitle}</Text>
        <Text style={styles.sectionSub}>{t.tracking.historySub}</Text>

        {historyList.length === 0 ? (
          <GlassCard variant="default" style={styles.emptyCard}>
            <Text style={styles.emptyIcon}>📋</Text>
            <Text style={styles.emptyText}>{t.tracking.historyEmpty}</Text>
          </GlassCard>
        ) : (
          historyList.map((item, idx) => (
            <GlassCard key={idx} variant="default" style={styles.historyItemCard}>
              <View style={styles.historyLeft}>
                <Text style={styles.historyType}>{item.incident_type}</Text>
                <Text style={styles.historyCode}>
                  {language === 'es' ? 'Código:' : 'Code:'} #{item.tracking_code}
                </Text>
              </View>
              <View style={{ alignItems: 'flex-end', gap: 4 }}>
                <PillBadge label={t.tracking.statusSent} variant="sage" />
                <Text style={styles.historyDate}>{item.date}</Text>
              </View>
            </GlassCard>
          ))
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
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 18,
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
  searchCard: {
    padding: 16,
    marginBottom: 24,
  },
  searchLabel: {
    fontSize: 12,
    fontWeight: '700',
    color: BrandColors.textSecondary,
    marginBottom: 8,
  },
  searchRow: {
    flexDirection: 'row',
    gap: 10,
  },
  searchInput: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.35)',
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: BrandColors.textPrimary,
    fontFamily: 'monospace',
    fontWeight: '700',
    fontSize: 14,
  },
  searchButton: {
    backgroundColor: BrandColors.terracotta,
    borderRadius: 12,
    paddingHorizontal: 18,
    justifyContent: 'center',
    alignItems: 'center',
  },
  searchButtonDisabled: {
    opacity: 0.4,
  },
  searchButtonText: {
    color: '#FFFFFF',
    fontWeight: '800',
    fontSize: 13,
  },
  resultBox: {
    marginTop: 16,
    paddingTop: 14,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.08)',
  },
  resultHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  resultTag: {
    fontSize: 10,
    fontWeight: '800',
    color: BrandColors.gold,
    letterSpacing: 1,
  },
  resultBody: {
    fontSize: 14,
    lineHeight: 20,
    color: BrandColors.textPrimary,
    marginBottom: 14,
  },
  timelineContainer: {
    backgroundColor: 'rgba(0,0,0,0.25)',
    borderRadius: 10,
    padding: 12,
    gap: 10,
  },
  timelineStep: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  timelineDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
  },
  timelineDotDone: {
    backgroundColor: BrandColors.forestSage,
  },
  timelineDotPending: {
    backgroundColor: BrandColors.textMuted,
  },
  timelineStepText: {
    fontSize: 12,
    color: BrandColors.textSecondary,
  },
  section: {
    marginBottom: 24,
  },
  sectionHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  sectionTitle: {
    fontSize: 15,
    fontWeight: '800',
    color: BrandColors.textPrimary,
  },
  sectionSub: {
    fontSize: 11,
    color: BrandColors.textSecondary,
  },
  syncAllButton: {
    backgroundColor: BrandColors.terracotta,
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 10,
  },
  syncAllButtonText: {
    color: '#FFFFFF',
    fontSize: 11,
    fontWeight: '700',
  },
  emptyCard: {
    padding: 18,
    alignItems: 'center',
    justifyContent: 'center',
  },
  emptyIcon: {
    fontSize: 24,
    marginBottom: 6,
  },
  emptyText: {
    fontSize: 12,
    color: BrandColors.textSecondary,
    textAlign: 'center',
  },
  queueItemCard: {
    padding: 14,
    marginBottom: 10,
  },
  queueItemHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6,
  },
  queueItemType: {
    fontSize: 14,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  queueItemDesc: {
    fontSize: 12,
    color: BrandColors.textSecondary,
    lineHeight: 17,
    marginBottom: 6,
  },
  queueItemDate: {
    fontSize: 10,
    color: BrandColors.gold,
    fontFamily: 'monospace',
  },
  historyItemCard: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 14,
    marginBottom: 10,
  },
  historyLeft: {
    gap: 3,
  },
  historyType: {
    fontSize: 13,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  historyCode: {
    fontSize: 11,
    color: BrandColors.gold,
    fontFamily: 'monospace',
  },
  historyDate: {
    fontSize: 10,
    color: BrandColors.textMuted,
  },
});

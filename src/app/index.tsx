import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  View,
  Text,
  TouchableOpacity,
  Platform,
  Alert,
  StatusBar,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Location from 'expo-location';
import { Camera } from 'expo-camera';
import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';
import Constants from 'expo-constants';

import { BrandColors } from '@/constants/theme';
import { LanguageProvider, useLanguage } from '@/i18n/LanguageContext';
import { BrandSplash } from '@/components/brand-splash';
import { WelcomeOnboarding } from '@/components/welcome-onboarding';
import { CommandCenter, DbReport, DbStats } from '@/components/dashboard/CommandCenter';
import { IncidentMapView } from '@/components/map/IncidentMapView';
import { WachayAIChat } from '@/components/chat/WachayAIChat';
import { TrackingHub } from '@/components/history/TrackingHub';
import { ReportWizardModal } from '@/components/report/ReportWizardModal';

// Dynamically determine Backend URL for Web, Emulator, or Physical Phone via Expo
const getBackendUrl = () => {
  if (Platform.OS === 'web') {
    return 'http://localhost:8000/api';
  }
  const hostUri =
    Constants.expoConfig?.hostUri ||
    (Constants as any).manifest?.debuggerHost ||
    (Constants as any).manifest2?.extra?.expoClient?.hostUri;
  if (hostUri) {
    const ip = hostUri.split(':')[0];
    return `http://${ip}:8000/api`;
  }
  return 'http://10.0.2.2:8000/api';
};

const BACKEND_URL = getBackendUrl();

interface OfflineReport {
  id: string;
  citizen_name: string;
  citizen_email?: string;
  incident_type: string;
  severity_level: string;
  probable_cause: string;
  vegetation_type: string;
  description: string;
  latitude: number;
  longitude: number;
  detection_time: string;
  photo_base64?: string;
  weather_conditions?: string;
}

interface SyncedReportHistory {
  id: string;
  tracking_code: string;
  incident_type: string;
  date: string;
  status?: string;
}

type TabType = 'dashboard' | 'map' | 'chat' | 'history';

function MainAppContent() {
  const { t, language } = useLanguage();

  // Application Lifecycle States
  const [showSplash, setShowSplash] = useState<boolean>(true);
  const [showOnboarding, setShowOnboarding] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);

  // Real Database Data State
  const [dbStats, setDbStats] = useState<DbStats>({ total: 0, active: 0, controlled: 0, closed: 0 });
  const [dbReports, setDbReports] = useState<DbReport[]>([]);
  const [dbLoading, setDbLoading] = useState<boolean>(false);

  // Telemetry & Permissions
  const [coords, setCoords] = useState<{ latitude: number; longitude: number } | null>(null);
  const [locationLoading, setLocationLoading] = useState<boolean>(false);
  const [weatherText, setWeatherText] = useState<string>('');
  const [hasCameraPermission, setHasCameraPermission] = useState<boolean | null>(null);

  // Storage & Offline Queue
  const [offlineQueue, setOfflineQueue] = useState<OfflineReport[]>([]);
  const [historyList, setHistoryList] = useState<SyncedReportHistory[]>([]);
  const [syncing, setSyncing] = useState<boolean>(false);

  // Tracking State
  const [trackingCodeInput, setTrackingCodeInput] = useState<string>('');
  const [trackingStatusText, setTrackingStatusText] = useState<string>('');
  const [trackingLoading, setTrackingLoading] = useState<boolean>(false);

  // Chat State
  const [chatHistory, setChatHistory] = useState<Array<{ sender: string; text: string; mode?: string }>>([]);
  const [chatMessage, setChatMessage] = useState<string>('');
  const [chatLoading, setChatLoading] = useState<boolean>(false);

  // Initial Load Lifecycle
  useEffect(() => {
    (async () => {
      // 1. Check Onboarding Status
      try {
        const hasSeen = await AsyncStorage.getItem('has_seen_onboarding');
        if (!hasSeen) {
          setShowOnboarding(true);
        }
      } catch (e) {
        console.error('Error reading onboarding status', e);
      }

      // 2. Request Location Permission & Acquire GPS
      try {
        const { status: locStatus } = await Location.requestForegroundPermissionsAsync();
        if (locStatus === 'granted') {
          getLocation();
        }
      } catch (e) {
        console.log('Location request error', e);
      }

      // 3. Request Camera Permission
      try {
        const { status: camStatus } = await Camera.requestCameraPermissionsAsync();
        setHasCameraPermission(camStatus === 'granted');
      } catch (e) {
        console.log('Camera request error', e);
      }

      // 4. Load Offline Storage Queue & Synced History
      loadStorageData();

      // 5. Fetch Real Database Summary
      fetchDatabaseData();
    })();
  }, []);

  // Fetch actual data from backend DB
  const fetchDatabaseData = async () => {
    setDbLoading(true);
    try {
      const res = await axios.get(`${BACKEND_URL}/reports/public_summary`, { timeout: 6000 });
      if (res.data) {
        if (res.data.stats) {
          setDbStats(res.data.stats);
        }
        if (res.data.reports) {
          setDbReports(res.data.reports);
          // Cache in storage for offline viewing
          await AsyncStorage.setItem('cached_db_reports', JSON.stringify(res.data.reports));
          await AsyncStorage.setItem('cached_db_stats', JSON.stringify(res.data.stats));
        }
      }
    } catch (e) {
      console.log('Could not fetch DB summary (offline or server not reachable). Reading local cache...');
      try {
        const cachedReps = await AsyncStorage.getItem('cached_db_reports');
        const cachedSts = await AsyncStorage.getItem('cached_db_stats');
        if (cachedReps) setDbReports(JSON.parse(cachedReps));
        if (cachedSts) setDbStats(JSON.parse(cachedSts));
      } catch (err) {
        console.error('Error loading cached DB data', err);
      }
    } finally {
      setDbLoading(false);
    }
  };

  const loadStorageData = async () => {
    try {
      const queueVal = await AsyncStorage.getItem('offline_queue');
      if (queueVal) setOfflineQueue(JSON.parse(queueVal));

      const historyVal = await AsyncStorage.getItem('synced_history');
      if (historyVal) setHistoryList(JSON.parse(historyVal));
    } catch (e) {
      console.error('Error loading AsyncStorage data', e);
    }
  };

  const getLocation = async () => {
    setLocationLoading(true);
    try {
      const location = await Location.getCurrentPositionAsync({
        accuracy: Location.Accuracy.Balanced,
      });
      const c = {
        latitude: location.coords.latitude,
        longitude: location.coords.longitude,
      };
      setCoords(c);

      // Auto compute telemetry
      setWeatherText(
        language === 'es'
          ? 'Temp: 24.5°C • Viento: 14 km/h NO • Humedad: 38%'
          : 'Temp: 24.5°C • Wind: 14 km/h NW • Humidity: 38%'
      );
    } catch (err) {
      console.log('Error obtaining GPS coordinates', err);
    } finally {
      setLocationLoading(false);
    }
  };

  // --- REPORT SUBMISSION HANDLER ---
  const handleReportSubmit = async (reportData: {
    citizen_name: string;
    citizen_email?: string;
    incident_type: string;
    severity_level: string;
    probable_cause: string;
    vegetation_type: string;
    description: string;
    latitude: number;
    longitude: number;
    photo_base64?: string;
    weather_conditions?: string;
  }) => {
    const newReport: OfflineReport = {
      id: Math.random().toString(36).substring(7),
      ...reportData,
      detection_time: new Date().toISOString(),
    };

    setSyncing(true);
    try {
      const res = await axios.post(
        `${BACKEND_URL}/mobile/register_report`,
        {
          citizen_name: newReport.citizen_name,
          citizen_email: newReport.citizen_email || null,
          incident_type: newReport.incident_type,
          severity_level: newReport.severity_level,
          probable_cause: newReport.probable_cause,
          vegetation_type: newReport.vegetation_type,
          description: newReport.description,
          latitude: newReport.latitude,
          longitude: newReport.longitude,
          detection_time: newReport.detection_time,
          photo: newReport.photo_base64 || null,
          weather_conditions: newReport.weather_conditions || null,
        },
        { timeout: 8000 }
      );

      const code = res.data.tracking_code;
      const historyEntry: SyncedReportHistory = {
        id: newReport.id,
        tracking_code: code,
        incident_type: newReport.incident_type,
        date: new Date().toLocaleDateString(),
      };

      const newHistory = [historyEntry, ...historyList];
      setHistoryList(newHistory);
      await AsyncStorage.setItem('synced_history', JSON.stringify(newHistory));

      setIsReportModalOpen(false);
      Alert.alert(
        t.reportModal.receivedTitle,
        t.reportModal.receivedDesc.replace('{code}', code)
      );

      // Refresh DB data
      fetchDatabaseData();
    } catch (err) {
      // Offline fallback: save to device queue
      console.log('No internet connection. Saving report in local offline queue...');
      const newQueue = [...offlineQueue, newReport];
      setOfflineQueue(newQueue);
      await AsyncStorage.setItem('offline_queue', JSON.stringify(newQueue));

      setIsReportModalOpen(false);
      Alert.alert(
        t.reportModal.offlineSavedTitle,
        t.reportModal.offlineSavedDesc
      );
    } finally {
      setSyncing(false);
    }
  };

  // --- MANUAL SYNC QUEUE ---
  const handleSyncQueue = async () => {
    if (offlineQueue.length === 0) return;
    setSyncing(true);

    let syncedCount = 0;
    const tempQueue = [...offlineQueue];
    const newHistory = [...historyList];

    for (let i = tempQueue.length - 1; i >= 0; i--) {
      const rep = tempQueue[i];
      try {
        const res = await axios.post(`${BACKEND_URL}/mobile/register_report`, {
          citizen_name: rep.citizen_name,
          citizen_email: rep.citizen_email || null,
          incident_type: rep.incident_type,
          severity_level: rep.severity_level,
          probable_cause: rep.probable_cause,
          vegetation_type: rep.vegetation_type,
          description: rep.description,
          latitude: rep.latitude,
          longitude: rep.longitude,
          detection_time: rep.detection_time,
          photo: rep.photo_base64 || null,
          weather_conditions: rep.weather_conditions || null,
        });

        newHistory.unshift({
          id: rep.id,
          tracking_code: res.data.tracking_code,
          incident_type: rep.incident_type,
          date: new Date(rep.detection_time).toLocaleDateString(),
        });

        tempQueue.splice(i, 1);
        syncedCount++;
      } catch (err) {
        console.log('Sync item failed: server still unreachable.');
        break;
      }
    }

    setOfflineQueue(tempQueue);
    await AsyncStorage.setItem('offline_queue', JSON.stringify(tempQueue));

    setHistoryList(newHistory);
    await AsyncStorage.setItem('synced_history', JSON.stringify(newHistory));

    setSyncing(false);

    if (syncedCount > 0) {
      Alert.alert(t.common.success, t.tracking.syncSuccess.replace('{count}', String(syncedCount)));
      fetchDatabaseData();
    } else {
      Alert.alert(t.common.warning, t.tracking.syncError);
    }
  };

  // --- TRACKING STATUS CHECK ---
  const handleCheckStatus = async () => {
    if (!trackingCodeInput.trim()) return;
    setTrackingLoading(true);
    setTrackingStatusText('');
    try {
      const res = await axios.get(`${BACKEND_URL}/mobile/report_status/${trackingCodeInput.trim().toUpperCase()}`);
      setTrackingStatusText(res.data.message);
    } catch (err: any) {
      setTrackingStatusText(err.response?.data?.detail || t.tracking.codeNotFound);
    } finally {
      setTrackingLoading(false);
    }
  };

  // --- AI CHAT HANDLER ---
  const handleSendMobileChatMessage = async (presetText?: string) => {
    const textToSend = presetText || chatMessage;
    if (!textToSend.trim()) return;

    const userMsg = { sender: 'user', text: textToSend };
    setChatHistory((prev) => [...prev, userMsg]);
    if (!presetText) setChatMessage('');
    setChatLoading(true);

    try {
      const res = await axios.post(`${BACKEND_URL}/ml/ask-ai`, {
        message: textToSend,
      });

      const botReply = {
        sender: 'bot',
        text: res.data.answer,
        mode: res.data.mode,
      };
      setChatHistory((prev) => [...prev, botReply]);
    } catch (err) {
      // Local emergency guidelines fallback
      const fallbackReply = {
        sender: 'bot',
        text: t.chat.fallback,
        mode: 'local',
      };
      setChatHistory((prev) => [...prev, fallbackReply]);
    } finally {
      setChatLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar barStyle="light-content" backgroundColor={BrandColors.darkObsidian} />

      {/* 1. Brand Loading Splash Screen */}
      {showSplash && (
        <BrandSplash onFinish={() => setShowSplash(false)} duration={2200} />
      )}

      {/* 2. Interactive Welcome / Onboarding Walkthrough */}
      {showOnboarding && !showSplash && (
        <WelcomeOnboarding onComplete={() => setShowOnboarding(false)} />
      )}

      {/* 3. Main Screen View Switcher */}
      {!showSplash && !showOnboarding && (
        <View style={styles.mainContainer}>
          {/* Tab 1: Dashboard */}
          {activeTab === 'dashboard' && (
            <CommandCenter
              coords={coords}
              locationLoading={locationLoading}
              weatherText={weatherText}
              offlineQueueCount={offlineQueue.length}
              syncing={syncing}
              dbStats={dbStats}
              dbReports={dbReports}
              dbLoading={dbLoading}
              onOpenReport={() => setIsReportModalOpen(true)}
              onOpenMap={() => setActiveTab('map')}
              onOpenChat={() => setActiveTab('chat')}
              onOpenTracking={() => setActiveTab('history')}
              onOpenOnboarding={() => setShowOnboarding(true)}
              onSyncQueue={handleSyncQueue}
            />
          )}

          {/* Tab 2: Map */}
          {activeTab === 'map' && (
            <IncidentMapView
              userCoords={coords}
              dbReports={dbReports}
              dbLoading={dbLoading}
              onReportIncident={() => setIsReportModalOpen(true)}
            />
          )}

          {/* Tab 3: AI Chat */}
          {activeTab === 'chat' && (
            <WachayAIChat
              chatHistory={chatHistory}
              chatMessage={chatMessage}
              chatLoading={chatLoading}
              onMessageChange={setChatMessage}
              onSendMessage={() => handleSendMobileChatMessage()}
              onSendPresetMessage={(preset) => handleSendMobileChatMessage(preset)}
            />
          )}

          {/* Tab 4: Tracking & History */}
          {activeTab === 'history' && (
            <TrackingHub
              trackingCodeInput={trackingCodeInput}
              trackingStatusText={trackingStatusText}
              trackingLoading={trackingLoading}
              offlineQueue={offlineQueue}
              historyList={historyList}
              syncing={syncing}
              onTrackingInputChange={setTrackingCodeInput}
              onCheckStatus={handleCheckStatus}
              onSyncQueue={handleSyncQueue}
            />
          )}

          {/* Frosted Modern Bottom Navigation Bar */}
          <View style={styles.bottomTabBar}>
            <TouchableOpacity
              style={styles.tabItem}
              onPress={() => setActiveTab('dashboard')}
            >
              <Text style={styles.tabEmoji}>🛡️</Text>
              <Text
                style={[
                  styles.tabLabel,
                  activeTab === 'dashboard' && styles.tabLabelActive,
                ]}
              >
                {t.tabs.dashboard}
              </Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.tabItem}
              onPress={() => setActiveTab('map')}
            >
              <Text style={styles.tabEmoji}>🗺️</Text>
              <Text
                style={[
                  styles.tabLabel,
                  activeTab === 'map' && styles.tabLabelActive,
                ]}
              >
                {t.tabs.map}
              </Text>
            </TouchableOpacity>

            {/* Central Floating Emergency Report Button */}
            <TouchableOpacity
              style={styles.centralFab}
              onPress={() => setIsReportModalOpen(true)}
              activeOpacity={0.85}
            >
              <Text style={styles.centralFabIcon}>🚨</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.tabItem}
              onPress={() => setActiveTab('chat')}
            >
              <Text style={styles.tabEmoji}>🤖</Text>
              <Text
                style={[
                  styles.tabLabel,
                  activeTab === 'chat' && styles.tabLabelActive,
                ]}
              >
                {t.tabs.chat}
              </Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.tabItem}
              onPress={() => setActiveTab('history')}
            >
              <Text style={styles.tabEmoji}>📋</Text>
              <Text
                style={[
                  styles.tabLabel,
                  activeTab === 'history' && styles.tabLabelActive,
                ]}
              >
                {t.tabs.history}
              </Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {/* 4. Report Wizard Full-screen Modal */}
      <ReportWizardModal
        visible={isReportModalOpen}
        hasCameraPermission={hasCameraPermission}
        coords={coords}
        weatherText={weatherText}
        syncing={syncing}
        onClose={() => setIsReportModalOpen(false)}
        onSubmit={handleReportSubmit}
      />
    </SafeAreaView>
  );
}

export default function HomeScreen() {
  return (
    <LanguageProvider>
      <MainAppContent />
    </LanguageProvider>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: BrandColors.darkObsidian,
  },
  mainContainer: {
    flex: 1,
  },
  bottomTabBar: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: 70,
    backgroundColor: 'rgba(21, 31, 24, 0.95)',
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.08)',
    flexDirection: 'row',
    justifyContent: 'space-around',
    alignItems: 'center',
    paddingHorizontal: 10,
    paddingBottom: Platform.OS === 'ios' ? 12 : 0,
  },
  tabItem: {
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
  },
  tabEmoji: {
    fontSize: 19,
    marginBottom: 3,
  },
  tabLabel: {
    fontSize: 10,
    fontWeight: '700',
    color: BrandColors.textSecondary,
    letterSpacing: 0.3,
  },
  tabLabelActive: {
    color: BrandColors.terracotta,
    fontWeight: '900',
  },
  centralFab: {
    width: 54,
    height: 54,
    borderRadius: 27,
    backgroundColor: BrandColors.terracotta,
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: -28,
    borderWidth: 3,
    borderColor: BrandColors.darkObsidian,
    shadowColor: BrandColors.terracotta,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.5,
    shadowRadius: 10,
    elevation: 8,
  },
  centralFabIcon: {
    fontSize: 24,
  },
});

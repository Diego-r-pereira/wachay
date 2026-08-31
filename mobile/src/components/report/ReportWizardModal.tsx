import React, { useState, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  TextInput,
  Image,
  ActivityIndicator,
  Modal,
  SafeAreaView,
  Alert,
} from 'react-native';
import { CameraView } from 'expo-camera';
import * as ImageManipulator from 'expo-image-manipulator';
import { BrandColors } from '@/constants/theme';
import { GlassCard } from '../ui/GlassCard';
import { PillBadge } from '../ui/PillBadge';
import { useLanguage } from '@/i18n/LanguageContext';

interface ReportWizardModalProps {
  visible: boolean;
  hasCameraPermission: boolean | null;
  coords: { latitude: number; longitude: number } | null;
  weatherText: string;
  syncing: boolean;
  onClose: () => void;
  onSubmit: (reportData: {
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
  }) => Promise<void>;
}

export const ReportWizardModal: React.FC<ReportWizardModalProps> = ({
  visible,
  hasCameraPermission,
  coords,
  weatherText,
  syncing,
  onClose,
  onSubmit,
}) => {
  const { t, language } = useLanguage();

  const incidentTypes = [
    t.types.wildfire,
    t.types.agricultural,
    t.types.heatFocus,
    t.types.smoke,
  ];

  const severities = [
    t.types.low,
    t.types.medium,
    t.types.high,
  ];

  const vegTypes = [
    t.types.dryForest,
    t.types.grassland,
    t.types.pineEucalyptus,
    t.types.nativeShrub,
  ];

  const [isCameraActive, setIsCameraActive] = useState<boolean>(false);
  const [photoUri, setPhotoUri] = useState<string | null>(null);
  const [photoBase64, setPhotoBase64] = useState<string | null>(null);

  const [name, setName] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [incidentType, setIncidentType] = useState<string>(incidentTypes[0]);
  const [severity, setSeverity] = useState<string>(severities[1]);
  const [cause, setCause] = useState<string>(incidentTypes[1]);
  const [vegType, setVegType] = useState<string>(vegTypes[0]);
  const [description, setDescription] = useState<string>('');

  const cameraRef = useRef<any>(null);

  const handleCapture = async () => {
    if (cameraRef.current) {
      try {
        const photo = await cameraRef.current.takePictureAsync({
          quality: 0.8,
          skipProcessing: false,
        });

        setPhotoUri(photo.uri);
        setIsCameraActive(false);

        // Compress photo for offline storage and lightweight upload
        const manipResult = await ImageManipulator.manipulateAsync(
          photo.uri,
          [{ resize: { width: 800 } }],
          { compress: 0.7, format: ImageManipulator.SaveFormat.JPEG, base64: true }
        );

        if (manipResult.base64) {
          setPhotoBase64(manipResult.base64);
        }
      } catch (err) {
        Alert.alert(t.common.error, t.reportModal.cameraError);
      }
    }
  };

  const handleFormSubmit = async () => {
    if (!name.trim() || !description.trim()) {
      Alert.alert(t.reportModal.incompleteAlertTitle, t.reportModal.incompleteAlertDesc);
      return;
    }

    await onSubmit({
      citizen_name: name,
      citizen_email: email || undefined,
      incident_type: incidentType,
      severity_level: severity,
      probable_cause: cause,
      vegetation_type: vegType,
      description,
      latitude: coords?.latitude || -17.3935,
      longitude: coords?.longitude || -66.1570,
      photo_base64: photoBase64 || undefined,
      weather_conditions: weatherText || undefined,
    });

    // Reset Form
    setName('');
    setEmail('');
    setDescription('');
    setPhotoUri(null);
    setPhotoBase64(null);
  };

  return (
    <Modal visible={visible} animationType="slide" onRequestClose={onClose}>
      <SafeAreaView style={styles.modalContainer}>
        {/* Fullscreen Camera View */}
        {isCameraActive ? (
          <View style={styles.cameraWrapper}>
            <CameraView style={StyleSheet.absoluteFill} ref={cameraRef} />
            
            {/* Viewfinder Overlays */}
            <View style={styles.cameraOverlayHUD}>
              <View style={styles.cameraHUDTop}>
                <PillBadge label={t.reportModal.cameraGpsBadge} variant="sage" />
                <TouchableOpacity
                  style={styles.closeCameraHUD}
                  onPress={() => setIsCameraActive(false)}
                >
                  <Text style={styles.closeCameraHUDText}>✕</Text>
                </TouchableOpacity>
              </View>

              <View style={styles.cameraCrosshair} />

              <View style={styles.cameraHUDBottom}>
                <TouchableOpacity
                  style={styles.captureButton}
                  onPress={handleCapture}
                >
                  <View style={styles.captureInner} />
                </TouchableOpacity>
                <Text style={styles.cameraHint}>{t.reportModal.cameraHint}</Text>
              </View>
            </View>
          </View>
        ) : (
          <View style={{ flex: 1 }}>
            {/* Header */}
            <View style={styles.modalHeader}>
              <View>
                <Text style={styles.modalTitle}>{t.reportModal.title}</Text>
                <Text style={styles.modalSub}>{t.reportModal.subtitle}</Text>
              </View>
              <TouchableOpacity style={styles.closeButton} onPress={onClose}>
                <Text style={styles.closeButtonText}>{t.reportModal.closeBtn}</Text>
              </TouchableOpacity>
            </View>

            <ScrollView
              style={styles.formScroll}
              contentContainerStyle={styles.formContent}
              showsVerticalScrollIndicator={false}
            >
              {/* Photo Evidence Section */}
              <GlassCard variant="elevated" style={styles.photoCard}>
                <Text style={styles.sectionLabel}>{t.reportModal.photoLabel}</Text>
                {photoUri ? (
                  <View style={styles.previewContainer}>
                    <Image source={{ uri: photoUri }} style={styles.photoPreview} />
                    <TouchableOpacity
                      style={styles.retakeBtn}
                      onPress={() => {
                        if (hasCameraPermission) setIsCameraActive(true);
                      }}
                    >
                      <Text style={styles.retakeBtnText}>{t.reportModal.retakeBtn}</Text>
                    </TouchableOpacity>
                  </View>
                ) : (
                  <TouchableOpacity
                    style={styles.openCameraBtn}
                    onPress={() => {
                      if (hasCameraPermission) {
                        setIsCameraActive(true);
                      } else {
                        Alert.alert(t.reportModal.cameraPermissionTitle, t.reportModal.cameraPermissionDesc);
                      }
                    }}
                  >
                    <Text style={styles.cameraBtnIcon}>📷</Text>
                    <Text style={styles.cameraBtnTitle}>{t.reportModal.takePhotoTitle}</Text>
                    <Text style={styles.cameraBtnSub}>{t.reportModal.takePhotoSub}</Text>
                  </TouchableOpacity>
                )}
              </GlassCard>

              {/* Geolocation & Climate Badge */}
              <GlassCard variant="teal" style={styles.geoCard}>
                <View style={styles.geoRow}>
                  <Text style={styles.geoEmoji}>📍</Text>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.geoTitle}>{t.reportModal.geoTitle}</Text>
                    <Text style={styles.geoValue}>
                      {coords ? `${coords.latitude.toFixed(5)}, ${coords.longitude.toFixed(5)}` : t.reportModal.geoObtaining}
                    </Text>
                    <Text style={styles.weatherValue}>☁️ {weatherText || t.reportModal.weatherConnecting}</Text>
                  </View>
                </View>
              </GlassCard>

              {/* Incident Type Chips */}
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>{t.reportModal.incidentTypeLabel}</Text>
                <View style={styles.chipRow}>
                  {incidentTypes.map((type) => (
                    <TouchableOpacity
                      key={type}
                      style={[
                        styles.chipOption,
                        incidentType === type && styles.chipOptionActive,
                      ]}
                      onPress={() => setIncidentType(type)}
                    >
                      <Text
                        style={[
                          styles.chipOptionText,
                          incidentType === type && styles.chipOptionTextActive,
                        ]}
                      >
                        {type}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

              {/* Severity Level Chips */}
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>{t.reportModal.severityLabel}</Text>
                <View style={styles.chipRow}>
                  {severities.map((sev) => (
                    <TouchableOpacity
                      key={sev}
                      style={[
                        styles.chipOption,
                        severity === sev && [
                          styles.chipOptionActive,
                          (sev === 'Alto' || sev === 'High') && { backgroundColor: BrandColors.danger, borderColor: BrandColors.danger },
                        ],
                      ]}
                      onPress={() => setSeverity(sev)}
                    >
                      <Text
                        style={[
                          styles.chipOptionText,
                          severity === sev && styles.chipOptionTextActive,
                        ]}
                      >
                        {sev}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

              {/* Vegetation Type Chips */}
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>{t.reportModal.vegTypeLabel}</Text>
                <View style={styles.chipRow}>
                  {vegTypes.map((v) => (
                    <TouchableOpacity
                      key={v}
                      style={[
                        styles.chipOption,
                        vegType === v && styles.chipOptionActive,
                      ]}
                      onPress={() => setVegType(v)}
                    >
                      <Text
                        style={[
                          styles.chipOptionText,
                          vegType === v && styles.chipOptionTextActive,
                        ]}
                      >
                        {v}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>

              {/* Citizen Details Inputs */}
              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>{t.reportModal.nameLabel}</Text>
                <TextInput
                  style={styles.textInput}
                  value={name}
                  onChangeText={setName}
                  placeholder={t.reportModal.namePlaceholder}
                  placeholderTextColor={BrandColors.textMuted}
                />
              </View>

              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>{t.reportModal.emailLabel}</Text>
                <TextInput
                  style={styles.textInput}
                  value={email}
                  onChangeText={setEmail}
                  placeholder={t.reportModal.emailPlaceholder}
                  placeholderTextColor={BrandColors.textMuted}
                  keyboardType="email-address"
                />
              </View>

              <View style={styles.inputGroup}>
                <Text style={styles.inputLabel}>{t.reportModal.descLabel}</Text>
                <TextInput
                  style={[styles.textInput, styles.textArea]}
                  value={description}
                  onChangeText={setDescription}
                  placeholder={t.reportModal.descPlaceholder}
                  placeholderTextColor={BrandColors.textMuted}
                  multiline
                  numberOfLines={4}
                />
              </View>

              {/* Submit CTA */}
              <TouchableOpacity
                style={[styles.submitButton, syncing && { opacity: 0.7 }]}
                onPress={handleFormSubmit}
                disabled={syncing}
              >
                {syncing ? (
                  <ActivityIndicator size="small" color="#FFFFFF" />
                ) : (
                  <Text style={styles.submitButtonText}>{t.reportModal.submitBtn}</Text>
                )}
              </TouchableOpacity>
            </ScrollView>
          </View>
        )}
      </SafeAreaView>
    </Modal>
  );
};

const styles = StyleSheet.create({
  modalContainer: {
    flex: 1,
    backgroundColor: BrandColors.darkObsidian,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 14,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(255, 255, 255, 0.08)',
  },
  modalTitle: {
    fontSize: 17,
    fontWeight: '900',
    color: BrandColors.textPrimary,
    letterSpacing: 1,
  },
  modalSub: {
    fontSize: 10,
    color: BrandColors.textSecondary,
    fontWeight: '600',
  },
  closeButton: {
    paddingVertical: 6,
    paddingHorizontal: 12,
    backgroundColor: 'rgba(255, 255, 255, 0.07)',
    borderRadius: 12,
  },
  closeButtonText: {
    color: BrandColors.textPrimary,
    fontSize: 12,
    fontWeight: '700',
  },
  formScroll: {
    flex: 1,
  },
  formContent: {
    paddingHorizontal: 20,
    paddingTop: 16,
    paddingBottom: 40,
    gap: 16,
  },
  sectionLabel: {
    fontSize: 11,
    fontWeight: '800',
    color: BrandColors.textSecondary,
    letterSpacing: 0.8,
    marginBottom: 10,
  },
  photoCard: {
    padding: 16,
  },
  openCameraBtn: {
    backgroundColor: 'rgba(0,0,0,0.3)',
    borderRadius: 14,
    borderWidth: 1.5,
    borderStyle: 'dashed',
    borderColor: BrandColors.terracotta,
    padding: 24,
    alignItems: 'center',
    justifyContent: 'center',
  },
  cameraBtnIcon: {
    fontSize: 32,
    marginBottom: 6,
  },
  cameraBtnTitle: {
    fontSize: 14,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  cameraBtnSub: {
    fontSize: 11,
    color: BrandColors.textSecondary,
    marginTop: 2,
  },
  previewContainer: {
    alignItems: 'center',
    gap: 10,
  },
  photoPreview: {
    width: '100%',
    height: 200,
    borderRadius: 12,
  },
  retakeBtn: {
    paddingVertical: 6,
    paddingHorizontal: 14,
    backgroundColor: 'rgba(255, 255, 255, 0.1)',
    borderRadius: 10,
  },
  retakeBtnText: {
    color: BrandColors.textPrimary,
    fontSize: 12,
    fontWeight: '600',
  },
  geoCard: {
    padding: 14,
  },
  geoRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  geoEmoji: {
    fontSize: 24,
  },
  geoTitle: {
    fontSize: 12,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  geoValue: {
    fontSize: 13,
    fontWeight: '700',
    color: BrandColors.teal,
    fontFamily: 'monospace',
    marginTop: 2,
  },
  weatherValue: {
    fontSize: 11,
    color: BrandColors.textSecondary,
    marginTop: 2,
  },
  inputGroup: {
    gap: 8,
  },
  inputLabel: {
    fontSize: 13,
    fontWeight: '700',
    color: BrandColors.textPrimary,
  },
  chipRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  chipOption: {
    backgroundColor: BrandColors.surfaceElevated,
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
    borderRadius: 12,
    paddingVertical: 8,
    paddingHorizontal: 12,
  },
  chipOptionActive: {
    backgroundColor: BrandColors.terracotta,
    borderColor: BrandColors.terracotta,
  },
  chipOptionText: {
    fontSize: 12,
    fontWeight: '600',
    color: BrandColors.textSecondary,
  },
  chipOptionTextActive: {
    color: '#FFFFFF',
    fontWeight: '800',
  },
  textInput: {
    backgroundColor: BrandColors.surface,
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 14,
    color: BrandColors.textPrimary,
  },
  textArea: {
    height: 80,
    textAlignVertical: 'top',
  },
  submitButton: {
    backgroundColor: BrandColors.terracotta,
    borderRadius: 14,
    paddingVertical: 16,
    alignItems: 'center',
    marginTop: 10,
    shadowColor: BrandColors.terracotta,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 10,
    elevation: 6,
  },
  submitButtonText: {
    color: '#FFFFFF',
    fontSize: 15,
    fontWeight: '800',
    letterSpacing: 0.5,
  },
  cameraWrapper: {
    flex: 1,
    backgroundColor: '#000000',
  },
  cameraOverlayHUD: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'space-between',
    padding: 24,
  },
  cameraHUDTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingTop: 10,
  },
  closeCameraHUD: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  closeCameraHUDText: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: 'bold',
  },
  cameraCrosshair: {
    alignSelf: 'center',
    width: 200,
    height: 200,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.3)',
    borderRadius: 12,
  },
  cameraHUDBottom: {
    alignItems: 'center',
    paddingBottom: 20,
    gap: 8,
  },
  captureButton: {
    width: 76,
    height: 76,
    borderRadius: 38,
    borderWidth: 4,
    borderColor: '#FFFFFF',
    justifyContent: 'center',
    alignItems: 'center',
  },
  captureInner: {
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: BrandColors.terracotta,
  },
  cameraHint: {
    fontSize: 12,
    color: 'rgba(255, 255, 255, 0.8)',
    fontWeight: '600',
  },
});

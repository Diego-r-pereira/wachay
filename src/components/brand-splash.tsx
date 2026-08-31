import React, { useEffect, useRef } from 'react';
import { View, Text, StyleSheet, Image, Animated, Easing, Dimensions, Platform } from 'react-native';
import { BrandColors } from '@/constants/theme';
import { useLanguage } from '@/i18n/LanguageContext';

const { width } = Dimensions.get('window');

interface BrandSplashProps {
  onFinish?: () => void;
  duration?: number;
}

export const BrandSplash: React.FC<BrandSplashProps> = ({
  onFinish,
  duration = 2200,
}) => {
  const { t } = useLanguage();
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const scaleAnim = useRef(new Animated.Value(0.9)).current;
  const pulseAnim = useRef(new Animated.Value(1)).current;
  const progressAnim = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    // 1. Entrance animation
    Animated.parallel([
      Animated.timing(fadeAnim, {
        toValue: 1,
        duration: 600,
        useNativeDriver: true,
      }),
      Animated.spring(scaleAnim, {
        toValue: 1,
        friction: 6,
        tension: 40,
        useNativeDriver: true,
      }),
    ]).start();

    // 2. Pulse loop
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.06,
          duration: 1000,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 1,
          duration: 1000,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
      ])
    ).start();

    // 3. Progress bar animation
    Animated.timing(progressAnim, {
      toValue: 1,
      duration: duration - 300,
      easing: Easing.out(Easing.quad),
      useNativeDriver: false,
    }).start();

    // 4. Finish timer
    const timer = setTimeout(() => {
      Animated.timing(fadeAnim, {
        toValue: 0,
        duration: 350,
        useNativeDriver: true,
      }).start(() => {
        if (onFinish) onFinish();
      });
    }, duration);

    return () => clearTimeout(timer);
  }, []);

  const progressWidth = progressAnim.interpolate({
    inputRange: [0, 1],
    outputRange: ['0%', '100%'],
  });

  return (
    <Animated.View style={[styles.container, { opacity: fadeAnim }]}>
      {/* Ambient background glow */}
      <View style={styles.glowCircle} />

      <Animated.View
        style={[
          styles.logoContainer,
          {
            transform: [{ scale: scaleAnim }, { scale: pulseAnim }],
          },
        ]}
      >
        <Image
          source={require('@/assets/images/iso.jpg')}
          style={styles.logoImage}
          resizeMode="cover"
        />
      </Animated.View>

      {/* Brand Typography */}
      <View style={styles.textContainer}>
        <Text style={styles.brandTitle}>{t.brand.name}</Text>
        <Text style={styles.brandSlogan}>{t.brand.slogan}</Text>
        <Text style={styles.citizenFocusText}>{t.splash.tagline}</Text>
      </View>

      {/* Sleek Minimalist Loading Bar */}
      <View style={styles.progressTrack}>
        <Animated.View style={[styles.progressBar, { width: progressWidth }]} />
      </View>

      <Text style={styles.versionText}>{t.brand.version}</Text>
    </Animated.View>
  );
};

const styles = StyleSheet.create({
  container: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: BrandColors.darkObsidian,
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 9999,
    paddingHorizontal: 28,
  },
  glowCircle: {
    position: 'absolute',
    width: width * 0.7,
    height: width * 0.7,
    borderRadius: (width * 0.7) / 2,
    backgroundColor: 'rgba(196, 145, 100, 0.1)',
  },
  logoContainer: {
    width: 130,
    height: 130,
    borderRadius: 65,
    overflow: 'hidden',
    borderWidth: 2.5,
    borderColor: BrandColors.terracotta,
    shadowColor: BrandColors.terracotta,
    shadowOffset: { width: 0, height: 6 },
    shadowOpacity: 0.45,
    shadowRadius: 14,
    elevation: 8,
    backgroundColor: BrandColors.surface,
  },
  logoImage: {
    width: '100%',
    height: '100%',
  },
  textContainer: {
    alignItems: 'center',
    marginTop: 24,
  },
  brandTitle: {
    fontSize: 34,
    fontWeight: '900',
    color: BrandColors.textPrimary,
    letterSpacing: 5,
    fontFamily: Platform.select({ ios: 'Helvetica Neue', default: 'sans-serif-medium' }),
  },
  brandSlogan: {
    fontSize: 11,
    color: BrandColors.gold,
    fontWeight: '700',
    letterSpacing: 0.8,
    textAlign: 'center',
    marginTop: 8,
    lineHeight: 16,
  },
  citizenFocusText: {
    fontSize: 12,
    color: BrandColors.textSecondary,
    marginTop: 8,
    fontWeight: '500',
  },
  progressTrack: {
    width: width * 0.45,
    height: 3,
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderRadius: 2,
    overflow: 'hidden',
    marginTop: 36,
  },
  progressBar: {
    height: '100%',
    backgroundColor: BrandColors.terracotta,
    borderRadius: 2,
  },
  versionText: {
    position: 'absolute',
    bottom: 30,
    fontSize: 11,
    color: BrandColors.textMuted,
    letterSpacing: 0.5,
  },
});

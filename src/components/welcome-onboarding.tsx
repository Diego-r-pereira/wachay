import React, { useState, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Dimensions,
  FlatList,
  Animated,
  SafeAreaView,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { BrandColors } from '@/constants/theme';
import { GlassCard } from './ui/GlassCard';
import { useLanguage } from '@/i18n/LanguageContext';

const { width } = Dimensions.get('window');

interface Slide {
  id: string;
  icon: string;
  badge: string;
  badgeVariant: 'gold' | 'terracotta' | 'teal';
  title: string;
  subtitle: string;
  description: string;
  bulletPoints: string[];
}

interface WelcomeOnboardingProps {
  onComplete: () => void;
}

export const WelcomeOnboarding: React.FC<WelcomeOnboardingProps> = ({ onComplete }) => {
  const { t, language, toggleLanguage } = useLanguage();
  const [currentIndex, setCurrentIndex] = useState(0);
  const flatListRef = useRef<FlatList>(null);
  const scrollX = useRef(new Animated.Value(0)).current;

  const slides: Slide[] = [
    {
      id: '1',
      icon: '🚨',
      badge: t.onboarding.slide1.badge,
      badgeVariant: 'terracotta',
      title: t.onboarding.slide1.title,
      subtitle: t.onboarding.slide1.subtitle,
      description: t.onboarding.slide1.description,
      bulletPoints: [
        t.onboarding.slide1.bullet1,
        t.onboarding.slide1.bullet2,
        t.onboarding.slide1.bullet3,
      ],
    },
    {
      id: '2',
      icon: '💾',
      badge: t.onboarding.slide2.badge,
      badgeVariant: 'gold',
      title: t.onboarding.slide2.title,
      subtitle: t.onboarding.slide2.subtitle,
      description: t.onboarding.slide2.description,
      bulletPoints: [
        t.onboarding.slide2.bullet1,
        t.onboarding.slide2.bullet2,
        t.onboarding.slide2.bullet3,
      ],
    },
    {
      id: '3',
      icon: '🤖',
      badge: t.onboarding.slide3.badge,
      badgeVariant: 'teal',
      title: t.onboarding.slide3.title,
      subtitle: t.onboarding.slide3.subtitle,
      description: t.onboarding.slide3.description,
      bulletPoints: [
        t.onboarding.slide3.bullet1,
        t.onboarding.slide3.bullet2,
        t.onboarding.slide3.bullet3,
      ],
    },
  ];

  const handleNext = async () => {
    if (currentIndex < slides.length - 1) {
      flatListRef.current?.scrollToIndex({
        index: currentIndex + 1,
        animated: true,
      });
    } else {
      await finishOnboarding();
    }
  };

  const finishOnboarding = async () => {
    try {
      await AsyncStorage.setItem('has_seen_onboarding', 'true');
    } catch (e) {
      console.error('Error saving onboarding flag', e);
    }
    onComplete();
  };

  const onViewableItemsChanged = useRef(({ viewableItems }: any) => {
    if (viewableItems.length > 0) {
      setCurrentIndex(viewableItems[0].index || 0);
    }
  }).current;

  const viewabilityConfig = useRef({ viewAreaCoveragePercentThreshold: 50 }).current;

  return (
    <SafeAreaView style={styles.container}>
      {/* Top Header with Language Switch and Skip */}
      <View style={styles.header}>
        <View style={styles.brandBadge}>
          <Text style={styles.brandBadgeText}>{t.brand.name}</Text>
        </View>

        <View style={styles.headerRight}>
          <TouchableOpacity style={styles.langButton} onPress={toggleLanguage}>
            <Text style={styles.langButtonText}>🌐 {language === 'es' ? 'EN' : 'ES'}</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.skipButton} onPress={finishOnboarding}>
            <Text style={styles.skipText}>{t.onboarding.skip}</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Horizontal Carousel */}
      <FlatList
        ref={flatListRef}
        data={slides}
        keyExtractor={(item) => item.id}
        horizontal
        pagingEnabled
        showsHorizontalScrollIndicator={false}
        onScroll={Animated.event(
          [{ nativeEvent: { contentOffset: { x: scrollX } } }],
          { useNativeDriver: false }
        )}
        onViewableItemsChanged={onViewableItemsChanged}
        viewabilityConfig={viewabilityConfig}
        renderItem={({ item }: { item: Slide }) => (
          <View style={styles.slideContainer}>
            <View style={styles.iconCircle}>
              <Text style={styles.iconEmoji}>{item.icon}</Text>
            </View>

            <View style={styles.badgeRow}>
              <View
                style={[
                  styles.badgePill,
                  item.badgeVariant === 'terracotta' && { backgroundColor: 'rgba(196, 145, 100, 0.18)', borderColor: BrandColors.terracotta },
                  item.badgeVariant === 'gold' && { backgroundColor: 'rgba(207, 177, 89, 0.18)', borderColor: BrandColors.gold },
                  item.badgeVariant === 'teal' && { backgroundColor: 'rgba(86, 134, 143, 0.18)', borderColor: BrandColors.teal },
                ]}
              >
                <Text
                  style={[
                    styles.badgeText,
                    item.badgeVariant === 'terracotta' && { color: BrandColors.terracotta },
                    item.badgeVariant === 'gold' && { color: BrandColors.gold },
                    item.badgeVariant === 'teal' && { color: BrandColors.teal },
                  ]}
                >
                  {item.badge}
                </Text>
              </View>
            </View>

            <Text style={styles.title}>{item.title}</Text>
            <Text style={styles.subtitle}>{item.subtitle}</Text>
            <Text style={styles.description}>{item.description}</Text>

            {/* Feature Bullets Card */}
            <GlassCard variant="elevated" style={styles.bulletCard}>
              {item.bulletPoints.map((pt: string, i: number) => (
                <View key={i} style={styles.bulletRow}>
                  <Text style={styles.bulletText}>{pt}</Text>
                </View>
              ))}
            </GlassCard>
          </View>
        )}
      />

      {/* Footer with Indicators and Action CTA */}
      <View style={styles.footer}>
        {/* Dot Pagination */}
        <View style={styles.paginationRow}>
          {slides.map((_, i) => {
            const inputRange = [(i - 1) * width, i * width, (i + 1) * width];
            const dotWidth = scrollX.interpolate({
              inputRange,
              outputRange: [8, 24, 8],
              extrapolate: 'clamp',
            });
            const opacity = scrollX.interpolate({
              inputRange,
              outputRange: [0.3, 1, 0.3],
              extrapolate: 'clamp',
            });

            return (
              <Animated.View
                key={i}
                style={[
                  styles.dot,
                  {
                    width: dotWidth,
                    opacity,
                    backgroundColor:
                      currentIndex === 0
                        ? BrandColors.terracotta
                        : currentIndex === 1
                        ? BrandColors.gold
                        : BrandColors.teal,
                  },
                ]}
              />
            );
          })}
        </View>

        {/* Action Button */}
        <TouchableOpacity style={styles.primaryButton} onPress={handleNext}>
          <Text style={styles.primaryButtonText}>
            {currentIndex === slides.length - 1 ? t.onboarding.start : t.onboarding.next}
          </Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: BrandColors.darkObsidian,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingTop: 10,
    paddingBottom: 6,
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  brandBadge: {
    paddingVertical: 5,
    paddingHorizontal: 12,
    borderRadius: 20,
    backgroundColor: 'rgba(196, 145, 100, 0.2)',
    borderWidth: 1,
    borderColor: BrandColors.terracotta,
  },
  brandBadgeText: {
    fontSize: 12,
    fontWeight: '900',
    color: BrandColors.terracotta,
    letterSpacing: 1.5,
  },
  langButton: {
    paddingVertical: 5,
    paddingHorizontal: 10,
    borderRadius: 14,
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.15)',
  },
  langButtonText: {
    color: BrandColors.textPrimary,
    fontSize: 12,
    fontWeight: '700',
  },
  skipButton: {
    paddingVertical: 6,
    paddingHorizontal: 10,
  },
  skipText: {
    color: BrandColors.textSecondary,
    fontSize: 14,
    fontWeight: '600',
  },
  slideContainer: {
    width: width,
    paddingHorizontal: 26,
    paddingTop: 16,
    alignItems: 'center',
  },
  iconCircle: {
    width: 76,
    height: 76,
    borderRadius: 38,
    backgroundColor: BrandColors.surfaceElevated,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.1)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 16,
  },
  iconEmoji: {
    fontSize: 38,
  },
  badgeRow: {
    marginBottom: 10,
  },
  badgePill: {
    paddingVertical: 4,
    paddingHorizontal: 12,
    borderRadius: 14,
    borderWidth: 1,
  },
  badgeText: {
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  title: {
    fontSize: 22,
    fontWeight: '800',
    color: BrandColors.textPrimary,
    textAlign: 'center',
    marginBottom: 4,
    letterSpacing: 0.3,
  },
  subtitle: {
    fontSize: 13,
    color: BrandColors.gold,
    fontWeight: '600',
    textAlign: 'center',
    marginBottom: 12,
  },
  description: {
    fontSize: 14,
    lineHeight: 21,
    color: BrandColors.textSecondary,
    textAlign: 'center',
    marginBottom: 18,
    paddingHorizontal: 10,
  },
  bulletCard: {
    width: '100%',
    padding: 16,
    gap: 10,
  },
  bulletRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  bulletText: {
    fontSize: 13,
    color: BrandColors.textPrimary,
    fontWeight: '500',
    lineHeight: 18,
  },
  footer: {
    paddingHorizontal: 26,
    paddingBottom: 24,
    paddingTop: 10,
    gap: 18,
  },
  paginationRow: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    gap: 8,
  },
  dot: {
    height: 8,
    borderRadius: 4,
  },
  primaryButton: {
    backgroundColor: BrandColors.terracotta,
    paddingVertical: 16,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: BrandColors.terracotta,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 10,
    elevation: 6,
  },
  primaryButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '800',
    letterSpacing: 0.5,
  },
});

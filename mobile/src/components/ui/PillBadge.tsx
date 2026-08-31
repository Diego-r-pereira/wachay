import React from 'react';
import { View, Text, StyleSheet, ViewStyle, TextStyle } from 'react-native';
import { BrandColors } from '@/constants/theme';

export type PillVariant = 'terracotta' | 'gold' | 'teal' | 'sage' | 'danger' | 'neutral';

interface PillBadgeProps {
  label: string;
  variant?: PillVariant;
  icon?: string;
  size?: 'small' | 'medium';
  style?: ViewStyle;
  textStyle?: TextStyle;
}

export const PillBadge: React.FC<PillBadgeProps> = ({
  label,
  variant = 'neutral',
  icon,
  size = 'small',
  style,
  textStyle,
}) => {
  const getColors = () => {
    switch (variant) {
      case 'terracotta':
        return { bg: 'rgba(196, 145, 100, 0.15)', text: BrandColors.terracotta, border: 'rgba(196, 145, 100, 0.4)' };
      case 'gold':
        return { bg: 'rgba(207, 177, 89, 0.15)', text: BrandColors.gold, border: 'rgba(207, 177, 89, 0.4)' };
      case 'teal':
        return { bg: 'rgba(86, 134, 143, 0.15)', text: BrandColors.teal, border: 'rgba(86, 134, 143, 0.4)' };
      case 'sage':
        return { bg: 'rgba(63, 100, 78, 0.2)', text: '#68B284', border: 'rgba(63, 100, 78, 0.5)' };
      case 'danger':
        return { bg: 'rgba(239, 68, 68, 0.15)', text: '#F87171', border: 'rgba(239, 68, 68, 0.4)' };
      default:
        return { bg: 'rgba(255, 255, 255, 0.06)', text: BrandColors.textSecondary, border: 'rgba(255, 255, 255, 0.1)' };
    }
  };

  const colors = getColors();

  return (
    <View
      style={[
        styles.badge,
        { backgroundColor: colors.bg, borderColor: colors.border },
        size === 'medium' ? styles.mediumBadge : styles.smallBadge,
        style,
      ]}
    >
      <Text
        style={[
          styles.text,
          { color: colors.text },
          size === 'medium' ? styles.mediumText : styles.smallText,
          textStyle,
        ]}
      >
        {icon ? `${icon} ` : ''}{label}
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  badge: {
    alignSelf: 'flex-start',
    borderRadius: 20,
    borderWidth: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
  },
  smallBadge: {
    paddingVertical: 3,
    paddingHorizontal: 8,
  },
  mediumBadge: {
    paddingVertical: 5,
    paddingHorizontal: 12,
  },
  text: {
    fontWeight: '600',
    letterSpacing: 0.3,
  },
  smallText: {
    fontSize: 11,
  },
  mediumText: {
    fontSize: 13,
  },
});

import React from 'react';
import { View, StyleSheet, ViewProps, ViewStyle } from 'react-native';
import { BrandColors } from '@/constants/theme';

interface GlassCardProps extends ViewProps {
  variant?: 'default' | 'elevated' | 'terracotta' | 'gold' | 'teal' | 'danger';
  style?: ViewStyle | ViewStyle[];
  children?: React.ReactNode;
}

export const GlassCard: React.FC<GlassCardProps> = ({
  variant = 'default',
  style,
  children,
  ...rest
}) => {
  const getVariantStyle = () => {
    switch (variant) {
      case 'elevated':
        return styles.elevated;
      case 'terracotta':
        return styles.terracotta;
      case 'gold':
        return styles.gold;
      case 'teal':
        return styles.teal;
      case 'danger':
        return styles.danger;
      default:
        return styles.default;
    }
  };

  return (
    <View style={[styles.base, getVariantStyle(), style]} {...rest}>
      {children}
    </View>
  );
};

const styles = StyleSheet.create({
  base: {
    borderRadius: 16,
    padding: 16,
    backgroundColor: BrandColors.surface,
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
  },
  default: {
    backgroundColor: BrandColors.surface,
    borderColor: BrandColors.surfaceBorder,
  },
  elevated: {
    backgroundColor: BrandColors.surfaceElevated,
    borderColor: 'rgba(255, 255, 255, 0.12)',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 4,
  },
  terracotta: {
    backgroundColor: 'rgba(196, 145, 100, 0.1)',
    borderColor: 'rgba(196, 145, 100, 0.35)',
  },
  gold: {
    backgroundColor: 'rgba(207, 177, 89, 0.1)',
    borderColor: 'rgba(207, 177, 89, 0.35)',
  },
  teal: {
    backgroundColor: 'rgba(86, 134, 143, 0.1)',
    borderColor: 'rgba(86, 134, 143, 0.35)',
  },
  danger: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderColor: 'rgba(239, 68, 68, 0.35)',
  },
});

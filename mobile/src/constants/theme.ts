/**
 * Below are the colors that are used in the app. The colors are defined in the light and dark mode.
 * There are many other ways to style your app. For example, [Nativewind](https://www.nativewind.dev/), [Tamagui](https://tamagui.dev/), [unistyles](https://reactnativeunistyles.vercel.app), etc.
 */

import '@/global.css';

import { Platform } from 'react-native';

export const BrandColors = {
  terracotta: '#C49164',     // Warm Terracotta / Emergency / Critical Fire Alerts (#C49164)
  gold: '#CFB159',           // Golden Amber / Thermal Monitoring / Moderate Risk (#CFB159)
  teal: '#56868F',           // Muted Teal / Wind Telemetry / AI Assistant (#56868F)
  forestSage: '#3F644E',     // Primary Ecological Brand Green
  forestSageAlt: '#2E523B',  // Deep Forest Green
  forestTitle: '#203126',    // Evergreen Dark
  darkObsidian: '#0E1410',   // AMOLED Dark Canvas
  surface: '#151F18',        // Surface Card BG
  surfaceElevated: '#1D2A21',// Elevated Card BG
  surfaceBorder: 'rgba(255, 255, 255, 0.08)',
  surfaceBorderLight: 'rgba(196, 145, 100, 0.25)',
  textPrimary: '#FBFBF9',    // Crisp Off-White
  textSecondary: '#8EA295',  // Sage Secondary Text
  textMuted: '#5C6E63',      // Muted Captions
  danger: '#EF4444',         // Pure Red Alert
  success: '#10B981',        // Success / Online Green
};

export const Colors = {
  light: {
    text: '#1C2C22',
    background: '#FBFBF9',
    backgroundElement: '#EFEEE9',
    backgroundSelected: '#E2E1DA',
    textSecondary: '#4A574E',
  },
  dark: {
    text: BrandColors.textPrimary,
    background: BrandColors.darkObsidian,
    backgroundElement: BrandColors.surface,
    backgroundSelected: BrandColors.surfaceElevated,
    textSecondary: BrandColors.textSecondary,
  },
} as const;

export type ThemeColor = keyof typeof Colors.light & keyof typeof Colors.dark;

export const Fonts = Platform.select({
  ios: {
    /** iOS `UIFontDescriptorSystemDesignDefault` */
    sans: 'system-ui',
    /** iOS `UIFontDescriptorSystemDesignSerif` */
    serif: 'ui-serif',
    /** iOS `UIFontDescriptorSystemDesignRounded` */
    rounded: 'ui-rounded',
    /** iOS `UIFontDescriptorSystemDesignMonospaced` */
    mono: 'ui-monospace',
  },
  default: {
    sans: 'normal',
    serif: 'serif',
    rounded: 'normal',
    mono: 'monospace',
  },
  web: {
    sans: 'var(--font-display)',
    serif: 'var(--font-serif)',
    rounded: 'var(--font-rounded)',
    mono: 'var(--font-mono)',
  },
});

export const Spacing = {
  half: 2,
  one: 4,
  two: 8,
  three: 16,
  four: 24,
  five: 32,
  six: 64,
} as const;

export const BottomTabInset = Platform.select({ ios: 50, android: 80 }) ?? 0;
export const MaxContentWidth = 800;

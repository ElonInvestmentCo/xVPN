import React from 'react';
import { View, StyleSheet, ViewStyle, Platform } from 'react-native';
import Colors from '@/constants/colors';

interface GlassCardProps {
  children: React.ReactNode;
  style?: ViewStyle;
  intensity?: 'low' | 'medium' | 'high';
  glowColor?: string;
}

export function GlassCard({ children, style, intensity = 'medium', glowColor }: GlassCardProps) {
  const bgOpacity = intensity === 'low' ? 0.03 : intensity === 'medium' ? 0.06 : 0.1;

  return (
    <View
      style={[
        styles.card,
        {
          backgroundColor: `rgba(255,255,255,${bgOpacity})`,
          ...(glowColor ? { shadowColor: glowColor, shadowOpacity: 0.25, shadowRadius: 20, shadowOffset: { width: 0, height: 0 } } : {}),
        },
        style,
      ]}
    >
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: 20,
    borderWidth: 2,
    borderColor: 'rgba(255,255,255,0.2)',
    overflow: 'hidden',
    ...(Platform.OS === 'web' ? {
      // @ts-ignore
      backdropFilter: 'blur(40px)',
      WebkitBackdropFilter: 'blur(40px)',
    } : {}),
  },
});

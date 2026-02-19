import React from 'react';
import { View, Text, StyleSheet, Platform } from 'react-native';
import Svg, { Circle } from 'react-native-svg';
import Colors from '@/constants/colors';

interface StatRingProps {
  value: number;
  maxValue: number;
  label: string;
  unit: string;
  color: string;
  size?: number;
}

export function StatRing({ value, maxValue, label, unit, color, size = 100 }: StatRingProps) {
  const strokeWidth = 4;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(value / maxValue, 1);
  const strokeDashoffset = circumference * (1 - progress);

  return (
    <View style={[styles.container, { width: size, height: size }]}>
      <Svg width={size} height={size} style={styles.svg}>
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={strokeWidth}
          fill="none"
        />
        <Circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          rotation="-90"
          origin={`${size / 2}, ${size / 2}`}
        />
      </Svg>
      <View style={styles.labelContainer}>
        <Text style={[styles.value, { color }]}>{value.toFixed(1)}</Text>
        <Text style={styles.unit}>{unit}</Text>
        <Text style={styles.label}>{label}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  svg: {
    position: 'absolute',
  },
  labelContainer: {
    alignItems: 'center',
  },
  value: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 16,
  },
  unit: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textSecondary,
    marginTop: 1,
  },
  label: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 9,
    color: Colors.dark.textMuted,
    marginTop: 2,
  },
});

import React, { useEffect } from 'react';
import { View, Text, StyleSheet, Platform } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withRepeat,
  withTiming,
  Easing,
  interpolate,
} from 'react-native-reanimated';
import { Ionicons } from '@expo/vector-icons';
import { GlassCard } from '@/components/GlassCard';
import Colors from '@/constants/colors';

interface LiveTelemetryProps {
  isConnected: boolean;
  downloadSpeed: number;
  uploadSpeed: number;
  sessionDuration: number;
  ping: number;
  dataUsed: number;
}

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

function AnimatedBar({ value, maxValue, color }: { value: number; maxValue: number; color: string }) {
  const barPulse = useSharedValue(0.6);

  useEffect(() => {
    if (value > 0) {
      barPulse.value = withRepeat(withTiming(1, { duration: 800, easing: Easing.inOut(Easing.ease) }), -1, true);
    } else {
      barPulse.value = withTiming(0.3);
    }
  }, [value > 0]);

  const barStyle = useAnimatedStyle(() => ({
    opacity: barPulse.value,
  }));

  const progress = Math.min(value / maxValue, 1);
  const barCount = 12;
  const activeBars = Math.round(progress * barCount);

  return (
    <View style={barStyles.container}>
      {Array.from({ length: barCount }).map((_, i) => (
        <Animated.View
          key={i}
          style={[
            barStyles.bar,
            {
              backgroundColor: i < activeBars ? color : 'rgba(255,255,255,0.06)',
              height: 4 + (i * 1.5),
            },
            i < activeBars ? barStyle : undefined,
          ]}
        />
      ))}
    </View>
  );
}

const barStyles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: 2,
    height: 24,
  },
  bar: {
    width: 3,
    borderRadius: 1.5,
    minHeight: 4,
  },
});

function TelemetryCard({ icon, iconColor, label, value, unit, barValue, barMax, barColor }: {
  icon: string;
  iconColor: string;
  label: string;
  value: string;
  unit: string;
  barValue: number;
  barMax: number;
  barColor: string;
}) {
  return (
    <GlassCard style={telStyles.card} intensity="low">
      <View style={telStyles.topRow}>
        <View style={telStyles.iconWrap}>
          <Ionicons name={icon as any} size={14} color={iconColor} />
        </View>
        <AnimatedBar value={barValue} maxValue={barMax} color={barColor} />
      </View>
      <View style={telStyles.valueRow}>
        <Text style={[telStyles.value, { color: iconColor }]}>{value}</Text>
        <Text style={telStyles.unit}>{unit}</Text>
      </View>
      <Text style={telStyles.label}>{label}</Text>
    </GlassCard>
  );
}

const telStyles = StyleSheet.create({
  card: {
    flex: 1,
    padding: 12,
  },
  topRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-end',
    marginBottom: 8,
  },
  iconWrap: {
    width: 26,
    height: 26,
    borderRadius: 8,
    backgroundColor: 'rgba(255,255,255,0.04)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  valueRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 3,
  },
  value: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 18,
  },
  unit: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 10,
    color: '#FFFFFF',
    letterSpacing: 0.5,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  label: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 10,
    color: Colors.dark.accent,
    marginTop: 2,
    letterSpacing: 0.5,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
});

export function LiveTelemetry({ isConnected, downloadSpeed, uploadSpeed, sessionDuration, ping, dataUsed }: LiveTelemetryProps) {
  return (
    <View style={styles.container}>
      <View style={styles.row}>
        <TelemetryCard
          icon="arrow-down"
          iconColor={Colors.dark.accent}
          label="Download"
          value={isConnected ? downloadSpeed.toFixed(1) : '0.0'}
          unit="Mbps"
          barValue={isConnected ? downloadSpeed : 0}
          barMax={150}
          barColor={Colors.dark.accent}
        />
        <TelemetryCard
          icon="arrow-up"
          iconColor={Colors.dark.accentPurple}
          label="Upload"
          value={isConnected ? uploadSpeed.toFixed(1) : '0.0'}
          unit="Mbps"
          barValue={isConnected ? uploadSpeed : 0}
          barMax={60}
          barColor={Colors.dark.accentPurple}
        />
      </View>
      <View style={styles.row}>
        <TelemetryCard
          icon="time-outline"
          iconColor={Colors.dark.accentCoral}
          label="Session"
          value={isConnected ? formatDuration(sessionDuration) : '00:00:00'}
          unit=""
          barValue={isConnected ? Math.min(sessionDuration, 3600) : 0}
          barMax={3600}
          barColor={Colors.dark.accentCoral}
        />
        <TelemetryCard
          icon="pulse-outline"
          iconColor={Colors.dark.warning}
          label="Latency"
          value={isConnected ? ping.toString() : '0'}
          unit="ms"
          barValue={isConnected ? ping : 0}
          barMax={200}
          barColor={Colors.dark.warning}
        />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    paddingHorizontal: 20,
    gap: 10,
  },
  row: {
    flexDirection: 'row',
    gap: 10,
  },
});

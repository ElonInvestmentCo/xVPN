import React, { useEffect } from 'react';
import { View, Text, StyleSheet, Platform } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withDelay,
  withRepeat,
  Easing,
} from 'react-native-reanimated';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import { GlassCard } from '@/components/GlassCard';
import Colors from '@/constants/colors';

interface LeakStatusIndicatorsProps {
  isConnected: boolean;
}

function StatusIndicator({ label, icon, iconLib, secure, delay, isConnected }: {
  label: string;
  icon: string;
  iconLib: 'ion' | 'mci';
  secure: boolean;
  delay: number;
  isConnected: boolean;
}) {
  const progress = useSharedValue(0);
  const pulseScale = useSharedValue(1);

  useEffect(() => {
    if (isConnected && secure) {
      progress.value = withDelay(delay, withTiming(1, { duration: 600 }));
      pulseScale.value = withDelay(
        delay + 600,
        withRepeat(withTiming(1.15, { duration: 2000, easing: Easing.inOut(Easing.ease) }), -1, true)
      );
    } else if (!isConnected) {
      progress.value = withTiming(0, { duration: 400 });
      pulseScale.value = withTiming(1);
    }
  }, [isConnected, secure]);

  const barStyle = useAnimatedStyle(() => ({
    width: `${progress.value * 100}%` as any,
  }));

  const dotStyle = useAnimatedStyle(() => ({
    transform: [{ scale: isConnected ? pulseScale.value : 1 }],
  }));

  const statusColor = !isConnected
    ? Colors.dark.textMuted
    : secure
    ? Colors.dark.success
    : Colors.dark.danger;

  const statusText = !isConnected ? 'Inactive' : secure ? 'Protected' : 'Exposed';

  return (
    <View style={indicatorStyles.container}>
      <View style={indicatorStyles.headerRow}>
        <View style={indicatorStyles.left}>
          <View style={[indicatorStyles.iconWrap, { backgroundColor: `${statusColor}15` }]}>
            {iconLib === 'mci' ? (
              <MaterialCommunityIcons name={icon as any} size={14} color={statusColor} />
            ) : (
              <Ionicons name={icon as any} size={14} color={statusColor} />
            )}
          </View>
          <Text style={indicatorStyles.label}>{label}</Text>
        </View>
        <View style={indicatorStyles.statusRow}>
          <Animated.View style={[indicatorStyles.dot, { backgroundColor: statusColor }, dotStyle]} />
          <Text style={[indicatorStyles.statusText, { color: statusColor }]}>{statusText}</Text>
        </View>
      </View>
      <View style={indicatorStyles.track}>
        <Animated.View style={[indicatorStyles.fill, { backgroundColor: statusColor }, barStyle]} />
      </View>
    </View>
  );
}

const indicatorStyles = StyleSheet.create({
  container: {
    gap: 6,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  left: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  iconWrap: {
    width: 26,
    height: 26,
    borderRadius: 7,
    alignItems: 'center',
    justifyContent: 'center',
  },
  label: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    color: '#FFFFFF',
    letterSpacing: 0.5,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 5,
  },
  dot: {
    width: 5,
    height: 5,
    borderRadius: 2.5,
  },
  statusText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    letterSpacing: 1,
  },
  track: {
    height: 2,
    backgroundColor: 'rgba(255,255,255,0.04)',
    borderRadius: 1,
    overflow: 'hidden',
    marginLeft: 34,
  },
  fill: {
    height: '100%',
    borderRadius: 1,
  },
});

export function LeakStatusIndicators({ isConnected }: LeakStatusIndicatorsProps) {
  return (
    <GlassCard style={styles.card} intensity="low" glowColor={isConnected ? 'rgba(0,230,118,0.15)' : undefined}>
      <View style={styles.header}>
        <Ionicons name="shield-checkmark-outline" size={16} color={isConnected ? Colors.dark.success : Colors.dark.textMuted} />
        <Text style={styles.title}>LEAK PROTECTION</Text>
      </View>
      <View style={styles.indicators}>
        <StatusIndicator
          label="DNS Leak"
          icon="server-outline"
          iconLib="ion"
          secure={isConnected}
          delay={200}
          isConnected={isConnected}
        />
        <View style={styles.divider} />
        <StatusIndicator
          label="WebRTC Leak"
          icon="videocam-outline"
          iconLib="ion"
          secure={isConnected}
          delay={500}
          isConnected={isConnected}
        />
        <View style={styles.divider} />
        <StatusIndicator
          label="IPv6 Leak"
          icon="git-network-outline"
          iconLib="ion"
          secure={true}
          delay={800}
          isConnected={isConnected}
        />
      </View>
    </GlassCard>
  );
}

const styles = StyleSheet.create({
  card: {
    marginHorizontal: 20,
    padding: 16,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 14,
  },
  title: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 10,
    color: Colors.dark.accent,
    letterSpacing: 3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  indicators: {
    gap: 10,
  },
  divider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.03)',
  },
});

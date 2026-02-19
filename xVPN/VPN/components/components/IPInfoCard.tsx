import React, { useEffect } from 'react';
import { View, Text, StyleSheet, Platform } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withRepeat,
  withTiming,
  Easing,
} from 'react-native-reanimated';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import { GlassCard } from '@/components/GlassCard';
import Colors from '@/constants/colors';

interface IPInfoCardProps {
  isConnected: boolean;
  virtualIp: string;
  serverCity: string;
  serverCountry: string;
}

function PulsingDot({ color, active }: { color: string; active: boolean }) {
  const scale = useSharedValue(1);

  useEffect(() => {
    if (active) {
      scale.value = withRepeat(withTiming(1.6, { duration: 1200, easing: Easing.inOut(Easing.ease) }), -1, true);
    } else {
      scale.value = withTiming(1);
    }
  }, [active]);

  const dotStyle = useAnimatedStyle(() => ({
    transform: [{ scale: scale.value }],
    opacity: active ? 0.6 : 0.2,
  }));

  return (
    <View style={dotStyles.container}>
      <Animated.View style={[dotStyles.outerRing, { borderColor: color }, dotStyle]} />
      <View style={[dotStyles.innerDot, { backgroundColor: color }]} />
    </View>
  );
}

const dotStyles = StyleSheet.create({
  container: {
    width: 20,
    height: 20,
    alignItems: 'center',
    justifyContent: 'center',
  },
  outerRing: {
    position: 'absolute',
    width: 16,
    height: 16,
    borderRadius: 8,
    borderWidth: 1,
  },
  innerDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
});

export function IPInfoCard({ isConnected, virtualIp, serverCity, serverCountry }: IPInfoCardProps) {
  const glowColor = isConnected ? Colors.dark.accent : undefined;

  return (
    <GlassCard style={styles.card} intensity="medium" glowColor={glowColor}>
      <View style={styles.headerRow}>
        <View style={styles.headerLeft}>
          <MaterialCommunityIcons name="ip-network-outline" size={18} color={Colors.dark.accent} />
          <Text style={styles.headerTitle}>IP Information</Text>
        </View>
        <PulsingDot color={isConnected ? Colors.dark.success : Colors.dark.textMuted} active={isConnected} />
      </View>

      <View style={styles.divider} />

      <View style={styles.infoRow}>
        <View style={styles.infoLeft}>
          <View style={[styles.infoIcon, { backgroundColor: 'rgba(0,240,255,0.08)' }]}>
            <MaterialCommunityIcons name="ip" size={14} color={Colors.dark.accent} />
          </View>
          <Text style={styles.infoLabel}>Virtual IP</Text>
        </View>
        <Text style={[styles.infoValue, { color: isConnected ? Colors.dark.accent : Colors.dark.textMuted }]}>
          {isConnected ? virtualIp : '---'}
        </Text>
      </View>

      <View style={styles.infoRow}>
        <View style={styles.infoLeft}>
          <View style={[styles.infoIcon, { backgroundColor: 'rgba(195,0,255,0.08)' }]}>
            <Ionicons name="business-outline" size={13} color={Colors.dark.accentPurple} />
          </View>
          <Text style={styles.infoLabel}>ISP</Text>
        </View>
        <Text style={[styles.infoValue, { color: isConnected ? Colors.dark.accentPurple : Colors.dark.textMuted }]}>
          {isConnected ? 'xVPN Secure Network' : '---'}
        </Text>
      </View>

      <View style={styles.infoRow}>
        <View style={styles.infoLeft}>
          <View style={[styles.infoIcon, { backgroundColor: 'rgba(0,230,118,0.08)' }]}>
            <Ionicons name="location-outline" size={13} color={Colors.dark.success} />
          </View>
          <Text style={styles.infoLabel}>Location</Text>
        </View>
        <Text style={[styles.infoValue, { color: isConnected ? Colors.dark.success : Colors.dark.textMuted }]}>
          {isConnected ? `${serverCity}, ${serverCountry}` : '---'}
        </Text>
      </View>

      {isConnected && (
        <View style={styles.secureBanner}>
          <Ionicons name="shield-checkmark" size={12} color={Colors.dark.success} />
          <Text style={styles.secureText}>Your real IP is hidden</Text>
        </View>
      )}
    </GlassCard>
  );
}

const styles = StyleSheet.create({
  card: {
    marginHorizontal: 20,
    padding: 16,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  headerTitle: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 11,
    color: Colors.dark.text,
    letterSpacing: 2,
  },
  divider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.04)',
    marginVertical: 12,
  },
  infoRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 8,
  },
  infoLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  infoIcon: {
    width: 28,
    height: 28,
    borderRadius: 8,
    alignItems: 'center',
    justifyContent: 'center',
  },
  infoLabel: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 12,
    color: '#FFFFFF',
    letterSpacing: 0.5,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  infoValue: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 12,
  },
  secureBanner: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    backgroundColor: 'rgba(0,230,118,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(0,230,118,0.12)',
    borderRadius: 10,
    padding: 10,
    marginTop: 8,
  },
  secureText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 10,
    color: Colors.dark.success,
    letterSpacing: 0.5,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
});

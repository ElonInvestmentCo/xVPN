import React from 'react';
import { View, Text, StyleSheet, ScrollView, Platform, Dimensions } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import Svg, { Circle } from 'react-native-svg';
import { NoiseBackground } from '@/components/NoiseBackground';
import { GlassCard } from '@/components/GlassCard';
import { useVpn } from '@/lib/vpn-context';
import Colors from '@/constants/colors';

const { width } = Dimensions.get('window');

function ProgressRing({ value, max, color, size = 110, strokeWidth = 5 }: { value: number; max: number; color: string; size?: number; strokeWidth?: number }) {
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(value / max, 1);
  const offset = circumference * (1 - progress);

  return (
    <Svg width={size} height={size}>
      <Circle cx={size / 2} cy={size / 2} r={radius} stroke="rgba(255,255,255,0.05)" strokeWidth={strokeWidth} fill="none" />
      <Circle cx={size / 2} cy={size / 2} r={radius} stroke={color} strokeWidth={strokeWidth} fill="none" strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" rotation="-90" origin={`${size / 2}, ${size / 2}`} />
    </Svg>
  );
}

function formatDataSize(mb: number): string {
  if (mb < 1) return `${(mb * 1024).toFixed(0)} KB`;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function StatsScreen() {
  const insets = useSafeAreaInsets();
  const { isConnected, stats, selectedServer, protocol } = useVpn();
  const topPadding = Platform.OS === 'web' ? 67 : insets.top;
  const ringSize = Math.min((width - 80) / 3, 110);

  return (
    <NoiseBackground>
      <ScrollView
        style={[styles.container, { paddingTop: topPadding }]}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.header}>
          <Text style={styles.title}>Statistics</Text>
          <Text style={styles.subtitle}>Real-time connection metrics</Text>
        </View>

        <GlassCard style={styles.mainStatsCard} intensity="medium" glowColor={isConnected ? Colors.dark.accent : undefined}>
          <View style={styles.connectionStatusRow}>
            <View style={[styles.liveIndicator, { backgroundColor: isConnected ? Colors.dark.success : Colors.dark.textMuted }]} />
            <Text style={[styles.connectionStatus, { color: isConnected ? Colors.dark.success : Colors.dark.textMuted }]}>
              {isConnected ? 'LIVE SESSION' : 'NO ACTIVE SESSION'}
            </Text>
          </View>

          <View style={styles.ringsRow}>
            <View style={styles.ringItem}>
              <View style={styles.ringWrapper}>
                <ProgressRing value={isConnected ? stats.downloadSpeed : 0} max={150} color={Colors.dark.accent} size={ringSize} />
                <View style={[styles.ringCenter, { width: ringSize, height: ringSize }]}>
                  <Text style={[styles.ringValue, { color: Colors.dark.accent }]}>{isConnected ? stats.downloadSpeed.toFixed(0) : '0'}</Text>
                  <Text style={styles.ringUnit}>Mbps</Text>
                </View>
              </View>
              <Text style={styles.ringLabel}>Download</Text>
            </View>

            <View style={styles.ringItem}>
              <View style={styles.ringWrapper}>
                <ProgressRing value={isConnected ? stats.uploadSpeed : 0} max={80} color={Colors.dark.accentPurple} size={ringSize} />
                <View style={[styles.ringCenter, { width: ringSize, height: ringSize }]}>
                  <Text style={[styles.ringValue, { color: Colors.dark.accentPurple }]}>{isConnected ? stats.uploadSpeed.toFixed(0) : '0'}</Text>
                  <Text style={styles.ringUnit}>Mbps</Text>
                </View>
              </View>
              <Text style={styles.ringLabel}>Upload</Text>
            </View>

            <View style={styles.ringItem}>
              <View style={styles.ringWrapper}>
                <ProgressRing value={isConnected ? stats.ping : 0} max={200} color={Colors.dark.accentCoral} size={ringSize} />
                <View style={[styles.ringCenter, { width: ringSize, height: ringSize }]}>
                  <Text style={[styles.ringValue, { color: Colors.dark.accentCoral }]}>{isConnected ? stats.ping : '0'}</Text>
                  <Text style={styles.ringUnit}>ms</Text>
                </View>
              </View>
              <Text style={styles.ringLabel}>Latency</Text>
            </View>
          </View>
        </GlassCard>

        <View style={styles.detailsGrid}>
          <GlassCard style={styles.detailCard} intensity="low">
            <Ionicons name="cloud-download-outline" size={20} color={Colors.dark.accent} />
            <Text style={styles.detailLabel}>Data Used</Text>
            <Text style={[styles.detailValue, { color: Colors.dark.accent }]}>{formatDataSize(stats.dataUsed)}</Text>
          </GlassCard>

          <GlassCard style={styles.detailCard} intensity="low">
            <Ionicons name="time-outline" size={20} color={Colors.dark.accentPurple} />
            <Text style={styles.detailLabel}>Duration</Text>
            <Text style={[styles.detailValue, { color: Colors.dark.accentPurple }]}>{formatDuration(stats.sessionDuration)}</Text>
          </GlassCard>
        </View>

        <View style={styles.detailsGrid}>
          <GlassCard style={styles.detailCard} intensity="low">
            <MaterialCommunityIcons name="shield-lock-outline" size={20} color={Colors.dark.success} />
            <Text style={styles.detailLabel}>Protocol</Text>
            <Text style={[styles.detailValue, { color: Colors.dark.success }]}>{protocol}</Text>
          </GlassCard>

          <GlassCard style={styles.detailCard} intensity="low">
            <Ionicons name="location-outline" size={20} color={Colors.dark.warning} />
            <Text style={styles.detailLabel}>Server</Text>
            <Text style={[styles.detailValue, { color: Colors.dark.warning }]} numberOfLines={1}>{selectedServer?.name || 'None'}</Text>
          </GlassCard>
        </View>

        <GlassCard style={styles.encryptionCard} intensity="low">
          <View style={styles.encryptionRow}>
            <View style={styles.encryptionLeft}>
              <MaterialCommunityIcons name="lock-outline" size={20} color={Colors.dark.accent} />
              <View>
                <Text style={styles.encryptionTitle}>Encryption</Text>
                <Text style={styles.encryptionValue}>AES-256-GCM</Text>
              </View>
            </View>
            <View style={styles.encryptionBadge}>
              <Text style={styles.encryptionBadgeText}>Military Grade</Text>
            </View>
          </View>
        </GlassCard>
      </ScrollView>
    </NoiseBackground>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scrollContent: {
    paddingBottom: 120,
  },
  header: {
    paddingHorizontal: 24,
    paddingTop: 12,
    paddingBottom: 16,
  },
  title: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 22,
    color: Colors.dark.text,
    letterSpacing: 2,
  },
  subtitle: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 13,
    color: Colors.dark.textMuted,
    marginTop: 4,
  },
  mainStatsCard: {
    marginHorizontal: 20,
    padding: 20,
    marginBottom: 16,
  },
  connectionStatusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 20,
  },
  liveIndicator: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  connectionStatus: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 10,
    letterSpacing: 2,
  },
  ringsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    alignItems: 'center',
  },
  ringItem: {
    alignItems: 'center',
    gap: 8,
  },
  ringWrapper: {
    position: 'relative',
  },
  ringCenter: {
    position: 'absolute',
    alignItems: 'center',
    justifyContent: 'center',
  },
  ringValue: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 18,
  },
  ringUnit: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 9,
    color: Colors.dark.textSecondary,
    marginTop: 1,
  },
  ringLabel: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.textMuted,
  },
  detailsGrid: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    gap: 10,
    marginBottom: 10,
  },
  detailCard: {
    flex: 1,
    padding: 16,
    gap: 8,
    alignItems: 'center',
  },
  detailLabel: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.textMuted,
  },
  detailValue: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 13,
  },
  encryptionCard: {
    marginHorizontal: 20,
    padding: 16,
    marginTop: 6,
  },
  encryptionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  encryptionLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  encryptionTitle: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.textMuted,
  },
  encryptionValue: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 14,
    color: Colors.dark.text,
  },
  encryptionBadge: {
    backgroundColor: 'rgba(0, 240, 255, 0.1)',
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.2)',
  },
  encryptionBadgeText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    color: Colors.dark.accent,
    letterSpacing: 1,
  },
});

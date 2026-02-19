import React, { useState, useCallback, useEffect } from 'react';
import { View, Text, StyleSheet, Platform, ScrollView, Pressable } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { NoiseBackground } from '@/components/NoiseBackground';
import { GlassCard } from '@/components/GlassCard';
import { PowerButton } from '@/components/PowerButton';
import { WorldMap } from '@/components/WorldMap';
import { LiveTelemetry } from '@/components/LiveTelemetry';
import { IPInfoCard } from '@/components/IPInfoCard';
import { RadarOverlay } from '@/components/RadarOverlay';
import { LeakStatusIndicators } from '@/components/LeakStatusIndicators';
import { useVpn } from '@/lib/vpn-context';
import { useAuth } from '@/lib/auth-context';
import { useFingerprintShield } from '@/lib/fingerprint-context';
import Colors from '@/constants/colors';

export default function DashboardScreen() {
  const insets = useSafeAreaInsets();
  const { isConnected, isConnecting, isProtecting, connectionError, connect, cancelConnection, completeConnection, disconnect, clearError, selectedServer, stats, virtualIp, setAuthToken, vpnConfigError } = useVpn();
  const { token, isAuthenticated, user } = useAuth();
  const { updateForServer } = useFingerprintShield();
  const topPadding = Platform.OS === 'web' ? 67 : insets.top;
  const [showRadar, setShowRadar] = useState(false);

  // Set auth token when available
  useEffect(() => {
    if (token) {
      setAuthToken(token);
    }
  }, [token, setAuthToken]);

  useEffect(() => {
    updateForServer(selectedServer?.flag || null, selectedServer?.city || undefined);
  }, [selectedServer?.flag, selectedServer?.city]);

  useEffect(() => {
    if (isProtecting || isConnected || connectionError) {
      setShowRadar(false);
    }
  }, [isProtecting, isConnected, connectionError]);

  // Navigate to subscription if VPN config error
  useEffect(() => {
    if (vpnConfigError && isConnecting) {
      cancelConnection();
      // In a real app, navigate to subscription screen
      console.warn('VPN Access Error:', vpnConfigError);
    }
  }, [vpnConfigError, isConnecting, cancelConnection]);

  const handlePowerPress = useCallback(() => {
    if (isConnected || isProtecting) {
      disconnect();
    } else if (isConnecting) {
      if (Platform.OS !== 'web') {
        Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
      }
      setShowRadar(false);
      cancelConnection();
    } else {
      if (Platform.OS !== 'web') {
        Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
      }
      clearError();
      setShowRadar(true);
      connect();
    }
  }, [isConnected, isConnecting, isProtecting, connect, disconnect, cancelConnection, clearError]);

  const handleRadarComplete = useCallback(() => {
    setShowRadar(false);
    if (isConnecting) {
      completeConnection();
    }
  }, [isConnecting, completeConnection]);

  const statusText = connectionError
    ? connectionError.message
    : isConnecting
    ? 'Establishing Secure Tunnel...'
    : isProtecting
    ? 'Verifying Residential ISP Trust...'
    : isConnected
    ? 'Secured & Protected'
    : 'Tap to Connect';
  const statusColor = connectionError
    ? '#FF3131'
    : isConnecting
    ? Colors.dark.accentPurple
    : isProtecting
    ? '#FFB300'
    : isConnected
    ? '#00E676'
    : Colors.dark.textMuted;

  return (
    <NoiseBackground>
      <ScrollView
        style={[styles.container, { paddingTop: topPadding }]}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
        bounces={false}
      >
        <View style={styles.header}>
          <Text style={styles.logo}>xVPN</Text>
          <View style={[styles.statusPill, { borderColor: statusColor }]}>
            <View style={[styles.statusDot, { backgroundColor: statusColor }]} />
            <Text style={[styles.statusPillText, { color: statusColor }]}>
              {isConnected ? 'ACTIVE' : isConnecting ? 'CONNECTING' : isProtecting ? 'PROTECTING' : connectionError ? 'FAILED' : 'IDLE'}
            </Text>
          </View>
        </View>

        <View style={styles.orbSection}>
          <PowerButton
            isConnected={isConnected}
            isConnecting={isConnecting}
            isProtecting={isProtecting}
            onPress={handlePowerPress}
          />
          <Text style={[styles.statusText, { color: statusColor }]}>{statusText}</Text>

          {vpnConfigError && (
            <GlassCard style={[styles.serverInfo, styles.errorCard]} intensity="low">
              <View style={styles.errorContent}>
                <Ionicons name="alert-circle" size={16} color="#FF3131" />
                <View style={styles.errorTextContainer}>
                  <Text style={styles.errorTitle}>Subscription Required</Text>
                  <Text style={styles.errorMessage}>{vpnConfigError}</Text>
                </View>
              </View>
            </GlassCard>
          )}

          {selectedServer && (
            <GlassCard style={styles.serverInfo} intensity="low" glowColor={isConnected ? '#00E676' : undefined}>
              <View style={styles.serverInfoRow}>
                <View style={styles.serverDot}>
                  <Ionicons
                    name="location"
                    size={14}
                    color={isConnected ? '#00E676' : Colors.dark.accent}
                  />
                </View>
                <View>
                  <Text style={styles.serverName}>USA - Texas</Text>
                  <Text style={styles.serverCity}>{selectedServer.city}, {selectedServer.country}</Text>
                </View>
                {isConnected && (
                  <View style={styles.encryptedBadge}>
                    <Ionicons name="lock-closed" size={10} color={Colors.dark.accent} />
                    <Text style={styles.encryptedText}>AES-256</Text>
                  </View>
                )}
              </View>
            </GlassCard>
          )}
        </View>

        <View style={styles.mapSection}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>GLOBAL NETWORK</Text>
            <View style={styles.nodeCount}>
              <View style={styles.nodeCountDot} />
              <Text style={styles.nodeCountText}>50 nodes</Text>
            </View>
          </View>
          <WorldMap selectedServer={selectedServer} isConnected={isConnected} />
        </View>

        {isConnected && (
          <View style={styles.ipSection}>
            <IPInfoCard
              isConnected={isConnected}
              virtualIp={virtualIp}
              serverCity={selectedServer?.city || ''}
              serverCountry={selectedServer?.country || ''}
            />
          </View>
        )}

        <View style={styles.leakSection}>
          <LeakStatusIndicators isConnected={isConnected} />
        </View>

        <View style={styles.telemetrySection}>
          <Text style={styles.sectionTitle}>LIVE TELEMETRY</Text>
          <LiveTelemetry
            isConnected={isConnected}
            downloadSpeed={stats.downloadSpeed}
            uploadSpeed={stats.uploadSpeed}
            sessionDuration={stats.sessionDuration}
            ping={stats.ping}
            dataUsed={stats.dataUsed}
          />
        </View>

        {isConnected && (
          <View style={styles.emergencySection}>
            <Pressable
              style={styles.emergencyButton}
              onPress={() => {
                if (Platform.OS !== 'web') {
                  Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
                }
                disconnect();
              }}
            >
              <Ionicons name="power" size={18} color="#FFFFFF" />
              <Text style={styles.emergencyText}>EMERGENCY DISCONNECT</Text>
            </Pressable>
          </View>
        )}

        <View style={styles.bottomSpacer} />
      </ScrollView>

      <RadarOverlay visible={showRadar} onComplete={handleRadarComplete} />
    </NoiseBackground>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scrollContent: {
    paddingBottom: 40,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 24,
    paddingTop: 12,
    paddingBottom: 4,
  },
  logo: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 22,
    color: Colors.dark.accent,
    letterSpacing: 3,
  },
  statusPill: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 20,
    borderWidth: 1,
    gap: 6,
  },
  statusDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  statusPillText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 9,
    letterSpacing: 2,
  },
  orbSection: {
    alignItems: 'center',
    paddingTop: 8,
    gap: 12,
  },
  statusText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 14,
    letterSpacing: 1,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  serverInfo: {
    paddingHorizontal: 16,
    paddingVertical: 10,
  },
  serverInfoRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  serverDot: {
    width: 30,
    height: 30,
    borderRadius: 10,
    backgroundColor: 'rgba(255,255,255,0.04)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  serverName: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 13,
    color: Colors.dark.text,
  },
  serverCity: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    color: Colors.dark.accent,
    letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  encryptedBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    marginLeft: 8,
    backgroundColor: 'rgba(0, 240, 255, 0.08)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.15)',
  },
  encryptedText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    color: Colors.dark.accent,
    letterSpacing: 1,
  },
  mapSection: {
    marginTop: 20,
    gap: 10,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 24,
  },
  sectionTitle: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 10,
    color: Colors.dark.accent,
    letterSpacing: 3,
    paddingHorizontal: 24,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  nodeCount: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 5,
  },
  nodeCountDot: {
    width: 5,
    height: 5,
    borderRadius: 2.5,
    backgroundColor: Colors.dark.accent,
  },
  nodeCountText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    color: '#FFFFFF',
    letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  ipSection: {
    marginTop: 20,
  },
  leakSection: {
    marginTop: 20,
  },
  telemetrySection: {
    marginTop: 24,
    gap: 12,
  },
  emergencySection: {
    marginTop: 24,
    paddingHorizontal: 20,
  },
  emergencyButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
    backgroundColor: '#FF3131',
    borderRadius: 16,
    paddingVertical: 16,
    borderWidth: 2,
    borderColor: 'rgba(255,49,49,0.6)',
    shadowColor: '#FF3131',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.5,
    shadowRadius: 16,
    elevation: 8,
  },
  emergencyText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 13,
    color: '#FFFFFF',
    letterSpacing: 3,
    textShadowColor: 'rgba(0,0,0,0.5)',
    textShadowOffset: { width: 0, height: 1 },
    textShadowRadius: 2,
  },
  bottomSpacer: {
    height: Platform.OS === 'web' ? 34 : 80,
  },
  errorCard: {
    borderColor: '#FF3131',
    borderWidth: 1,
    backgroundColor: 'rgba(255, 49, 49, 0.08)',
  },
  errorContent: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12,
  },
  errorTextContainer: {
    flex: 1,
    gap: 4,
  },
  errorTitle: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 12,
    color: '#FF3131',
  },
  errorMessage: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: '#FF6B6B',
    lineHeight: 16,
  },
});

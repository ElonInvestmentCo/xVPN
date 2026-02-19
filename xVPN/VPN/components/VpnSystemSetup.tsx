import React, { useState, useEffect, useCallback } from 'react';
import { View, Text, StyleSheet, Pressable, Platform, Alert, ScrollView } from 'react-native';
import * as Haptics from 'expo-haptics';
import { MaterialCommunityIcons } from '@expo/vector-icons';
import { useVpn } from '@/lib/vpn-context';
import {
  checkVpnSystemSupport,
  connectToSystemVpn,
  disconnectFromSystemVpn,
  getSystemVpnStatus,
  requestVpnPermission,
  type VpnConfig,
  type SystemVpnStatus,
} from '@/lib/vpn-system-integration';
import Colors from '@/constants/colors';

/**
 * VPN System Setup Component
 * 
 * Handles configuration and connection to system-level VPN settings
 * on iOS and Android devices.
 */
export function VpnSystemSetup() {
  const { selectedServer, protocol, connectionState } = useVpn();
  const [vpnSupported, setVpnSupported] = useState(false);
  const [vpnStatus, setVpnStatus] = useState<SystemVpnStatus>({
    isAvailable: false,
    isConnected: false,
  });
  const [loading, setLoading] = useState(false);
  const [setupCompleted, setSetupCompleted] = useState(false);

  // Check VPN system support on mount
  useEffect(() => {
    const checkSupport = async () => {
      const supported = await checkVpnSystemSupport();
      setVpnSupported(supported);

      if (supported) {
        const status = await getSystemVpnStatus();
        setVpnStatus(status);
      }
    };

    checkSupport();
  }, []);

  // Update VPN status periodically
  useEffect(() => {
    if (!vpnSupported) return;

    const interval = setInterval(async () => {
      const status = await getSystemVpnStatus();
      setVpnStatus(status);
    }, 5000);

    return () => clearInterval(interval);
  }, [vpnSupported]);

  const handleSetupVpn = useCallback(async () => {
    if (!selectedServer) {
      Alert.alert('No Server Selected', 'Please select a VPN server first');
      return;
    }

    if (Platform.OS !== 'web') {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    }
    setLoading(true);

    try {
      // Request permission if needed
      const hasPermission = await requestVpnPermission();
      if (!hasPermission && !vpnSupported) {
        setLoading(false);
        return;
      }

      // Create VPN configuration
      const vpnConfig: VpnConfig = {
        id: selectedServer.id,
        name: `xVPN - ${selectedServer.name}`,
        protocol: (protocol as any) || 'ikev2',
        server: `vpn-${selectedServer.country.toLowerCase()}.example.com`,
        port: 500,
        username: 'vpnuser',
        password: 'encrypted-password',
        description: `xVPN connection to ${selectedServer.city}, ${selectedServer.country}`,
        onDemandEnabled: true,
        onDemandRules: [
          {
            action: 'connect',
            domainMatch: ['*'],
          },
        ],
      };

      // Connect to system VPN
      const connected = await connectToSystemVpn(vpnConfig);

      if (connected) {
        if (Platform.OS !== 'web') {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        }
        setSetupCompleted(true);
        Alert.alert(
          'VPN Configured',
          'Your VPN profile has been added to Settings. You can now manage it from Settings > VPN.'
        );
      } else {
        Alert.alert(
          'Setup Incomplete',
          'The app will manage your VPN connection. System integration will be available soon.'
        );
      }
    } catch (error) {
      Alert.alert('Setup Error', String(error));
    } finally {
      setLoading(false);
    }
  }, [selectedServer, protocol, vpnSupported]);

  const handleDisconnect = useCallback(async () => {
    if (Platform.OS !== 'web') {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    }
    setLoading(true);

    try {
      const disconnected = await disconnectFromSystemVpn();

      if (disconnected) {
        if (Platform.OS !== 'web') {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        }
        setVpnStatus({ isAvailable: vpnSupported, isConnected: false });
        Alert.alert('Disconnected', 'VPN connection has been closed');
      }
    } catch (error) {
      Alert.alert('Error', String(error));
    } finally {
      setLoading(false);
    }
  }, [vpnSupported]);

  if (Platform.OS === 'web') {
    return null; // VPN system integration not available on web
  }

  return (
    <ScrollView style={styles.container} showsVerticalScrollIndicator={false}>
      <View style={styles.section}>
        <View style={styles.header}>
          <MaterialCommunityIcons name="vpn" size={24} color={Colors.dark.accent} />
          <Text style={styles.title}>System VPN Integration</Text>
        </View>

        {vpnSupported ? (
          <>
            <View style={styles.statusCard}>
              <View style={styles.statusRow}>
                <Text style={styles.statusLabel}>VPN Support</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: 'rgba(0, 230, 118, 0.15)' },
                  ]}
                >
                  <MaterialCommunityIcons
                    name="check-circle"
                    size={14}
                    color={Colors.dark.success}
                  />
                  <Text style={[styles.statusText, { color: Colors.dark.success }]}>
                    Supported
                  </Text>
                </View>
              </View>

              <View style={styles.statusRow}>
                <Text style={styles.statusLabel}>System Status</Text>
                <View
                  style={[
                    styles.statusBadge,
                    {
                      backgroundColor: vpnStatus.isConnected
                        ? 'rgba(0, 230, 118, 0.15)'
                        : 'rgba(255, 255, 255, 0.08)',
                    },
                  ]}
                >
                  <MaterialCommunityIcons
                    name={vpnStatus.isConnected ? 'shield-check' : 'shield-off'}
                    size={14}
                    color={
                      vpnStatus.isConnected ? Colors.dark.success : Colors.dark.textMuted
                    }
                  />
                  <Text
                    style={[
                      styles.statusText,
                      {
                        color: vpnStatus.isConnected
                          ? Colors.dark.success
                          : Colors.dark.textMuted,
                      },
                    ]}
                  >
                    {vpnStatus.isConnected ? 'Connected' : 'Disconnected'}
                  </Text>
                </View>
              </View>

              {vpnStatus.currentVpnName && (
                <View style={styles.statusRow}>
                  <Text style={styles.statusLabel}>Current VPN</Text>
                  <Text style={styles.statusValue}>{vpnStatus.currentVpnName}</Text>
                </View>
              )}
            </View>

            <View style={styles.infoCard}>
              <MaterialCommunityIcons
                name="information"
                size={16}
                color={Colors.dark.accent}
              />
              <Text style={styles.infoText}>
                Your xVPN profile appears in Settings {">"} VPN on your device. You can activate
                it anytime from there.
              </Text>
            </View>

            <Pressable
              style={[styles.button, loading && styles.buttonLoading]}
              onPress={handleSetupVpn}
              disabled={loading}
            >
              <MaterialCommunityIcons name="plus-circle" size={18} color="#000" />
              <Text style={styles.buttonText}>
                {setupCompleted ? 'Update VPN Profile' : 'Setup VPN Profile'}
              </Text>
            </Pressable>

            {vpnStatus.isConnected && (
              <Pressable
                style={[styles.button, styles.disconnectButton, loading && styles.buttonLoading]}
                onPress={handleDisconnect}
                disabled={loading}
              >
                <MaterialCommunityIcons name="link-off" size={18} color={Colors.dark.accent} />
                <Text style={[styles.buttonText, { color: Colors.dark.accent }]}>
                  Disconnect System VPN
                </Text>
              </Pressable>
            )}
          </>
        ) : (
          <>
            <View style={styles.warningCard}>
              <MaterialCommunityIcons
                name="alert-circle"
                size={24}
                color={Colors.dark.textMuted}
              />
              <Text style={styles.warningTitle}>System VPN Not Available</Text>
              <Text style={styles.warningText}>
                {Platform.OS === 'ios'
                  ? 'VPN configuration is not available on this iOS device.'
                  : 'VPN services are not properly configured on this Android device.'}
              </Text>
              <Text style={styles.warningSubtext}>
                The app will manage your VPN connection instead. You can still enjoy all xVPN
                features.
              </Text>
            </View>

            <View style={styles.infoCard}>
              <MaterialCommunityIcons
                name="check-circle"
                size={16}
                color={Colors.dark.success}
              />
              <Text style={styles.infoText}>
                xVPN is fully functional and will route your traffic securely.
              </Text>
            </View>
          </>
        )}
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>What&apos;s This?</Text>
        <Text style={styles.descriptionText}>
          System VPN Integration allows xVPN to work deeply with your device&apos;s native VPN
          settings. This enables:
        </Text>

        <View style={styles.featureList}>
          {[
            'Always-on VPN mode',
            'Per-app VPN rules',
            'Split tunneling capabilities',
            'System-level VPN status',
            'On-demand VPN activation',
          ].map((feature, i) => (
            <View key={i} style={styles.featureItem}>
              <MaterialCommunityIcons
                name="check"
                size={16}
                color={Colors.dark.accent}
                style={styles.featureIcon}
              />
              <Text style={styles.featureText}>{feature}</Text>
            </View>
          ))}
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
  section: {
    marginBottom: 24,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 16,
  },
  title: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 18,
    color: Colors.dark.text,
    letterSpacing: 1,
  },
  sectionTitle: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 14,
    color: Colors.dark.text,
    letterSpacing: 1,
    marginBottom: 12,
  },
  statusCard: {
    backgroundColor: 'rgba(0, 240, 255, 0.05)',
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.15)',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    gap: 12,
  },
  statusRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  statusLabel: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 12,
    color: Colors.dark.textMuted,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  statusBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
  },
  statusText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    letterSpacing: 0.5,
  },
  statusValue: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 12,
    color: Colors.dark.text,
  },
  infoCard: {
    flexDirection: 'row',
    backgroundColor: 'rgba(0, 240, 255, 0.08)',
    borderLeftWidth: 3,
    borderLeftColor: Colors.dark.accent,
    borderRadius: 8,
    padding: 12,
    marginBottom: 16,
    gap: 10,
  },
  infoText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
    flex: 1,
    lineHeight: 16,
  },
  button: {
    backgroundColor: Colors.dark.accent,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    paddingVertical: 14,
    borderRadius: 12,
    marginBottom: 12,
  },
  disconnectButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: Colors.dark.accent,
  },
  buttonLoading: {
    opacity: 0.6,
  },
  buttonText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 13,
    color: '#000',
    letterSpacing: 1,
  },
  warningCard: {
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.1)',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    marginBottom: 16,
    gap: 8,
  },
  warningTitle: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 14,
    color: Colors.dark.text,
    letterSpacing: 1,
  },
  warningText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 13,
    color: Colors.dark.textMuted,
    textAlign: 'center',
    lineHeight: 18,
  },
  warningSubtext: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.textMuted,
    textAlign: 'center',
    opacity: 0.8,
  },
  descriptionText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
    lineHeight: 16,
    marginBottom: 12,
  },
  featureList: {
    gap: 8,
  },
  featureItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  featureIcon: {
    marginTop: 2,
  },
  featureText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
});

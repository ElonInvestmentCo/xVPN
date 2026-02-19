import React, { useState, useCallback } from 'react';
import { View, Text, StyleSheet, ScrollView, Switch, Pressable, Platform } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import * as LocalAuthentication from 'expo-local-authentication';
import { NoiseBackground } from '@/components/NoiseBackground';
import { GlassCard } from '@/components/GlassCard';
import { IPInfoCard } from '@/components/IPInfoCard';
import { SecuritySuitePanel } from '@/components/SecuritySuitePanel';
import { FingerprintShieldPanel } from '@/components/FingerprintShieldPanel';
import { SubscriptionModal } from '@/components/SubscriptionModal';
import { useVpn } from '@/lib/vpn-context';
import { useFingerprintShield } from '@/lib/fingerprint-context';
import { useAuth } from '@/lib/auth-context';
import Colors from '@/constants/colors';

// ============================================================
// ISOLATED MEMOIZED COMPONENTS - Prevent cross-toggle re-renders
// ============================================================

// Core SettingRow component with fixed width for switch container
const SettingRow = React.memo(({ icon, iconColor, iconLib, title, subtitle, children }: {
  icon: string;
  iconColor: string;
  iconLib?: 'ion' | 'mci';
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) => (
  <View style={styles.settingRow}>
    <View style={[styles.settingIcon, { backgroundColor: `${iconColor}15`, flexShrink: 0 }]}>
      {iconLib === 'mci' ? (
        <MaterialCommunityIcons name={icon as any} size={18} color={iconColor} />
      ) : (
        <Ionicons name={icon as any} size={18} color={iconColor} />
      )}
    </View>
    <View style={styles.settingTextGroup}>
      <Text style={styles.settingTitle} numberOfLines={1}>{title}</Text>
      {subtitle && <Text style={styles.settingSubtitle} numberOfLines={1}>{subtitle}</Text>}
    </View>
    <View style={[styles.switchContainer, { width: 54, justifyContent: 'flex-end' }]}>
      {children}
    </View>
  </View>
), (prevProps, nextProps) => {
  // Only re-render if children change (the switch value)
  return prevProps.children === nextProps.children;
});
SettingRow.displayName = 'SettingRow';

// Auto-Connect Toggle - Isolated Component
const AutoConnectToggle = React.memo(({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) => (
  <SettingRow icon="wifi-outline" iconColor={Colors.dark.accentPurple} title="Auto-Connect" subtitle="Connect on app launch">
    <Switch
      value={value}
      onValueChange={onChange}
      trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(195, 0, 255, 0.3)' }}
      thumbColor={value ? Colors.dark.accentPurple : '#666'}
    />
  </SettingRow>
));
AutoConnectToggle.displayName = 'AutoConnectToggle';

// Biometric Lock Toggle - Isolated Component
const BiometricLockToggle = React.memo(({ value, loading, onChange }: { value: boolean; loading: boolean; onChange: (v: boolean) => void }) => (
  <SettingRow icon="finger-print-outline" iconColor={Colors.dark.success} title="Biometric Lock" subtitle="Require Face ID / fingerprint">
    <Switch
      value={value}
      onValueChange={onChange}
      disabled={loading}
      trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(0, 230, 118, 0.3)' }}
      thumbColor={value ? Colors.dark.success : '#666'}
    />
  </SettingRow>
));
BiometricLockToggle.displayName = 'BiometricLockToggle';

// DNS Leak Protection Toggle - Isolated Component
const DnsLeakToggle = React.memo(({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) => (
  <SettingRow icon="eye-off-outline" iconColor={Colors.dark.accentCoral} title="DNS Leak Protection" subtitle="Prevent DNS queries outside tunnel">
    <Switch
      value={value}
      onValueChange={onChange}
      trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(0, 240, 255, 0.3)' }}
      thumbColor={value ? Colors.dark.accent : '#666'}
    />
  </SettingRow>
));
DnsLeakToggle.displayName = 'DnsLeakToggle';

// Ad Blocker Toggle - Isolated Component
const AdBlockerToggle = React.memo(({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) => (
  <SettingRow icon="analytics-outline" iconColor={Colors.dark.warning} title="Ad & Tracker Blocker" subtitle="Block ads, malware and trackers">
    <Switch
      value={value}
      onValueChange={onChange}
      trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(0, 240, 255, 0.3)' }}
      thumbColor={value ? Colors.dark.accent : '#666'}
    />
  </SettingRow>
));
AdBlockerToggle.displayName = 'AdBlockerToggle';

export default function SettingsScreen() {
  const insets = useSafeAreaInsets();
  const {
    protocol,
    killSwitch,
    autoConnect, setAutoConnect,
    doubleVpn,
    isConnected,
    selectedServer,
    virtualIp,
    biometricLock, setBiometricLock,
    dnsLeakProtection, setDnsLeakProtection,
    adBlocker, setAdBlocker,
    isPremium, subscriptionType, subscriptionExpiresAt,
  } = useVpn();
  const { summary } = useFingerprintShield();
  const { logout, user } = useAuth();
  const [securityPanelVisible, setSecurityPanelVisible] = useState(false);
  const [fingerprintPanelVisible, setFingerprintPanelVisible] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [subscriptionModalVisible, setSubscriptionModalVisible] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const topPadding = Platform.OS === 'web' ? 67 : insets.top;

  const showToast = useCallback((message: string) => {
    setToast(message);
    setTimeout(() => setToast(null), 2500);
  }, []);

  const handleAutoConnectToggle = useCallback((value: boolean) => {
    if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    setAutoConnect(value);
    showToast(value ? 'Auto-Connect enabled' : 'Auto-Connect disabled');
  }, [setAutoConnect, showToast]);

  const handleBiometricToggle = useCallback(async (value: boolean) => {
    if (!value) {
      if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      setBiometricLock(false);
      showToast('Biometric lock disabled');
      return;
    }

    setBiometricLoading(true);

    try {
      const compatible = await LocalAuthentication.hasHardwareAsync();
      if (!compatible) {
        showToast('Biometric hardware not available');
        setBiometricLoading(false);
        return;
      }

      const enrolled = await LocalAuthentication.isEnrolledAsync();
      if (!enrolled) {
        showToast('No biometrics enrolled on this device');
        setBiometricLoading(false);
        return;
      }

      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Authenticate to enable biometric lock',
        cancelLabel: 'Cancel',
        disableDeviceFallback: false,
      });

      if (result.success) {
        if (Platform.OS !== 'web') Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        setBiometricLock(true);
        showToast('Biometric lock enabled');
      } else {
        showToast('Authentication failed');
      }
    } catch {
      showToast('Biometric authentication error');
    } finally {
      setBiometricLoading(false);
    }
  }, [setBiometricLock, showToast]);

  const handleDnsToggle = useCallback((value: boolean) => {
    if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    setDnsLeakProtection(value);
    showToast(value ? 'DNS Leak Protection enabled' : 'DNS Leak Protection disabled');
  }, [setDnsLeakProtection, showToast]);

  const handleAdBlockerToggle = useCallback((value: boolean) => {
    if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    setAdBlocker(value);
    showToast(value ? 'Ad & Tracker Blocker enabled' : 'Ad & Tracker Blocker disabled');
  }, [setAdBlocker, showToast]);

  return (
    <NoiseBackground>
      <ScrollView
        style={[styles.container, { paddingTop: topPadding }]}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.header}>
          <Text style={styles.title}>Settings</Text>
          <Text style={styles.subtitle}>Configure your VPN</Text>
        </View>

        <IPInfoCard
          isConnected={isConnected}
          virtualIp={virtualIp}
          serverCity={selectedServer?.city || ''}
          serverCountry={selectedServer?.country || ''}
        />

        <Text style={styles.sectionLabel}>SECURITY VAULT</Text>
        <Pressable
          onPress={() => {
            if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
            setSecurityPanelVisible(true);
          }}
        >
          <GlassCard style={styles.securitySuiteCard} intensity="medium" glowColor={Colors.dark.accent}>
            <View style={styles.suiteRow}>
              <View style={styles.suiteLeft}>
                <View style={styles.suiteIconWrap}>
                  <MaterialCommunityIcons name="shield-lock" size={22} color={Colors.dark.accent} />
                </View>
                <View style={styles.suiteTextGroup}>
                  <Text style={styles.suiteTitle}>Security Suite</Text>
                  <Text style={styles.suiteDesc}>Kill Switch, Double VPN, Protocol</Text>
                </View>
              </View>
              <View style={styles.suiteRight}>
                <View style={styles.suiteStatusPills}>
                  {killSwitch && (
                    <View style={[styles.miniPill, { borderColor: 'rgba(255,46,99,0.3)', backgroundColor: 'rgba(255,46,99,0.06)' }]}>
                      <View style={[styles.miniDot, { backgroundColor: Colors.dark.accentCoral }]} />
                      <Text style={[styles.miniPillText, { color: Colors.dark.accentCoral }]}>KS</Text>
                    </View>
                  )}
                  {doubleVpn && (
                    <View style={[styles.miniPill, { borderColor: 'rgba(195,0,255,0.3)', backgroundColor: 'rgba(195,0,255,0.06)' }]}>
                      <View style={[styles.miniDot, { backgroundColor: Colors.dark.accentPurple }]} />
                      <Text style={[styles.miniPillText, { color: Colors.dark.accentPurple }]}>2x</Text>
                    </View>
                  )}
                </View>
                <Ionicons name="chevron-forward" size={16} color={Colors.dark.textMuted} />
              </View>
            </View>
            <View style={styles.suiteProtocol}>
              <Ionicons name="shield-checkmark" size={12} color={Colors.dark.accent} />
              <Text style={styles.suiteProtocolText}>{protocol}</Text>
            </View>
          </GlassCard>
        </Pressable>

        <View style={{ height: 12 }} />

        <Pressable
          onPress={() => {
            if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
            setFingerprintPanelVisible(true);
          }}
        >
          <GlassCard style={styles.securitySuiteCard} intensity="medium" glowColor={Colors.dark.accentPurple}>
            <View style={styles.suiteRow}>
              <View style={styles.suiteLeft}>
                <View style={[styles.suiteIconWrap, { backgroundColor: 'rgba(195,0,255,0.08)', borderColor: 'rgba(195,0,255,0.15)' }]}>
                  <MaterialCommunityIcons name="fingerprint" size={22} color={Colors.dark.accentPurple} />
                </View>
                <View style={styles.suiteTextGroup}>
                  <Text style={styles.suiteTitle}>Fingerprint Shield</Text>
                  <Text style={styles.suiteDesc}>WebRTC, Timezone, Canvas, UA</Text>
                </View>
              </View>
              <View style={styles.suiteRight}>
                <View style={styles.suiteStatusPills}>
                  {summary.activeProtections > 0 && (
                    <View style={[styles.miniPill, { borderColor: 'rgba(195,0,255,0.3)', backgroundColor: 'rgba(195,0,255,0.06)' }]}>
                      <View style={[styles.miniDot, { backgroundColor: Colors.dark.accentPurple }]} />
                      <Text style={[styles.miniPillText, { color: Colors.dark.accentPurple }]}>{summary.activeProtections}/4</Text>
                    </View>
                  )}
                </View>
                <Ionicons name="chevron-forward" size={16} color={Colors.dark.textMuted} />
              </View>
            </View>
            <View style={styles.suiteProtocol}>
              <MaterialCommunityIcons name="shield-check" size={12} color={Colors.dark.accentPurple} />
              <Text style={[styles.suiteProtocolText, { color: Colors.dark.accentPurple }]}>
                {summary.protectionLevel.toUpperCase()}
              </Text>
            </View>
          </GlassCard>
        </Pressable>

        <Text style={styles.sectionLabel}>CONNECTION</Text>
        <GlassCard style={styles.settingsCard} intensity="low">
          <AutoConnectToggle value={autoConnect} onChange={handleAutoConnectToggle} />
          <View style={styles.divider} />
          <BiometricLockToggle value={biometricLock} loading={biometricLoading} onChange={handleBiometricToggle} />
        </GlassCard>

        <Text style={styles.sectionLabel}>PRIVACY</Text>
        <GlassCard style={styles.settingsCard} intensity="low">
          <DnsLeakToggle value={dnsLeakProtection} onChange={handleDnsToggle} />
          <View style={styles.divider} />
          <AdBlockerToggle value={adBlocker} onChange={handleAdBlockerToggle} />
          <View style={styles.divider} />
          <SettingRow icon="document-text-outline" iconColor={Colors.dark.textSecondary} title="No-Log Policy" subtitle="Zero activity logging guaranteed">
            <View style={styles.verifiedBadge}>
              <Ionicons name="checkmark-circle" size={14} color={Colors.dark.success} />
              <Text style={styles.verifiedText}>Audited – Always Active</Text>
            </View>
          </SettingRow>
        </GlassCard>

        <Text style={styles.sectionLabel}>SUBSCRIPTION</Text>
        <Pressable
          onPress={() => {
            if (!isPremium) {
              if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
              setSubscriptionModalVisible(true);
            }
          }}
        >
          <GlassCard style={styles.securitySuiteCard} intensity="medium" glowColor={isPremium ? Colors.dark.success : Colors.dark.accentPurple}>
            <View style={styles.suiteRow}>
              <View style={styles.suiteLeft}>
                <View style={[styles.suiteIconWrap, {
                  backgroundColor: isPremium ? 'rgba(0,230,118,0.08)' : 'rgba(195,0,255,0.08)',
                  borderColor: isPremium ? 'rgba(0,230,118,0.15)' : 'rgba(195,0,255,0.15)',
                }]}>
                  <Ionicons name="diamond" size={22} color={isPremium ? Colors.dark.success : Colors.dark.accentPurple} />
                </View>
                <View style={styles.suiteTextGroup}>
                  <Text style={styles.suiteTitle}>{isPremium ? 'Premium Active' : 'Upgrade to Premium'}</Text>
                  <Text style={[styles.suiteDesc, { color: isPremium ? Colors.dark.success : Colors.dark.accentPurple }]}>
                    {isPremium
                      ? `${subscriptionType === 'elite_stealth' ? 'Elite Stealth' : 'Annual Pass'}${subscriptionExpiresAt ? ` · Renews ${new Date(subscriptionExpiresAt).toLocaleDateString()}` : ''}`
                      : 'Unlock all servers & features'}
                  </Text>
                </View>
              </View>
              {!isPremium && (
                <Ionicons name="chevron-forward" size={16} color={Colors.dark.textMuted} />
              )}
              {isPremium && (
                <View style={[styles.miniPill, { borderColor: 'rgba(0,230,118,0.3)', backgroundColor: 'rgba(0,230,118,0.06)' }]}>
                  <View style={[styles.miniDot, { backgroundColor: Colors.dark.success }]} />
                  <Text style={[styles.miniPillText, { color: Colors.dark.success }]}>ACTIVE</Text>
                </View>
              )}
            </View>
          </GlassCard>
        </Pressable>

        <Text style={styles.sectionLabel}>ACCOUNT</Text>
        <GlassCard style={styles.settingsCard} intensity="low">
          <SettingRow icon="person-circle-outline" iconColor={Colors.dark.accent} title={user?.displayName || 'User'} subtitle={user?.email || ''}>
            <View />
          </SettingRow>

          <View style={styles.divider} />

          <Pressable
            style={styles.logoutRow}
            onPress={() => {
              if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
              logout();
            }}
          >
            <View style={[styles.settingIcon, { backgroundColor: 'rgba(255,46,99,0.1)' }]}>
              <Ionicons name="log-out-outline" size={18} color={Colors.dark.accentCoral} />
            </View>
            <Text style={styles.logoutText}>Sign Out</Text>
          </Pressable>
        </GlassCard>

        <Text style={styles.sectionLabel}>ABOUT</Text>
        <GlassCard style={styles.settingsCard} intensity="low">
          <SettingRow icon="information-circle-outline" iconColor={Colors.dark.textSecondary} title="Version" subtitle="xVPN for mobile">
            <Text style={styles.versionText}>2.0.26</Text>
          </SettingRow>
        </GlassCard>

        <View style={styles.branding}>
          <Text style={styles.brandingLogo}>xVPN</Text>
          <Text style={styles.brandingText}>Deep Space Security</Text>
        </View>
      </ScrollView>

      {toast && (
        <View style={styles.toastContainer}>
          <View style={styles.toast}>
            <Ionicons name="checkmark-circle" size={16} color={Colors.dark.accent} />
            <Text style={styles.toastText}>{toast}</Text>
          </View>
        </View>
      )}

      <SecuritySuitePanel
        visible={securityPanelVisible}
        onClose={() => setSecurityPanelVisible(false)}
      />

      <FingerprintShieldPanel
        visible={fingerprintPanelVisible}
        onClose={() => setFingerprintPanelVisible(false)}
      />

      <SubscriptionModal
        visible={subscriptionModalVisible}
        onClose={() => setSubscriptionModalVisible(false)}
      />
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
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 13,
    color: Colors.dark.accent,
    marginTop: 4,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  sectionLabel: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 10,
    color: Colors.dark.accent,
    letterSpacing: 3,
    paddingHorizontal: 24,
    marginTop: 22,
    marginBottom: 10,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  securitySuiteCard: {
    marginHorizontal: 20,
    padding: 16,
    marginBottom: 2,
  },
  suiteRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  suiteLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    flex: 1,
  },
  suiteIconWrap: {
    width: 42,
    height: 42,
    borderRadius: 14,
    backgroundColor: 'rgba(0,240,255,0.08)',
    borderWidth: 1,
    borderColor: 'rgba(0,240,255,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  suiteTextGroup: {
    flex: 1,
  },
  suiteTitle: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 15,
    color: Colors.dark.text,
  },
  suiteDesc: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    color: Colors.dark.accent,
    marginTop: 2,
    letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  suiteRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  suiteStatusPills: {
    flexDirection: 'row',
    gap: 4,
  },
  miniPill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 3,
    paddingHorizontal: 6,
    paddingVertical: 3,
    borderRadius: 6,
    borderWidth: 1,
  },
  miniDot: {
    width: 4,
    height: 4,
    borderRadius: 2,
  },
  miniPillText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 7,
    letterSpacing: 1,
  },
  suiteProtocol: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginTop: 10,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.04)',
  },
  suiteProtocolText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 9,
    color: Colors.dark.accent,
    letterSpacing: 2,
  },
  settingsCard: {
    marginHorizontal: 20,
    padding: 4,
    overflow: 'hidden',
  },
  settingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 14,
    gap: 12,
    minHeight: 64,
    overflow: 'hidden',
  },
  settingIcon: {
    width: 36,
    height: 36,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  },
  settingTextGroup: {
    flex: 1,
    overflow: 'hidden',
  },
  switchContainer: {
    width: 52,
    height: 32,
    justifyContent: 'center',
    alignItems: 'center',
    flexShrink: 0,
  },
  settingTitle: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 14,
    color: Colors.dark.text,
  },
  settingSubtitle: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    color: Colors.dark.accent,
    marginTop: 2,
    letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  divider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.04)',
    marginHorizontal: 14,
  },
  verifiedBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    backgroundColor: 'rgba(0, 230, 118, 0.1)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 10,
  },
  verifiedText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.success,
  },
  versionText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 12,
    color: Colors.dark.textMuted,
  },
  branding: {
    alignItems: 'center',
    marginTop: 30,
    gap: 4,
  },
  brandingLogo: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 16,
    color: Colors.dark.accent,
    letterSpacing: 4,
    opacity: 0.4,
  },
  brandingText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.textMuted,
    opacity: 0.4,
  },
  logoutRow: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 14,
    gap: 12,
  },
  logoutText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 14,
    color: Colors.dark.accentCoral,
  },
  toastContainer: {
    position: 'absolute',
    bottom: 100,
    left: 0,
    right: 0,
    alignItems: 'center',
  },
  toast: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    backgroundColor: 'rgba(0,0,0,0.85)',
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderRadius: 24,
    borderWidth: 1,
    borderColor: 'rgba(0,240,255,0.2)',
  },
  toastText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 13,
    color: Colors.dark.text,
  },
});

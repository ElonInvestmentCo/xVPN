import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, Modal, Pressable, ScrollView, Switch, Platform, Dimensions } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
  withTiming,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { GlassCard } from '@/components/GlassCard';
import { useFingerprintShield } from '@/lib/fingerprint-context';
import { USER_AGENT_LABELS, UserAgentProfile } from '@/lib/fingerprint-shield';
import Colors from '@/constants/colors';

const { width: SCREEN_WIDTH } = Dimensions.get('window');
const PANEL_WIDTH = Math.min(SCREEN_WIDTH * 0.92, 400);

const UA_PROFILES: UserAgentProfile[] = ['windows_chrome', 'windows_firefox', 'mac_safari', 'mac_chrome', 'iphone_safari'];

interface FingerprintShieldPanelProps {
  visible: boolean;
  onClose: () => void;
}

function ProtectionMeter({ active, total }: { active: number; total: number }) {
  const segments = Array.from({ length: total }, (_, i) => i < active);
  const levelColor = active === 4 ? Colors.dark.success : active >= 2 ? Colors.dark.warning : active >= 1 ? Colors.dark.accentCoral : Colors.dark.textMuted;
  const levelLabel = active === 4 ? 'MAXIMUM' : active >= 2 ? 'MODERATE' : active >= 1 ? 'BASIC' : 'NONE';

  return (
    <View style={meterStyles.container}>
      <View style={meterStyles.barRow}>
        {segments.map((filled, i) => (
          <View
            key={i}
            style={[
              meterStyles.segment,
              { backgroundColor: filled ? levelColor : 'rgba(255,255,255,0.06)' },
            ]}
          />
        ))}
      </View>
      <View style={meterStyles.labelRow}>
        <Text style={[meterStyles.levelText, { color: levelColor }]}>{levelLabel}</Text>
        <Text style={meterStyles.countText}>{active}/{total} active</Text>
      </View>
    </View>
  );
}

const meterStyles = StyleSheet.create({
  container: {
    gap: 6,
  },
  barRow: {
    flexDirection: 'row',
    gap: 3,
  },
  segment: {
    flex: 1,
    height: 4,
    borderRadius: 2,
  },
  labelRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  levelText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    letterSpacing: 2,
  },
  countText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textMuted,
  },
});

export function FingerprintShieldPanel({ visible, onClose }: FingerprintShieldPanelProps) {
  const insets = useSafeAreaInsets();
  const {
    state,
    summary,
    setWebRTCMask,
    setTimezoneSpoofing,
    setCanvasNoise,
    setUserAgentRotation,
    setActiveUserAgent,
    cycleUserAgent,
  } = useFingerprintShield();

  const topPadding = Platform.OS === 'web' ? 67 : insets.top;
  const bottomPadding = Platform.OS === 'web' ? 34 : insets.bottom;
  const slideX = useSharedValue(PANEL_WIDTH);
  const [uaExpanded, setUaExpanded] = useState(false);

  useEffect(() => {
    if (visible) {
      slideX.value = withSpring(0, { damping: 20, stiffness: 200 });
    } else {
      slideX.value = withTiming(PANEL_WIDTH, { duration: 250 });
    }
  }, [visible]);

  const panelAnimStyle = useAnimatedStyle(() => ({
    transform: [{ translateX: slideX.value }],
  }));

  const hapticToggle = (fn: (v: boolean) => void) => (v: boolean) => {
    if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    fn(v);
  };

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onClose}
      statusBarTranslucent
    >
      <View style={styles.overlay}>
        <Pressable style={styles.backdropTouch} onPress={onClose} />
        <Animated.View style={[styles.panel, panelAnimStyle, { paddingTop: topPadding + 12, paddingBottom: bottomPadding + 12 }]}>
          <View style={styles.panelHeader}>
            <View style={styles.panelTitleRow}>
              <MaterialCommunityIcons name="fingerprint" size={20} color={Colors.dark.accent} />
              <Text style={styles.panelTitle}>Fingerprint Shield</Text>
            </View>
            <Pressable onPress={onClose} hitSlop={12}>
              <Ionicons name="close" size={22} color={Colors.dark.textSecondary} />
            </Pressable>
          </View>

          <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.panelContent}>
            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={Colors.dark.accent}>
              <View style={styles.meterHeader}>
                <MaterialCommunityIcons name="shield-check" size={16} color={Colors.dark.accent} />
                <Text style={styles.meterTitle}>Protection Level</Text>
              </View>
              <ProtectionMeter active={summary.activeProtections} total={summary.totalProtections} />
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={state.webrtcMask ? Colors.dark.accentCoral : undefined}>
              <View style={styles.sectionRow}>
                <View style={styles.sectionLeft}>
                  <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(255,46,99,0.1)' }]}>
                    <MaterialCommunityIcons name="web-remove" size={16} color={Colors.dark.accentCoral} />
                  </View>
                  <View style={styles.sectionTextGroup}>
                    <Text style={styles.sectionTitle}>WebRTC Mask</Text>
                    <Text style={styles.sectionDesc}>Blocks STUN queries from leaking your real local IP address through WebRTC</Text>
                  </View>
                </View>
                <Switch
                  value={state.webrtcMask}
                  onValueChange={hapticToggle(setWebRTCMask)}
                  trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(255,46,99,0.3)' }}
                  thumbColor={state.webrtcMask ? Colors.dark.accentCoral : '#555'}
                />
              </View>
              {state.webrtcMask && (
                <View style={styles.statusGrid}>
                  <StatusPill label="Local IP" status="Hidden" color={Colors.dark.success} />
                  <StatusPill label="STUN" status="Blocked" color={Colors.dark.success} />
                  <StatusPill label="TURN" status="Blocked" color={Colors.dark.success} />
                  <StatusPill label="mDNS" status="Enabled" color={Colors.dark.success} />
                </View>
              )}
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={state.timezoneSpoofing ? Colors.dark.accentPurple : undefined}>
              <View style={styles.sectionRow}>
                <View style={styles.sectionLeft}>
                  <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(195,0,255,0.1)' }]}>
                    <Ionicons name="time-outline" size={16} color={Colors.dark.accentPurple} />
                  </View>
                  <View style={styles.sectionTextGroup}>
                    <Text style={styles.sectionTitle}>Timezone Spoofing</Text>
                    <Text style={styles.sectionDesc}>Syncs browser timezone to match your selected VPN server location</Text>
                  </View>
                </View>
                <Switch
                  value={state.timezoneSpoofing}
                  onValueChange={hapticToggle(setTimezoneSpoofing)}
                  trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(195,0,255,0.3)' }}
                  thumbColor={state.timezoneSpoofing ? Colors.dark.accentPurple : '#555'}
                />
              </View>
              {state.timezoneSpoofing && summary.timezone.spoofedTimezone && (
                <View style={styles.infoBox}>
                  <View style={styles.infoRow}>
                    <Text style={styles.infoLabel}>Original</Text>
                    <Text style={styles.infoValue}>{summary.timezone.originalTimezone}</Text>
                  </View>
                  <View style={styles.infoDivider} />
                  <View style={styles.infoRow}>
                    <Text style={styles.infoLabel}>Spoofed To</Text>
                    <Text style={[styles.infoValue, { color: Colors.dark.accentPurple }]}>{summary.timezone.spoofedTimezone}</Text>
                  </View>
                  <View style={styles.infoDivider} />
                  <View style={styles.statusGrid}>
                    <StatusPill label="Intl API" status="Patched" color={Colors.dark.success} />
                    <StatusPill label="Date API" status="Patched" color={Colors.dark.success} />
                  </View>
                </View>
              )}
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={state.canvasNoise ? Colors.dark.warning : undefined}>
              <View style={styles.sectionRow}>
                <View style={styles.sectionLeft}>
                  <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(255,179,0,0.1)' }]}>
                    <MaterialCommunityIcons name="image-filter-hdr" size={16} color={Colors.dark.warning} />
                  </View>
                  <View style={styles.sectionTextGroup}>
                    <Text style={styles.sectionTitle}>Canvas Defeat</Text>
                    <Text style={styles.sectionDesc}>Injects subtle noise into Canvas rendering to prevent GPU/hardware fingerprinting</Text>
                  </View>
                </View>
                <Switch
                  value={state.canvasNoise}
                  onValueChange={hapticToggle(setCanvasNoise)}
                  trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(255,179,0,0.3)' }}
                  thumbColor={state.canvasNoise ? Colors.dark.warning : '#555'}
                />
              </View>
              {state.canvasNoise && (
                <View style={styles.statusGrid}>
                  <StatusPill label="Noise" status={`${(state.canvasNoiseLevel * 100).toFixed(0)}%`} color={Colors.dark.warning} />
                  <StatusPill label="Hash" status="Randomized" color={Colors.dark.success} />
                  <StatusPill label="GPU Info" status="Masked" color={Colors.dark.success} />
                </View>
              )}
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={state.userAgentRotation ? Colors.dark.accent : undefined}>
              <View style={styles.sectionRow}>
                <View style={styles.sectionLeft}>
                  <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(0,240,255,0.1)' }]}>
                    <MaterialCommunityIcons name="account-switch" size={16} color={Colors.dark.accent} />
                  </View>
                  <View style={styles.sectionTextGroup}>
                    <Text style={styles.sectionTitle}>User-Agent Rotation</Text>
                    <Text style={styles.sectionDesc}>Cycles between common browser strings to appear as a standard retail user</Text>
                  </View>
                </View>
                <Switch
                  value={state.userAgentRotation}
                  onValueChange={hapticToggle(setUserAgentRotation)}
                  trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(0,240,255,0.3)' }}
                  thumbColor={state.userAgentRotation ? Colors.dark.accent : '#555'}
                />
              </View>

              <View style={styles.uaDivider} />
              <Text style={styles.uaSectionLabel}>BROWSER PROFILE</Text>

              <Pressable
                style={styles.uaTrigger}
                onPress={() => {
                  if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
                  setUaExpanded(!uaExpanded);
                }}
              >
                <Text style={styles.uaTriggerText}>{USER_AGENT_LABELS[state.activeUserAgent]}</Text>
                <Ionicons name={uaExpanded ? 'chevron-up' : 'chevron-down'} size={14} color={Colors.dark.textMuted} />
              </Pressable>

              {uaExpanded && (
                <View style={styles.uaList}>
                  {UA_PROFILES.map(profile => {
                    const isActive = state.activeUserAgent === profile;
                    return (
                      <Pressable
                        key={profile}
                        style={[styles.uaOption, isActive && styles.uaOptionActive]}
                        onPress={() => {
                          if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
                          setActiveUserAgent(profile);
                          setUaExpanded(false);
                        }}
                      >
                        <Text style={[styles.uaOptionText, isActive && styles.uaOptionTextActive]}>
                          {USER_AGENT_LABELS[profile]}
                        </Text>
                        {isActive && <Ionicons name="checkmark-circle" size={14} color={Colors.dark.accent} />}
                      </Pressable>
                    );
                  })}
                </View>
              )}

              {state.userAgentRotation && (
                <Pressable
                  style={styles.cycleButton}
                  onPress={() => {
                    if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
                    cycleUserAgent();
                  }}
                >
                  <MaterialCommunityIcons name="refresh" size={14} color={Colors.dark.accent} />
                  <Text style={styles.cycleButtonText}>Rotate Now</Text>
                </Pressable>
              )}

              {state.userAgentRotation && state.currentUserAgentString && (
                <View style={styles.uaStringBox}>
                  <Text style={styles.uaStringLabel}>ACTIVE UA STRING</Text>
                  <Text style={styles.uaString} numberOfLines={2}>{state.currentUserAgentString}</Text>
                </View>
              )}
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="low">
              <View style={styles.disclaimerRow}>
                <Ionicons name="information-circle-outline" size={16} color={Colors.dark.textMuted} />
                <Text style={styles.disclaimerText}>
                  Client-side fingerprint shield works alongside the server-side protection engine for comprehensive anti-tracking defense.
                </Text>
              </View>
            </GlassCard>
          </ScrollView>
        </Animated.View>
      </View>
    </Modal>
  );
}

function StatusPill({ label, status, color }: { label: string; status: string; color: string }) {
  return (
    <View style={pillStyles.container}>
      <View style={[pillStyles.dot, { backgroundColor: color }]} />
      <Text style={pillStyles.label}>{label}</Text>
      <Text style={[pillStyles.status, { color }]}>{status}</Text>
    </View>
  );
}

const pillStyles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 5,
  },
  dot: {
    width: 4,
    height: 4,
    borderRadius: 2,
  },
  label: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 9,
    color: Colors.dark.textMuted,
  },
  status: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 7,
    letterSpacing: 1,
    marginLeft: 2,
  },
});

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.6)',
    flexDirection: 'row',
    justifyContent: 'flex-end',
  },
  backdropTouch: {
    flex: 1,
  },
  panel: {
    width: PANEL_WIDTH,
    backgroundColor: '#0F0F0F',
    borderLeftWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
    paddingHorizontal: 16,
  },
  panelHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  panelTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  panelTitle: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 14,
    color: Colors.dark.text,
    letterSpacing: 2,
  },
  panelContent: {
    gap: 14,
    paddingBottom: 20,
  },
  sectionCard: {
    padding: 16,
  },
  sectionRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
  },
  sectionLeft: {
    flexDirection: 'row',
    flex: 1,
    gap: 10,
    marginRight: 10,
  },
  sectionIconWrap: {
    width: 34,
    height: 34,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  sectionTextGroup: {
    flex: 1,
  },
  sectionTitle: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 14,
    color: Colors.dark.text,
  },
  sectionDesc: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 11,
    color: Colors.dark.textMuted,
    marginTop: 3,
    lineHeight: 16,
  },
  meterHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 10,
  },
  meterTitle: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 13,
    color: Colors.dark.text,
  },
  statusGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 6,
    marginTop: 12,
  },
  infoBox: {
    marginTop: 12,
    backgroundColor: 'rgba(255,255,255,0.02)',
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.04)',
    padding: 10,
    gap: 6,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  infoLabel: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textMuted,
  },
  infoValue: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 9,
    color: Colors.dark.textSecondary,
    letterSpacing: 1,
  },
  infoDivider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.03)',
  },
  uaDivider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.04)',
    marginTop: 14,
  },
  uaSectionLabel: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    color: Colors.dark.textMuted,
    letterSpacing: 3,
    marginTop: 12,
    marginBottom: 6,
    marginLeft: 4,
  },
  uaTrigger: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: 'rgba(255,255,255,0.04)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.06)',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
  },
  uaTriggerText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
  uaList: {
    marginTop: 6,
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
  },
  uaOption: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 8,
  },
  uaOptionActive: {
    backgroundColor: 'rgba(0,240,255,0.06)',
  },
  uaOptionText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
  uaOptionTextActive: {
    color: Colors.dark.accent,
  },
  cycleButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    marginTop: 10,
    backgroundColor: 'rgba(0,240,255,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(0,240,255,0.15)',
    borderRadius: 10,
    paddingVertical: 10,
  },
  cycleButtonText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 10,
    color: Colors.dark.accent,
    letterSpacing: 2,
  },
  uaStringBox: {
    marginTop: 10,
    backgroundColor: 'rgba(0,0,0,0.3)',
    borderRadius: 8,
    padding: 10,
    gap: 4,
  },
  uaStringLabel: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 7,
    color: Colors.dark.textMuted,
    letterSpacing: 2,
  },
  uaString: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 9,
    color: Colors.dark.textSecondary,
    lineHeight: 14,
  },
  disclaimerRow: {
    flexDirection: 'row',
    gap: 8,
    alignItems: 'flex-start',
  },
  disclaimerText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textMuted,
    flex: 1,
    lineHeight: 15,
  },
});

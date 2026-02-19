import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, Modal, Pressable, ScrollView, Switch, Platform, Dimensions } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withSpring,
  Easing,
  SlideInRight,
  SlideOutRight,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import Svg, { Line, Circle, Rect } from 'react-native-svg';
import * as Haptics from 'expo-haptics';
import { GlassCard } from '@/components/GlassCard';
import { useVpn } from '@/lib/vpn-context';
import Colors from '@/constants/colors';

const { width: SCREEN_WIDTH } = Dimensions.get('window');
const PANEL_WIDTH = Math.min(SCREEN_WIDTH * 0.92, 400);

const PROTOCOLS = ['WireGuard', 'OpenVPN', 'Stealth'];

interface SecuritySuitePanelProps {
  visible: boolean;
  onClose: () => void;
}

function MultiHopVisual({ entry, exit, enabled }: { entry: string; exit: string; enabled: boolean }) {
  const opacity = enabled ? 1 : 0.3;
  const lineColor = enabled ? Colors.dark.accentPurple : 'rgba(255,255,255,0.1)';
  const nodeActiveColor = enabled ? Colors.dark.accent : 'rgba(255,255,255,0.15)';
  const hopColor = enabled ? Colors.dark.accentPurple : 'rgba(255,255,255,0.1)';

  return (
    <View style={[hopStyles.container, { opacity }]}>
      <View style={hopStyles.row}>
        <View style={hopStyles.nodeColumn}>
          <View style={[hopStyles.node, { borderColor: nodeActiveColor }]}>
            <MaterialCommunityIcons name="laptop" size={16} color={nodeActiveColor} />
          </View>
          <Text style={hopStyles.nodeLabel}>You</Text>
        </View>

        <View style={hopStyles.lineSection}>
          <Svg height={24} width={60}>
            <Line x1={0} y1={12} x2={60} y2={12} stroke={lineColor} strokeWidth={1.5} strokeDasharray="4 3" />
            <Circle cx={20} cy={12} r={2} fill={lineColor} />
            <Circle cx={40} cy={12} r={2} fill={lineColor} />
          </Svg>
          <Text style={[hopStyles.lineLabel, { color: lineColor }]}>AES-256</Text>
        </View>

        <View style={hopStyles.nodeColumn}>
          <View style={[hopStyles.node, { borderColor: hopColor, backgroundColor: enabled ? 'rgba(195,0,255,0.08)' : 'transparent' }]}>
            <Ionicons name="server-outline" size={14} color={hopColor} />
          </View>
          <Text style={[hopStyles.nodeLabel, { color: hopColor }]} numberOfLines={1}>{entry}</Text>
        </View>

        <View style={hopStyles.lineSection}>
          <Svg height={24} width={60}>
            <Line x1={0} y1={12} x2={60} y2={12} stroke={hopColor} strokeWidth={1.5} strokeDasharray="4 3" />
            <Circle cx={20} cy={12} r={2} fill={hopColor} />
            <Circle cx={40} cy={12} r={2} fill={hopColor} />
          </Svg>
          <Text style={[hopStyles.lineLabel, { color: hopColor }]}>ChaCha20</Text>
        </View>

        <View style={hopStyles.nodeColumn}>
          <View style={[hopStyles.node, { borderColor: nodeActiveColor, backgroundColor: enabled ? 'rgba(0,240,255,0.08)' : 'transparent' }]}>
            <Ionicons name="globe-outline" size={14} color={nodeActiveColor} />
          </View>
          <Text style={[hopStyles.nodeLabel, { color: nodeActiveColor }]} numberOfLines={1}>{exit}</Text>
        </View>
      </View>
    </View>
  );
}

const hopStyles = StyleSheet.create({
  container: {
    paddingVertical: 12,
    paddingHorizontal: 4,
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
  },
  nodeColumn: {
    alignItems: 'center',
    gap: 4,
    width: 52,
  },
  node: {
    width: 38,
    height: 38,
    borderRadius: 12,
    borderWidth: 1.5,
    alignItems: 'center',
    justifyContent: 'center',
  },
  nodeLabel: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 8,
    color: Colors.dark.textMuted,
    textAlign: 'center',
  },
  lineSection: {
    alignItems: 'center',
    gap: 2,
    flex: 1,
  },
  lineLabel: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 6,
    letterSpacing: 1,
  },
});

function HopServerSelector({ servers, selectedId, onSelect, label }: {
  servers: { id: string; name: string; city: string }[];
  selectedId: string | undefined;
  onSelect: (id: string) => void;
  label: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const selected = servers.find(s => s.id === selectedId);

  return (
    <View style={selectorStyles.container}>
      <Text style={selectorStyles.label}>{label}</Text>
      <Pressable
        style={selectorStyles.trigger}
        onPress={() => {
          Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
          setExpanded(!expanded);
        }}
      >
        <Text style={selectorStyles.triggerText}>{selected ? `${selected.name} - ${selected.city}` : 'Select'}</Text>
        <Ionicons name={expanded ? 'chevron-up' : 'chevron-down'} size={14} color={Colors.dark.textMuted} />
      </Pressable>
      {expanded && (
        <View style={selectorStyles.list}>
          {servers.map(s => (
            <Pressable
              key={s.id}
              style={[selectorStyles.option, s.id === selectedId && selectorStyles.optionActive]}
              onPress={() => {
                Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
                onSelect(s.id);
                setExpanded(false);
              }}
            >
              <Text style={[selectorStyles.optionText, s.id === selectedId && selectorStyles.optionTextActive]}>{s.name}</Text>
              <Text style={selectorStyles.optionCity}>{s.city}</Text>
            </Pressable>
          ))}
        </View>
      )}
    </View>
  );
}

const selectorStyles = StyleSheet.create({
  container: {
    gap: 6,
  },
  label: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    color: Colors.dark.textMuted,
    letterSpacing: 2,
    marginLeft: 4,
  },
  trigger: {
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
  triggerText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
  list: {
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderRadius: 10,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    maxHeight: 150,
  },
  option: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 8,
  },
  optionActive: {
    backgroundColor: 'rgba(195,0,255,0.08)',
  },
  optionText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
  optionTextActive: {
    color: Colors.dark.accentPurple,
  },
  optionCity: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textMuted,
  },
});

export function SecuritySuitePanel({ visible, onClose }: SecuritySuitePanelProps) {
  const insets = useSafeAreaInsets();
  const {
    killSwitch, setKillSwitch,
    protocol, setProtocol,
    doubleVpn, setDoubleVpn,
    doubleVpnServer, setDoubleVpnServer,
    selectedServer, servers,
  } = useVpn();
  const topPadding = Platform.OS === 'web' ? 67 : insets.top;
  const bottomPadding = Platform.OS === 'web' ? 34 : insets.bottom;
  const slideX = useSharedValue(PANEL_WIDTH);

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

  const entryServer = selectedServer?.name || 'Server 1';
  const exitServer = doubleVpnServer?.name || 'Server 2';

  const otherServers = servers.filter(s => s.id !== selectedServer?.id);

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
              <MaterialCommunityIcons name="shield-lock" size={20} color={Colors.dark.accent} />
              <Text style={styles.panelTitle}>Security Suite</Text>
            </View>
            <Pressable onPress={onClose} hitSlop={12}>
              <Ionicons name="close" size={22} color={Colors.dark.textSecondary} />
            </Pressable>
          </View>

          <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.panelContent}>
            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={killSwitch ? Colors.dark.accentCoral : undefined}>
              <View style={styles.sectionRow}>
                <View style={styles.sectionLeft}>
                  <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(255,46,99,0.1)' }]}>
                    <Ionicons name="warning" size={16} color={Colors.dark.accentCoral} />
                  </View>
                  <View style={styles.sectionTextGroup}>
                    <Text style={styles.sectionTitle}>Kill Switch</Text>
                    <Text style={styles.sectionDesc}>Instantly blocks all traffic if the VPN connection drops unexpectedly</Text>
                  </View>
                </View>
                <Switch
                  value={killSwitch}
                  onValueChange={(v) => {
                    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
                    setKillSwitch(v);
                  }}
                  trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(255,46,99,0.3)' }}
                  thumbColor={killSwitch ? Colors.dark.accentCoral : '#555'}
                />
              </View>
              {killSwitch && (
                <View style={styles.warningBanner}>
                  <Ionicons name="warning" size={12} color={Colors.dark.accentCoral} />
                  <Text style={styles.warningText}>All internet traffic will halt if VPN disconnects</Text>
                </View>
              )}
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={doubleVpn ? Colors.dark.accentPurple : undefined}>
              <View style={styles.sectionRow}>
                <View style={styles.sectionLeft}>
                  <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(195,0,255,0.1)' }]}>
                    <MaterialCommunityIcons name="vector-polyline" size={16} color={Colors.dark.accentPurple} />
                  </View>
                  <View style={styles.sectionTextGroup}>
                    <Text style={styles.sectionTitle}>Double VPN</Text>
                    <Text style={styles.sectionDesc}>Route traffic through two servers for extra encryption layers</Text>
                  </View>
                </View>
                <Switch
                  value={doubleVpn}
                  onValueChange={(v) => {
                    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
                    setDoubleVpn(v);
                  }}
                  trackColor={{ false: 'rgba(255,255,255,0.1)', true: 'rgba(195,0,255,0.3)' }}
                  thumbColor={doubleVpn ? Colors.dark.accentPurple : '#555'}
                />
              </View>

              <View style={styles.hopDivider} />
              <Text style={styles.hopSectionLabel}>MULTI-HOP PATH</Text>
              <MultiHopVisual entry={entryServer} exit={exitServer} enabled={doubleVpn} />

              {doubleVpn && (
                <View style={styles.hopServerSelect}>
                  <HopServerSelector
                    servers={otherServers}
                    selectedId={doubleVpnServer?.id}
                    onSelect={(id) => {
                      const s = servers.find(srv => srv.id === id) || null;
                      setDoubleVpnServer(s);
                    }}
                    label="EXIT NODE"
                  />
                </View>
              )}
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="medium" glowColor={Colors.dark.accent}>
              <View style={styles.protocolHeader}>
                <View style={[styles.sectionIconWrap, { backgroundColor: 'rgba(0,240,255,0.1)' }]}>
                  <Ionicons name="shield-checkmark" size={16} color={Colors.dark.accent} />
                </View>
                <View style={styles.sectionTextGroup}>
                  <Text style={styles.sectionTitle}>Protocol</Text>
                  <Text style={styles.sectionDesc}>Select your tunnel encryption protocol</Text>
                </View>
              </View>

              <View style={styles.protocolGrid}>
                {PROTOCOLS.map(p => {
                  const isActive = protocol === p;
                  const icon = p === 'WireGuard' ? 'flash' : p === 'OpenVPN' ? 'lock-closed' : 'eye-off';
                  const desc = p === 'WireGuard' ? 'Fastest & modern' : p === 'OpenVPN' ? 'Battle-tested' : 'Bypass censorship';
                  return (
                    <Pressable
                      key={p}
                      style={[styles.protocolCard, isActive && styles.protocolCardActive]}
                      onPress={() => {
                        Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
                        setProtocol(p);
                      }}
                    >
                      <Ionicons name={icon as any} size={18} color={isActive ? Colors.dark.accent : Colors.dark.textMuted} />
                      <Text style={[styles.protocolName, isActive && styles.protocolNameActive]}>{p}</Text>
                      <Text style={styles.protocolDesc}>{desc}</Text>
                      {isActive && (
                        <View style={styles.protocolCheck}>
                          <Ionicons name="checkmark-circle" size={14} color={Colors.dark.accent} />
                        </View>
                      )}
                    </Pressable>
                  );
                })}
              </View>
            </GlassCard>

            <GlassCard style={styles.sectionCard} intensity="low">
              <View style={styles.encryptionRow}>
                <MaterialCommunityIcons name="shield-key-outline" size={18} color={Colors.dark.success} />
                <View style={styles.sectionTextGroup}>
                  <Text style={styles.sectionTitle}>Encryption Status</Text>
                  <Text style={styles.sectionDesc}>AES-256-GCM with Perfect Forward Secrecy</Text>
                </View>
                <View style={styles.militaryBadge}>
                  <Text style={styles.militaryBadgeText}>MILITARY</Text>
                </View>
              </View>
            </GlassCard>
          </ScrollView>
        </Animated.View>
      </View>
    </Modal>
  );
}

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
    fontSize: 16,
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
  warningBanner: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    backgroundColor: 'rgba(255,46,99,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(255,46,99,0.12)',
    borderRadius: 10,
    padding: 10,
    marginTop: 12,
  },
  warningText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.accentCoral,
    flex: 1,
  },
  hopDivider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.04)',
    marginTop: 14,
  },
  hopSectionLabel: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    color: Colors.dark.textMuted,
    letterSpacing: 3,
    marginTop: 12,
    marginLeft: 4,
  },
  hopServerSelect: {
    marginTop: 8,
  },
  protocolHeader: {
    flexDirection: 'row',
    gap: 10,
    marginBottom: 14,
  },
  protocolGrid: {
    gap: 8,
  },
  protocolCard: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.05)',
    borderRadius: 12,
    padding: 12,
  },
  protocolCardActive: {
    borderColor: 'rgba(0,240,255,0.25)',
    backgroundColor: 'rgba(0,240,255,0.04)',
  },
  protocolName: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 13,
    color: Colors.dark.textSecondary,
  },
  protocolNameActive: {
    color: Colors.dark.accent,
  },
  protocolDesc: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textMuted,
    flex: 1,
  },
  protocolCheck: {
    marginLeft: 'auto',
  },
  encryptionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  militaryBadge: {
    backgroundColor: 'rgba(0,230,118,0.1)',
    borderWidth: 1,
    borderColor: 'rgba(0,230,118,0.2)',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 8,
  },
  militaryBadgeText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 7,
    color: Colors.dark.success,
    letterSpacing: 2,
  },
});

import React from 'react';
import { View, Text, Pressable, StyleSheet, ViewStyle } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { GlassCard } from '@/components/GlassCard';
import Colors from '@/constants/colors';
import type { VpnServer } from '@/lib/vpn-context';

const REGION_COLORS: Record<string, string> = {
  US: Colors.dark.accent,
  GB: Colors.dark.accentPurple,
  DE: Colors.dark.accentPurple,
  JP: '#FF6B6B',
  SG: '#FF6B6B',
  AU: Colors.dark.warning,
  CA: Colors.dark.accent,
  NL: Colors.dark.accentPurple,
  CH: Colors.dark.accentPurple,
  FR: Colors.dark.accentPurple,
  KR: '#FF6B6B',
  BR: Colors.dark.success,
  IN: '#FF6B6B',
  SE: Colors.dark.accentPurple,
};

interface ServerCardProps {
  server: VpnServer;
  isSelected: boolean;
  isFavorite: boolean;
  onSelect: () => void;
  onToggleFavorite: () => void;
}

export function ServerCard({ server, isSelected, isFavorite, onSelect, onToggleFavorite }: ServerCardProps) {
  const pingColor = server.ping < 50 ? Colors.dark.success : server.ping < 100 ? Colors.dark.warning : Colors.dark.danger;
  const loadColor = server.load < 40 ? Colors.dark.success : server.load < 70 ? Colors.dark.warning : Colors.dark.danger;

  const handlePress = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    onSelect();
  };

  return (
    <Pressable onPress={handlePress}>
      <GlassCard
        style={[styles.card, isSelected && styles.selectedCard] as ViewStyle}
        intensity={isSelected ? 'high' : 'low'}
        glowColor={isSelected ? Colors.dark.accent : undefined}
      >
        <View style={styles.row}>
          <View style={styles.leftSection}>
            <View style={[styles.iconContainer, isSelected && styles.iconContainerSelected]}>
              <Ionicons
                name="globe-outline"
                size={22}
                color={isSelected ? Colors.dark.accent : (REGION_COLORS[server.flag] || Colors.dark.textSecondary)}
              />
            </View>
            <View style={styles.textGroup}>
              <View style={styles.nameRow}>
                <Text style={[styles.name, isSelected && styles.nameSelected]}>{server.name}</Text>
                {server.premium && (
                  <View style={styles.premiumBadge}>
                    <Ionicons name="diamond" size={10} color={Colors.dark.accentPurple} />
                  </View>
                )}
              </View>
              <Text style={styles.city}>{server.city}, {server.country}</Text>
            </View>
          </View>
          <View style={styles.rightSection}>
            <View style={styles.statsRow}>
              <View style={styles.stat}>
                <View style={[styles.statDot, { backgroundColor: pingColor }]} />
                <Text style={styles.statText}>{server.ping}ms</Text>
              </View>
              <View style={styles.stat}>
                <Ionicons name="speedometer-outline" size={12} color={loadColor} />
                <Text style={styles.statText}>{server.load}%</Text>
              </View>
            </View>
            <Pressable
              onPress={(e) => {
                e.stopPropagation?.();
                Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
                onToggleFavorite();
              }}
              hitSlop={12}
            >
              <Ionicons
                name={isFavorite ? 'star' : 'star-outline'}
                size={18}
                color={isFavorite ? '#00f2ff' : Colors.dark.textMuted}
              />
            </Pressable>
          </View>
        </View>
      </GlassCard>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  card: {
    marginHorizontal: 20,
    marginBottom: 10,
    padding: 16,
  },
  selectedCard: {
    borderColor: 'rgba(0, 240, 255, 0.2)',
  },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  leftSection: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  iconContainer: {
    width: 40,
    height: 40,
    borderRadius: 12,
    backgroundColor: 'rgba(255,255,255,0.04)',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  iconContainerSelected: {
    backgroundColor: 'rgba(0, 240, 255, 0.08)',
  },
  textGroup: {
    flex: 1,
  },
  nameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  name: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 15,
    color: Colors.dark.text,
  },
  nameSelected: {
    color: Colors.dark.accent,
  },
  premiumBadge: {
    width: 18,
    height: 18,
    borderRadius: 9,
    backgroundColor: 'rgba(195, 0, 255, 0.15)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  city: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 12,
    color: Colors.dark.accent,
    marginTop: 2,
    letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
  rightSection: {
    alignItems: 'flex-end',
    gap: 8,
  },
  statsRow: {
    flexDirection: 'row',
    gap: 10,
  },
  stat: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  statDot: {
    width: 5,
    height: 5,
    borderRadius: 2.5,
  },
  statText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 11,
    color: '#FFFFFF',
    letterSpacing: 0.3,
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 2 },
    textShadowRadius: 2,
  },
});

import React, { useEffect } from 'react';
import { View, Text, Pressable, StyleSheet, Platform } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withRepeat,
  withTiming,
  withSpring,
  withSequence,
  withDelay,
  Easing,
  interpolateColor,
  interpolate,
} from 'react-native-reanimated';
import Svg, { Circle, Defs, RadialGradient, Stop } from 'react-native-svg';
import { MaterialCommunityIcons, Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import Colors from '@/constants/colors';

const BUTTON_SIZE = 150;
const INNER_RING = BUTTON_SIZE + 20;
const MIDDLE_RING = BUTTON_SIZE + 44;
const OUTER_RING = BUTTON_SIZE + 70;
const ENERGY_RING = BUTTON_SIZE + 58;

interface PowerButtonProps {
  isConnected: boolean;
  isConnecting: boolean;
  isProtecting?: boolean;
  onPress: () => void;
}

function EnergyArc({ size, color, dashArray, rotation }: { size: number; color: string; dashArray: string; rotation: number }) {
  const r = (size - 4) / 2;
  return (
    <Svg width={size} height={size} style={[StyleSheet.absoluteFill, { transform: [{ rotate: `${rotation}deg` }] }]}>
      <Circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        stroke={color}
        strokeWidth={2}
        fill="none"
        strokeDasharray={dashArray}
        strokeLinecap="round"
        opacity={0.7}
      />
    </Svg>
  );
}

export function PowerButton({ isConnected, isConnecting, isProtecting = false, onPress }: PowerButtonProps) {
  const pulse = useSharedValue(1);
  const cyanPulse = useSharedValue(0.3);
  const rotation = useSharedValue(0);
  const rotation2 = useSharedValue(0);
  const scale = useSharedValue(1);
  const colorProgress = useSharedValue(0);
  const glowOpacity = useSharedValue(0);
  const shieldBadgeScale = useSharedValue(0);
  const energyRingOpacity = useSharedValue(0);

  useEffect(() => {
    if (isProtecting) {
      rotation.value = withRepeat(withTiming(360, { duration: 4000, easing: Easing.linear }), -1, false);
      rotation2.value = withTiming(0, { duration: 500 });
      pulse.value = withRepeat(withTiming(1.04, { duration: 1200, easing: Easing.inOut(Easing.ease) }), -1, true);
      colorProgress.value = withTiming(0.75, { duration: 600 });
      glowOpacity.value = withRepeat(withTiming(0.5, { duration: 1000 }), -1, true);
      cyanPulse.value = withTiming(0);
      energyRingOpacity.value = withTiming(0.5, { duration: 300 });
      shieldBadgeScale.value = withTiming(0, { duration: 200 });
    } else if (isConnecting) {
      cyanPulse.value = withTiming(0);
      rotation.value = withRepeat(withTiming(360, { duration: 2500, easing: Easing.linear }), -1, false);
      rotation2.value = withRepeat(withTiming(-360, { duration: 1800, easing: Easing.linear }), -1, false);
      pulse.value = withRepeat(withTiming(1.06, { duration: 600, easing: Easing.inOut(Easing.ease) }), -1, true);
      colorProgress.value = withRepeat(withTiming(0.5, { duration: 800 }), -1, true);
      glowOpacity.value = withRepeat(withTiming(0.6, { duration: 600 }), -1, true);
      energyRingOpacity.value = withTiming(1, { duration: 300 });
      shieldBadgeScale.value = withTiming(0, { duration: 200 });
    } else if (isConnected) {
      rotation.value = withTiming(rotation.value % 360);
      rotation2.value = withTiming(0);
      pulse.value = withRepeat(withTiming(1.02, { duration: 4000, easing: Easing.inOut(Easing.ease) }), -1, true);
      colorProgress.value = withTiming(1, { duration: 600 });
      glowOpacity.value = withTiming(0.5, { duration: 800 });
      cyanPulse.value = withTiming(0);
      energyRingOpacity.value = withTiming(0, { duration: 500 });
      shieldBadgeScale.value = withDelay(300, withSpring(1, { damping: 12, stiffness: 150 }));
    } else {
      rotation.value = withTiming(0, { duration: 500 });
      rotation2.value = withTiming(0, { duration: 500 });
      pulse.value = withTiming(1, { duration: 500 });
      colorProgress.value = withTiming(0, { duration: 500 });
      glowOpacity.value = withTiming(0, { duration: 500 });
      energyRingOpacity.value = withTiming(0, { duration: 300 });
      shieldBadgeScale.value = withTiming(0, { duration: 200 });
      cyanPulse.value = withRepeat(withTiming(0.8, { duration: 2500, easing: Easing.inOut(Easing.ease) }), -1, true);
    }
  }, [isConnected, isConnecting, isProtecting]);

  const outerGlowStyle = useAnimatedStyle(() => ({
    opacity: interpolate(colorProgress.value, [0, 0.5, 0.75, 1], [0, 0.3, 0.4, 0.5]),
    transform: [{ scale: pulse.value }],
    backgroundColor: interpolateColor(colorProgress.value, [0, 0.5, 0.75, 1], ['rgba(0,240,255,0)', 'rgba(195,0,255,0.08)', 'rgba(255,179,0,0.08)', 'rgba(0,230,118,0.06)']),
    shadowColor: interpolateColor(colorProgress.value, [0, 0.5, 0.75, 1], ['#00F0FF', '#C300FF', '#FFB300', '#00E676']),
    shadowOpacity: glowOpacity.value,
  }));

  const cyanPulseStyle = useAnimatedStyle(() => ({
    opacity: cyanPulse.value,
    transform: [{ scale: interpolate(cyanPulse.value, [0.3, 0.8], [1, 1.15]) }],
  }));

  const energyRing1Style = useAnimatedStyle(() => ({
    opacity: energyRingOpacity.value,
    transform: [{ rotate: `${rotation.value}deg` }],
  }));

  const energyRing2Style = useAnimatedStyle(() => ({
    opacity: interpolate(energyRingOpacity.value, [0, 1], [0, 0.6]),
    transform: [{ rotate: `${rotation2.value}deg` }],
  }));

  const middleRingStyle = useAnimatedStyle(() => ({
    transform: [{ scale: pulse.value }],
    borderColor: interpolateColor(colorProgress.value, [0, 0.5, 0.75, 1], ['rgba(255,255,255,0.05)', 'rgba(195,0,255,0.3)', 'rgba(255,179,0,0.3)', 'rgba(0,230,118,0.25)']),
  }));

  const buttonStyle = useAnimatedStyle(() => ({
    transform: [{ scale: scale.value }],
    backgroundColor: interpolateColor(colorProgress.value, [0, 0.5, 0.75, 1], ['rgba(255,255,255,0.04)', 'rgba(195,0,255,0.06)', 'rgba(255,179,0,0.06)', 'rgba(0,230,118,0.06)']),
    borderColor: interpolateColor(colorProgress.value, [0, 0.5, 0.75, 1], ['rgba(0,240,255,0.15)', 'rgba(195,0,255,0.5)', 'rgba(255,179,0,0.4)', 'rgba(0,230,118,0.4)']),
  }));

  const shieldBadgeStyle = useAnimatedStyle(() => ({
    transform: [{ scale: shieldBadgeScale.value }],
    opacity: shieldBadgeScale.value,
  }));

  const handlePress = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
    scale.value = withSequence(
      withSpring(0.9, { damping: 10, stiffness: 300 }),
      withSpring(1, { damping: 8, stiffness: 150 })
    );
    onPress();
  };

  const iconColor = isConnected ? '#00E676' : isProtecting ? '#FFB300' : isConnecting ? Colors.dark.accentPurple : Colors.dark.accent;

  return (
    <View style={styles.container}>
      <Animated.View style={[styles.outerGlow, outerGlowStyle]} />

      {!isConnected && !isConnecting && (
        <Animated.View style={[styles.cyanPulseRing, cyanPulseStyle]} />
      )}

      <Animated.View style={[styles.energyRingContainer, energyRing1Style]}>
        <EnergyArc size={ENERGY_RING} color={Colors.dark.accentPurple} dashArray="30 20 60 15" rotation={0} />
      </Animated.View>
      <Animated.View style={[styles.energyRingContainer, energyRing2Style]}>
        <EnergyArc size={ENERGY_RING - 10} color={Colors.dark.accent} dashArray="20 40 10 30" rotation={45} />
      </Animated.View>

      <Animated.View style={[styles.middleRing, middleRingStyle]} />

      <Pressable onPress={handlePress}>
        <Animated.View style={[styles.button, buttonStyle]}>
          <MaterialCommunityIcons name="power" size={52} color={iconColor} />
        </Animated.View>
      </Pressable>

      <Animated.View style={[styles.shieldBadge, shieldBadgeStyle]}>
        <View style={styles.shieldBadgeInner}>
          <Ionicons name="shield-checkmark" size={12} color="#00E676" />
          <Text style={styles.shieldBadgeText}>PROTECTED</Text>
        </View>
      </Animated.View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    width: OUTER_RING + 20,
    height: OUTER_RING + 20,
    alignItems: 'center',
    justifyContent: 'center',
  },
  outerGlow: {
    position: 'absolute',
    width: OUTER_RING,
    height: OUTER_RING,
    borderRadius: OUTER_RING / 2,
    shadowOffset: { width: 0, height: 0 },
    shadowRadius: 40,
    elevation: 10,
  },
  cyanPulseRing: {
    position: 'absolute',
    width: MIDDLE_RING + 8,
    height: MIDDLE_RING + 8,
    borderRadius: (MIDDLE_RING + 8) / 2,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.2)',
  },
  energyRingContainer: {
    position: 'absolute',
    width: ENERGY_RING,
    height: ENERGY_RING,
    alignItems: 'center',
    justifyContent: 'center',
  },
  middleRing: {
    position: 'absolute',
    width: INNER_RING,
    height: INNER_RING,
    borderRadius: INNER_RING / 2,
    borderWidth: 1,
  },
  button: {
    width: BUTTON_SIZE,
    height: BUTTON_SIZE,
    borderRadius: BUTTON_SIZE / 2,
    borderWidth: 1.5,
    alignItems: 'center',
    justifyContent: 'center',
  },
  shieldBadge: {
    position: 'absolute',
    bottom: 8,
  },
  shieldBadgeInner: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    backgroundColor: 'rgba(0, 230, 118, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(0, 230, 118, 0.25)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 12,
  },
  shieldBadgeText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 8,
    color: '#00E676',
    letterSpacing: 2,
  },
});

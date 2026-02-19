import React, { useEffect } from 'react';
import { View, Text, StyleSheet, Dimensions, Platform } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withRepeat,
  withDelay,
  withSequence,
  Easing,
  interpolate,
  runOnJS,
} from 'react-native-reanimated';
import Svg, { Circle, Line } from 'react-native-svg';
import { Ionicons } from '@expo/vector-icons';
import Colors from '@/constants/colors';

const { width: SCREEN_W, height: SCREEN_H } = Dimensions.get('window');
const CENTER_X = SCREEN_W / 2;
const CENTER_Y = SCREEN_H / 2;
const RADAR_RADIUS = Math.min(SCREEN_W, SCREEN_H) * 0.38;

interface RadarOverlayProps {
  visible: boolean;
  onComplete: () => void;
}

function RadarGrid() {
  const rings = [0.25, 0.5, 0.75, 1.0];
  const lines = [0, 45, 90, 135];
  return (
    <Svg width={SCREEN_W} height={SCREEN_H} style={StyleSheet.absoluteFill}>
      {rings.map((r, i) => (
        <Circle
          key={`ring-${i}`}
          cx={CENTER_X}
          cy={CENTER_Y}
          r={RADAR_RADIUS * r}
          stroke="rgba(0,240,255,0.08)"
          strokeWidth={1}
          fill="none"
        />
      ))}
      {lines.map((angle, i) => {
        const rad = (angle * Math.PI) / 180;
        const x2 = CENTER_X + Math.cos(rad) * RADAR_RADIUS;
        const y2 = CENTER_Y + Math.sin(rad) * RADAR_RADIUS;
        const x1 = CENTER_X - Math.cos(rad) * RADAR_RADIUS;
        const y1 = CENTER_Y - Math.sin(rad) * RADAR_RADIUS;
        return (
          <Line
            key={`line-${i}`}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke="rgba(0,240,255,0.05)"
            strokeWidth={1}
          />
        );
      })}
    </Svg>
  );
}

function SweepBeam() {
  const rotation = useSharedValue(0);

  useEffect(() => {
    rotation.value = withRepeat(
      withTiming(360, { duration: 1800, easing: Easing.linear }),
      -1,
      false
    );
  }, []);

  const sweepStyle = useAnimatedStyle(() => ({
    transform: [{ rotate: `${rotation.value}deg` }],
  }));

  return (
    <Animated.View style={[sweepStyles.container, sweepStyle]}>
      <View style={sweepStyles.beam} />
    </Animated.View>
  );
}

const sweepStyles = StyleSheet.create({
  container: {
    position: 'absolute',
    width: RADAR_RADIUS * 2,
    height: RADAR_RADIUS * 2,
    left: CENTER_X - RADAR_RADIUS,
    top: CENTER_Y - RADAR_RADIUS,
  },
  beam: {
    position: 'absolute',
    left: RADAR_RADIUS,
    width: RADAR_RADIUS,
    height: 3,
    borderRadius: 1.5,
    top: RADAR_RADIUS - 1.5,
    backgroundColor: 'rgba(0,240,255,0.3)',
  },
});

function PingBlip({ x, y, delay }: { x: number; y: number; delay: number }) {
  const scale = useSharedValue(0);
  const opacity = useSharedValue(0);

  useEffect(() => {
    scale.value = withDelay(
      delay,
      withRepeat(
        withSequence(
          withTiming(1, { duration: 600, easing: Easing.out(Easing.ease) }),
          withTiming(0, { duration: 400 })
        ),
        -1,
        false
      )
    );
    opacity.value = withDelay(
      delay,
      withRepeat(
        withSequence(
          withTiming(1, { duration: 300 }),
          withTiming(0, { duration: 700 })
        ),
        -1,
        false
      )
    );
  }, []);

  const blipStyle = useAnimatedStyle(() => ({
    transform: [{ scale: scale.value }],
    opacity: opacity.value,
  }));

  return (
    <Animated.View
      style={[
        {
          position: 'absolute',
          left: CENTER_X + x - 6,
          top: CENTER_Y + y - 6,
          width: 12,
          height: 12,
          borderRadius: 6,
          backgroundColor: Colors.dark.accent,
        },
        blipStyle,
      ]}
    />
  );
}

export function RadarOverlay({ visible, onComplete }: RadarOverlayProps) {
  const overlayOpacity = useSharedValue(0);
  const textOpacity = useSharedValue(0);
  const progressWidth = useSharedValue(0);
  const statusOpacity = useSharedValue(0);
  const checkScale = useSharedValue(0);

  useEffect(() => {
    if (visible) {
      overlayOpacity.value = withTiming(1, { duration: 400 });
      textOpacity.value = withDelay(300, withTiming(1, { duration: 400 }));
      progressWidth.value = withDelay(400, withTiming(1, { duration: 2400, easing: Easing.inOut(Easing.ease) }));
      statusOpacity.value = withDelay(500, withRepeat(withTiming(1, { duration: 800 }), 5, true));
      checkScale.value = withDelay(2800, withSequence(
        withTiming(1.3, { duration: 200 }),
        withTiming(1, { duration: 200 })
      ));
      setTimeout(() => {
        overlayOpacity.value = withTiming(0, { duration: 500 });
        setTimeout(() => onComplete(), 500);
      }, 3400);
    } else {
      overlayOpacity.value = withTiming(0, { duration: 300 });
      textOpacity.value = 0;
      progressWidth.value = 0;
      statusOpacity.value = 0;
      checkScale.value = 0;
    }
  }, [visible]);

  const overlayStyle = useAnimatedStyle(() => ({
    opacity: overlayOpacity.value,
  }));

  const textStyle = useAnimatedStyle(() => ({
    opacity: textOpacity.value,
  }));

  const progressStyle = useAnimatedStyle(() => ({
    width: `${interpolate(progressWidth.value, [0, 1], [0, 100])}%` as any,
  }));

  const statusStyle = useAnimatedStyle(() => ({
    opacity: statusOpacity.value,
  }));

  const checkStyle = useAnimatedStyle(() => ({
    transform: [{ scale: checkScale.value }],
    opacity: checkScale.value,
  }));

  const blips = [
    { x: -RADAR_RADIUS * 0.5, y: -RADAR_RADIUS * 0.3, delay: 200 },
    { x: RADAR_RADIUS * 0.4, y: -RADAR_RADIUS * 0.6, delay: 600 },
    { x: -RADAR_RADIUS * 0.7, y: RADAR_RADIUS * 0.2, delay: 400 },
    { x: RADAR_RADIUS * 0.3, y: RADAR_RADIUS * 0.5, delay: 800 },
    { x: RADAR_RADIUS * 0.6, y: -RADAR_RADIUS * 0.1, delay: 1000 },
    { x: -RADAR_RADIUS * 0.2, y: RADAR_RADIUS * 0.7, delay: 1200 },
  ];

  if (!visible) return null;

  return (
    <Animated.View 
      style={[styles.overlay, overlayStyle]}
      pointerEvents={visible ? 'auto' : 'none'}
    >
      <RadarGrid />
      <SweepBeam />
      {blips.map((b, i) => (
        <PingBlip key={i} x={b.x} y={b.y} delay={b.delay} />
      ))}

      <View style={styles.centerContent}>
        <Animated.View style={checkStyle}>
          <Ionicons name="shield-checkmark" size={40} color={Colors.dark.accent} />
        </Animated.View>
      </View>

      <View style={styles.bottomContent}>
        <Animated.View style={textStyle}>
          <Text style={styles.scanTitle}>SCANNING NETWORK</Text>
        </Animated.View>

        <Animated.View style={statusStyle}>
          <Text style={styles.scanStatus}>Establishing encrypted tunnel...</Text>
        </Animated.View>

        <View style={styles.progressTrack}>
          <Animated.View style={[styles.progressFill, progressStyle]} />
        </View>

        <View style={styles.checksRow}>
          <CheckItem label="DNS Secure" delay={800} />
          <CheckItem label="AES-256-GCM" delay={1500} />
          <CheckItem label="Handshake OK" delay={2200} />
          <CheckItem label="Tunnel Active" delay={2800} />
        </View>
      </View>
    </Animated.View>
  );
}

function CheckItem({ label, delay }: { label: string; delay: number }) {
  const opacity = useSharedValue(0);
  const translateX = useSharedValue(-10);

  useEffect(() => {
    opacity.value = withDelay(delay, withTiming(1, { duration: 400 }));
    translateX.value = withDelay(delay, withTiming(0, { duration: 400 }));
  }, []);

  const style = useAnimatedStyle(() => ({
    opacity: opacity.value,
    transform: [{ translateX: translateX.value }],
  }));

  return (
    <Animated.View style={[styles.checkItem, style]}>
      <Ionicons name="checkmark-circle" size={14} color={Colors.dark.success} />
      <Text style={styles.checkLabel}>{label}</Text>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(8,8,8,0.95)',
    zIndex: 100,
    justifyContent: 'center',
    alignItems: 'center',
  },
  centerContent: {
    position: 'absolute',
    alignItems: 'center',
    justifyContent: 'center',
  },
  bottomContent: {
    position: 'absolute',
    bottom: Platform.OS === 'web' ? 120 : 160,
    left: 0,
    right: 0,
    alignItems: 'center',
    gap: 12,
    paddingHorizontal: 40,
  },
  scanTitle: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 14,
    color: Colors.dark.accent,
    letterSpacing: 4,
  },
  scanStatus: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textSecondary,
  },
  progressTrack: {
    width: '80%',
    height: 3,
    backgroundColor: 'rgba(255,255,255,0.06)',
    borderRadius: 2,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: Colors.dark.accent,
    borderRadius: 2,
  },
  checksRow: {
    flexDirection: 'row',
    gap: 16,
    marginTop: 4,
  },
  checkItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  checkLabel: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.success,
    letterSpacing: 1,
  },
});

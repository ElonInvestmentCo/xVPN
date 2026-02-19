import React, { useEffect } from 'react';
import { View, StyleSheet, Dimensions, Platform } from 'react-native';
import Animated, { useSharedValue, useAnimatedStyle, withRepeat, withTiming, Easing } from 'react-native-reanimated';
import { LinearGradient } from 'expo-linear-gradient';
import Colors from '@/constants/colors';

const { width, height } = Dimensions.get('window');

export function NoiseBackground({ children }: { children: React.ReactNode }) {
  const orbY1 = useSharedValue(0);
  const orbY2 = useSharedValue(0);
  const orbX1 = useSharedValue(0);

  useEffect(() => {
    orbY1.value = withRepeat(withTiming(-30, { duration: 8000, easing: Easing.inOut(Easing.ease) }), -1, true);
    orbY2.value = withRepeat(withTiming(25, { duration: 6000, easing: Easing.inOut(Easing.ease) }), -1, true);
    orbX1.value = withRepeat(withTiming(20, { duration: 10000, easing: Easing.inOut(Easing.ease) }), -1, true);
  }, []);

  const orb1Style = useAnimatedStyle(() => ({
    transform: [{ translateY: orbY1.value }, { translateX: orbX1.value }],
  }));

  const orb2Style = useAnimatedStyle(() => ({
    transform: [{ translateY: orbY2.value }],
  }));

  return (
    <View style={styles.container}>
      <LinearGradient
        colors={['#0F0F0F', '#0D0D1A', '#0F0F0F']}
        start={{ x: 0, y: 0 }}
        end={{ x: 1, y: 1 }}
        style={StyleSheet.absoluteFill}
      />
      <Animated.View style={[styles.orb1, orb1Style]} />
      <Animated.View style={[styles.orb2, orb2Style]} />
      <View style={styles.noiseOverlay} />
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0F0F0F',
  },
  orb1: {
    position: 'absolute',
    top: '15%',
    left: '-20%',
    width: width * 0.8,
    height: width * 0.8,
    borderRadius: width * 0.4,
    backgroundColor: 'rgba(0, 240, 255, 0.04)',
  },
  orb2: {
    position: 'absolute',
    bottom: '20%',
    right: '-25%',
    width: width * 0.7,
    height: width * 0.7,
    borderRadius: width * 0.35,
    backgroundColor: 'rgba(195, 0, 255, 0.04)',
  },
  noiseOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(255,255,255,0.008)',
  },
});

import React, { useCallback } from 'react';
import { Pressable, ViewStyle, StyleProp } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withSpring,
} from 'react-native-reanimated';
import * as Haptics from 'expo-haptics';

interface HapticButtonProps {
  onPress: () => void;
  children: React.ReactNode;
  style?: StyleProp<ViewStyle>;
  scaleDown?: number;
  hapticStyle?: Haptics.ImpactFeedbackStyle;
  disabled?: boolean;
  testID?: string;
  hitSlop?: number;
}

export function HapticButton({
  onPress,
  children,
  style,
  scaleDown = 0.95,
  hapticStyle = Haptics.ImpactFeedbackStyle.Light,
  disabled = false,
  testID,
  hitSlop,
}: HapticButtonProps) {
  const scale = useSharedValue(1);

  const animStyle = useAnimatedStyle(() => ({
    transform: [{ scale: scale.value }],
  }));

  const handlePressIn = useCallback(() => {
    scale.value = withSpring(scaleDown, { damping: 15, stiffness: 300 });
  }, [scaleDown]);

  const handlePressOut = useCallback(() => {
    scale.value = withSpring(1, { damping: 10, stiffness: 200 });
  }, []);

  const handlePress = useCallback(() => {
    if (disabled) return;
    Haptics.impactAsync(hapticStyle);
    onPress();
  }, [disabled, hapticStyle, onPress]);

  return (
    <Pressable
      onPressIn={handlePressIn}
      onPressOut={handlePressOut}
      onPress={handlePress}
      disabled={disabled}
      testID={testID}
      hitSlop={hitSlop}
    >
      <Animated.View style={[style, animStyle]}>
        {children}
      </Animated.View>
    </Pressable>
  );
}

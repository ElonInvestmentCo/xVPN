import React, { useState, useRef, useEffect, useCallback } from 'react';
import { View, Text, StyleSheet, Pressable, Modal, Platform, ActivityIndicator, Linking, TouchableWithoutFeedback, Animated, PanResponder, Dimensions, ScrollView } from 'react-native';
import { BlurView } from 'expo-blur';
import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { useVpn } from '@/lib/vpn-context';
import { useAuth } from '@/lib/auth-context';
import Colors from '@/constants/colors';

interface Plan {
  id: string;
  stripeId: string;
  name: string;
  price: string;
  period: string;
  savings?: string;
  recommended?: boolean;
}

const PLANS: Plan[] = [
  { id: 'elite_stealth', stripeId: 'elite_stealth', name: 'Elite Stealth', price: '$19.99', period: '/month', recommended: true },
  { id: 'annual_pass', stripeId: 'annual_pass', name: 'Annual Pass', price: '$189', period: '/year', savings: 'Save 21%' },
];

interface SubscriptionModalProps {
  visible: boolean;
  onClose: () => void;
  serverName?: string;
}

export function SubscriptionModal({ visible, onClose, serverName }: SubscriptionModalProps) {
  const { setSubscription, setPremium } = useVpn();
  const { token, isAuthenticated } = useAuth();
  const [selectedPlan, setSelectedPlan] = useState<string>('elite_stealth');
  const [loading, setLoading] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blurIntensity, setBlurIntensity] = useState(100);

  // Single animated value for pan gesture
  const panY = useRef(new Animated.Value(0)).current;
  const panResponder = useRef<any>(null);

  // Initialize PanResponder with clean event handling
  useEffect(() => {
    if (!visible) {
      setBlurIntensity(100);
      panY.setValue(0);
      setIsProcessing(false);
      setLoading(false);
      setError(null);
      return;
    }
    
    // Re-check auth state whenever modal is opened
    // This ensures we always have current auth status

    panResponder.current = PanResponder.create({
      onStartShouldSetPanResponder: () => !isProcessing,
      onMoveShouldSetPanResponder: (evt, gestureState) => !isProcessing && Math.abs(gestureState.dy) > 5,
      onPanResponderMove: (evt, gestureState) => {
        if (isProcessing) return;
        const position = gestureState.dy;
        // Clamp blur intensity between 0 and 100
        const intensity = Math.max(0, Math.min(100, 100 - (position / 2)));
        setBlurIntensity(intensity);
        panY.setValue(position);
      },
      onPanResponderRelease: (evt, gestureState) => {
        if (isProcessing) return;
        const dismissThreshold = 150;  // Increased threshold for more deliberate dismiss
        // Dismiss if user dragged down more than threshold AND velocity is downward
        if (gestureState.dy > dismissThreshold && gestureState.vy > 0.1) {
          if (Platform.OS !== 'web') {
            Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
          }
          dismissModal();
        } else {
          // Snap back smoothly if not dismissing
          setBlurIntensity(100);
          Animated.spring(panY, {
            toValue: 0,
            useNativeDriver: false,
            tension: 70,          // Increased tension for snappier response
            friction: 12,         // Increased friction to avoid overshoot
            speed: 8,             // Faster snap-back
          }).start(() => {
            // Reset panY to 0 in completion callback to ensure clean state
            panY.setValue(0);
          });
        }
      },
    });

    return () => {
      panY.removeAllListeners();
    };
  }, [visible, panY, isProcessing]);

  // Dismiss modal with animation
  const dismissModal = useCallback(() => {
    if (isProcessing) return;
    Animated.timing(panY, {
      toValue: Dimensions.get('screen').height,
      duration: 300,
      useNativeDriver: false,
    }).start(() => {
      setBlurIntensity(100);
      panY.setValue(0);
      setIsProcessing(false);
      onClose();
    });
  }, [panY, onClose, isProcessing]);

  const handleSubscribe = useCallback(async () => {
    if (loading || isProcessing) return;
    
    // If not logged in, show error message
    if (!isAuthenticated || !token) {
      setError('Please log in first to subscribe');
      // Optionally dismiss modal so user can log in
      setTimeout(() => {
        dismissModal();
      }, 1500);
      return;
    }
    
    // User is logged in - skip login prompt and proceed directly to payment
    if (Platform.OS !== 'web') {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
    }
    
    setLoading(true);
    setIsProcessing(true);
    setError(null);

    try {
      const domain = process.env.EXPO_PUBLIC_DOMAIN || (typeof window !== 'undefined' ? window.location.origin : '');
      const baseUrl = domain.startsWith('http') ? domain : `https://${domain}`;

      const response = await fetch(`${baseUrl}/api/create-checkout-session`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create checkout session');
      }

      if (data.url) {
        if (Platform.OS === 'web') {
          window.open(data.url, '_blank');
        } else {
          await Linking.openURL(data.url);
        }
        // Update premium status after successful checkout
        setPremium(true);
        dismissModal();
      } else if (data.sessionId) {
        // Handle session ID only response
        throw new Error('Session created but no checkout URL provided');
      }
    } catch (err: any) {
      console.error('Subscription error:', err);
      setError(err.message || 'Something went wrong. Please try again.');
    } finally {
      setLoading(false);
      setIsProcessing(false);
    }
  }, [selectedPlan, dismissModal, loading, isProcessing, token, isAuthenticated, setPremium]);

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={isProcessing ? undefined : dismissModal}>
      <BlurView intensity={blurIntensity} style={styles.blurContainer}>
        <TouchableWithoutFeedback onPress={isProcessing ? undefined : dismissModal}>
          <View style={styles.overlay}>
            <Animated.View
              style={[
                styles.container,
                {
                  transform: [{ translateY: panY }],
                },
              ]}
              {...(panResponder.current && !isProcessing ? panResponder.current.panHandlers : {})}
            >
          <View style={styles.handle} />

          <ScrollView 
            scrollEnabled={true}
            style={styles.scrollContent}
            showsVerticalScrollIndicator={false}
            bounces={false}
          >
          <View style={styles.header}>
            <View style={styles.premiumIcon}>
              <Ionicons name="diamond" size={28} color={Colors.dark.accentPurple} />
            </View>
            <Text style={styles.title}>Premium Access</Text>
            <Text style={styles.subtitle}>
              {serverName ? `Unlock ${serverName} and all premium servers` : 'Unlock all premium servers worldwide'}
            </Text>
          </View>

          <View style={styles.features}>
            {['50+ Premium Server Locations', 'Residential IP Masking', 'Multi-Hop Double VPN', 'Priority Bandwidth'].map((feature, i) => (
              <View key={i} style={styles.featureRow}>
                <Ionicons name="checkmark-circle" size={18} color={Colors.dark.success} />
                <Text style={styles.featureText}>{feature}</Text>
              </View>
            ))}
          </View>

          <View style={styles.plans}>
            {PLANS.map((plan) => (
              <Pressable
                key={plan.id}
                onPress={() => {
                  if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
                  setSelectedPlan(plan.id);
                }}
              >
                <View style={[
                  styles.planCard,
                  selectedPlan === plan.id && styles.planCardSelected,
                  plan.recommended && selectedPlan === plan.id && styles.planCardRecommended,
                ]}>
                  {plan.recommended && (
                    <View style={styles.recommendedBadge}>
                      <Text style={styles.recommendedText}>RECOMMENDED</Text>
                    </View>
                  )}
                  <View style={styles.planRow}>
                    <View style={[styles.radio, selectedPlan === plan.id && styles.radioSelected]}>
                      {selectedPlan === plan.id && <View style={styles.radioDot} />}
                    </View>
                    <View style={styles.planInfo}>
                      <Text style={[styles.planName, selectedPlan === plan.id && styles.planNameSelected]}>{plan.name}</Text>
                      <View style={styles.priceRow}>
                        <Text style={[styles.planPrice, selectedPlan === plan.id && styles.planPriceSelected]}>{plan.price}</Text>
                        <Text style={styles.planPeriod}>{plan.period}</Text>
                      </View>
                    </View>
                    {plan.savings && (
                      <View style={styles.savingsBadge}>
                        <Text style={styles.savingsText}>{plan.savings}</Text>
                      </View>
                    )}
                  </View>
                </View>
              </Pressable>
            ))}
          </View>

          {error && (
            <View style={styles.errorContainer}>
              <Ionicons name="alert-circle" size={16} color="#FF3131" />
              <Text style={styles.errorText}>{error}</Text>
            </View>
          )}

          <Pressable
            style={({ pressed }) => [
              styles.subscribeButton,
              (loading || isProcessing) && styles.subscribeButtonLoading,
              pressed && !loading && !isProcessing && { opacity: 0.8 }
            ]}
            onPress={handleSubscribe}
            disabled={loading || isProcessing}
          >
            {loading || isProcessing ? (
              <ActivityIndicator color="#000" />
            ) : (
              <>
                <Ionicons name="lock-closed" size={18} color="#000" />
                <Text style={styles.subscribeButtonText}>Subscribe & Unlock</Text>
              </>
            )}
          </Pressable>

          <Pressable onPress={() => {
            if (Platform.OS !== 'web') Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
            onClose();
          }} style={styles.cancelButton}>
            <Text style={styles.cancelText}>Maybe Later</Text>
          </Pressable>

          <Text style={styles.disclaimer}>Cancel anytime. Secure payment via Stripe.</Text>
          </ScrollView>
            </Animated.View>
            </View>
          </TouchableWithoutFeedback>
        </BlurView>
      </Modal>
    );
  }

const styles = StyleSheet.create({
  blurContainer: {
    flex: 1,
    justifyContent: 'flex-end',
  },
  overlay: {
    flex: 1,
    backgroundColor: 'transparent',
    justifyContent: 'flex-end',
  },
  container: {
    backgroundColor: '#1A1A2E',
    borderTopLeftRadius: 28,
    borderTopRightRadius: 28,
    paddingHorizontal: 24,
    paddingBottom: Platform.OS === 'ios' ? 40 : 24,
    paddingTop: 12,
    maxHeight: '90%',
  },
  scrollContent: {
    flexGrow: 1,
  },
  handle: {
    width: 36,
    height: 4,
    backgroundColor: 'rgba(255,255,255,0.2)',
    borderRadius: 2,
    alignSelf: 'center',
    marginBottom: 20,
  },
  header: {
    alignItems: 'center',
    marginBottom: 20,
  },
  premiumIcon: {
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: 'rgba(195,0,255,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 12,
  },
  title: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 20,
    color: Colors.dark.text,
    letterSpacing: 2,
  },
  subtitle: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 13,
    color: Colors.dark.textSecondary,
    textAlign: 'center',
    marginTop: 8,
    lineHeight: 18,
  },
  features: {
    gap: 10,
    marginBottom: 20,
  },
  featureRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  featureText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 14,
    color: Colors.dark.text,
  },
  plans: {
    gap: 10,
    marginBottom: 20,
  },
  planCard: {
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.08)',
    borderRadius: 16,
    padding: 16,
    backgroundColor: 'rgba(255,255,255,0.03)',
  },
  planCardSelected: {
    borderColor: Colors.dark.accent,
    backgroundColor: 'rgba(0,240,255,0.05)',
  },
  planCardRecommended: {
    borderColor: Colors.dark.accentPurple,
    backgroundColor: 'rgba(195,0,255,0.05)',
  },
  recommendedBadge: {
    position: 'absolute',
    top: -9,
    right: 12,
    backgroundColor: Colors.dark.accentPurple,
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 6,
  },
  recommendedText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 7,
    color: '#FFF',
    letterSpacing: 1,
  },
  planRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  radio: {
    width: 22,
    height: 22,
    borderRadius: 11,
    borderWidth: 2,
    borderColor: 'rgba(255,255,255,0.2)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  radioSelected: {
    borderColor: Colors.dark.accent,
  },
  radioDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: Colors.dark.accent,
  },
  planInfo: {
    flex: 1,
  },
  planName: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 16,
    color: Colors.dark.textSecondary,
  },
  planNameSelected: {
    color: Colors.dark.text,
  },
  priceRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    gap: 4,
    marginTop: 2,
  },
  planPrice: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 18,
    color: Colors.dark.textSecondary,
  },
  planPriceSelected: {
    color: Colors.dark.accent,
  },
  planPeriod: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: Colors.dark.textMuted,
  },
  savingsBadge: {
    backgroundColor: 'rgba(0,230,118,0.15)',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 8,
  },
  savingsText: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 10,
    color: Colors.dark.success,
    letterSpacing: 0.5,
  },
  errorContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    backgroundColor: 'rgba(255,49,49,0.1)',
    borderRadius: 10,
    padding: 12,
    marginBottom: 12,
  },
  errorText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 12,
    color: '#FF3131',
    flex: 1,
  },
  subscribeButton: {
    backgroundColor: Colors.dark.accent,
    borderRadius: 16,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  subscribeButtonLoading: {
    opacity: 0.7,
  },
  subscribeButtonText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 14,
    color: '#000',
    letterSpacing: 1,
  },
  cancelButton: {
    alignItems: 'center',
    paddingVertical: 14,
  },
  cancelText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 14,
    color: Colors.dark.textMuted,
  },
  disclaimer: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 10,
    color: Colors.dark.textMuted,
    textAlign: 'center',
    opacity: 0.6,
  },
});

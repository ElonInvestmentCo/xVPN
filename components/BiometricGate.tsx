import React, { useEffect, useState, useCallback, useRef } from 'react';
import { View, Text, StyleSheet, Platform, AppState, Pressable, TextInput, KeyboardAvoidingView } from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import { Ionicons, MaterialCommunityIcons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { useVpn } from '@/lib/vpn-context';
import Colors from '@/constants/colors';

interface BiometricGateProps {
  children: React.ReactNode;
}

type BiometricType = 'faceID' | 'fingerprint' | 'none';
type AuthMethod = 'biometric' | 'pin' | 'none';

export function BiometricGate({ children }: BiometricGateProps) {
  const { biometricLock } = useVpn();
  const [locked, setLocked] = useState(false);
  const [authenticating, setAuthenticating] = useState(false);
  const [biometricType, setBiometricType] = useState<BiometricType>('none');
  const [authMethod, setAuthMethod] = useState<AuthMethod>('none');
  const [pinCode, setPinCode] = useState('');
  const [showPinInput, setShowPinInput] = useState(false);
  const appState = useRef(AppState.currentState);
  const hasCheckedInitial = useRef(false);

  // Detect available biometric types on mount
  useEffect(() => {
    const detectBiometrics = async () => {
      try {
        if (Platform.OS === 'web' || Platform.OS === 'windows' || Platform.OS === 'macos') {
          // Desktop: use PIN fallback
          setAuthMethod('pin');
          setBiometricType('none');
          return;
        }

        const compatible = await LocalAuthentication.hasHardwareAsync();
        if (!compatible) {
          setAuthMethod('pin');
          setBiometricType('none');
          return;
        }

        const enrolled = await LocalAuthentication.isEnrolledAsync();
        if (!enrolled) {
          setAuthMethod('pin');
          setBiometricType('none');
          return;
        }

        // Detect specific biometric type
        const types = await LocalAuthentication.supportedAuthenticationTypesAsync();
        let detectedType: BiometricType = 'none';

        if (types.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION)) {
          detectedType = 'faceID';
        } else if (types.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)) {
          detectedType = 'fingerprint';
        }

        if (detectedType !== 'none') {
          setBiometricType(detectedType);
          setAuthMethod('biometric');
        } else {
          // Fallback to PIN if biometric not detected
          setAuthMethod('pin');
        }
      } catch (error) {
        console.error('Error detecting biometrics:', error);
        setAuthMethod('pin');
        setBiometricType('none');
      }
    };

    detectBiometrics();
  }, []);

  const authenticateWithBiometric = useCallback(async () => {
    if (authenticating) return;
    setAuthenticating(true);

    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: biometricType === 'faceID' ? 'Face ID required to unlock xVPN' : 'Fingerprint required to unlock xVPN',
        fallbackLabel: 'Use passcode',
        disableDeviceFallback: false,
      });

      if (result.success) {
        if (Platform.OS !== 'web') {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        }
        setLocked(false);
      } else {
        // User cancelled - allow PIN fallback
        if (authMethod === 'pin') {
          setShowPinInput(true);
        }
      }
    } catch (error) {
      console.error('Biometric auth error:', error);
      // Fallback to PIN on error
      if (authMethod === 'pin') {
        setShowPinInput(true);
      } else {
        setLocked(false); // Development fallback
      }
    } finally {
      setAuthenticating(false);
    }
  }, [authenticating, authMethod, biometricType]);

  const authenticateWithPin = useCallback((pin: string) => {
    // Simple PIN validation (you can replace with more secure validation)
    const validPin = '1234'; // Default PIN for development
    
    if (pin === validPin) {
      if (Platform.OS !== 'web') {
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      }
      setLocked(false);
      setPinCode('');
      setShowPinInput(false);
    } else {
      if (Platform.OS !== 'web') {
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      }
      setPinCode('');
    }
  }, []);

  const authenticate = useCallback(async () => {
    if (!authMethod || authMethod === 'none') {
      setLocked(false);
      return;
    }

    if (authMethod === 'biometric') {
      await authenticateWithBiometric();
    } else if (authMethod === 'pin') {
      setShowPinInput(true);
    }
  }, [authMethod, authenticateWithBiometric]);

  useEffect(() => {
    if (biometricLock && !hasCheckedInitial.current) {
      hasCheckedInitial.current = true;
      // For development: skip auto-lock on startup
      setLocked(false);
      // Uncomment below to enable on-startup biometric lock in production
      // setLocked(true);
      // authenticate();
    }
  }, [biometricLock, authenticate]);

  if (!locked || !biometricLock) {
    return <>{children}</>;
  }

  const getBiometricIcon = () => {
    if (biometricType === 'faceID') return 'face-recognition';
    if (biometricType === 'fingerprint') return 'fingerprint';
    return 'lock';
  };

  return (
    <View style={styles.container}>
      {children}
      <View style={styles.overlay}>
        <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={styles.content}>
          <View style={styles.iconContainer}>
            {biometricType === 'faceID' || biometricType === 'fingerprint' ? (
              <MaterialCommunityIcons name={getBiometricIcon()} size={56} color={Colors.dark.accent} />
            ) : (
              <Ionicons name="lock-closed" size={48} color={Colors.dark.accent} />
            )}
          </View>
          <Text style={styles.title}>xVPN Locked</Text>

          {showPinInput ? (
            <>
              <Text style={styles.subtitle}>Enter PIN</Text>
              <TextInput
                style={styles.pinInput}
                placeholder="••••"
                placeholderTextColor={Colors.dark.textMuted}
                secureTextEntry
                keyboardType="number-pad"
                maxLength={4}
                value={pinCode}
                onChangeText={(text) => {
                  setPinCode(text);
                  if (text.length === 4) {
                    authenticateWithPin(text);
                  }
                }}
                editable={!authenticating}
              />
              <Pressable
                style={styles.cancelPinButton}
                onPress={() => {
                  setShowPinInput(false);
                  setPinCode('');
                }}
              >
                <Text style={styles.cancelPinText}>Back</Text>
              </Pressable>
            </>
          ) : (
            <>
              <Text style={styles.subtitle}>
                {biometricType === 'faceID'
                  ? 'Authenticate with Face ID'
                  : biometricType === 'fingerprint'
                  ? 'Authenticate with Fingerprint'
                  : 'Authenticate to continue'}
              </Text>
              <Pressable
                style={styles.unlockButton}
                onPress={authenticate}
                disabled={authenticating}
              >
                {authenticating ? (
                  <Text style={styles.unlockText}>Authenticating...</Text>
                ) : (
                  <>
                    {biometricType === 'faceID' || biometricType === 'fingerprint' ? (
                      <MaterialCommunityIcons
                        name={getBiometricIcon()}
                        size={20}
                        color="#000"
                        style={styles.unlockIcon}
                      />
                    ) : (
                      <Ionicons
                        name="lock-closed"
                        size={18}
                        color="#000"
                        style={styles.unlockIcon}
                      />
                    )}
                    <Text style={styles.unlockText}>
                      {biometricType === 'faceID'
                        ? 'Use Face ID'
                        : biometricType === 'fingerprint'
                        ? 'Use Fingerprint'
                        : 'Authenticate'}
                    </Text>
                  </>
                )}
              </Pressable>
              {authMethod === 'pin' && biometricType === 'none' && (
                <Pressable
                  style={styles.pinFallbackButton}
                  onPress={() => setShowPinInput(true)}
                >
                  <Text style={styles.pinFallbackText}>Enter PIN</Text>
                </Pressable>
              )}
            </>
          )}
        </KeyboardAvoidingView>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(15, 15, 15, 0.97)',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 9999,
  },
  content: {
    alignItems: 'center',
    gap: 16,
    paddingHorizontal: 24,
  },
  iconContainer: {
    width: 96,
    height: 96,
    borderRadius: 48,
    backgroundColor: 'rgba(0, 240, 255, 0.08)',
    borderWidth: 2,
    borderColor: 'rgba(0, 240, 255, 0.2)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 8,
  },
  title: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 22,
    color: Colors.dark.text,
    letterSpacing: 3,
  },
  subtitle: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 14,
    color: Colors.dark.textMuted,
    marginBottom: 8,
  },
  unlockButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    backgroundColor: Colors.dark.accent,
    paddingHorizontal: 28,
    paddingVertical: 14,
    borderRadius: 16,
    marginTop: 12,
    minWidth: 200,
  },
  unlockIcon: {
    marginRight: 4,
  },
  unlockText: {
    fontFamily: 'Orbitron_700Bold',
    fontSize: 14,
    color: '#000',
    letterSpacing: 1,
  },
  pinInput: {
    fontFamily: 'SpaceGrotesk_600SemiBold',
    fontSize: 24,
    color: Colors.dark.text,
    borderBottomWidth: 2,
    borderBottomColor: Colors.dark.accent,
    paddingHorizontal: 12,
    paddingVertical: 16,
    textAlign: 'center',
    width: 120,
    marginTop: 12,
    marginBottom: 20,
  },
  pinFallbackButton: {
    marginTop: 16,
    paddingVertical: 12,
    paddingHorizontal: 16,
  },
  pinFallbackText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 13,
    color: Colors.dark.accent,
    textDecorationLine: 'underline',
  },
  cancelPinButton: {
    paddingVertical: 12,
    paddingHorizontal: 16,
  },
  cancelPinText: {
    fontFamily: 'SpaceGrotesk_400Regular',
    fontSize: 13,
    color: Colors.dark.textMuted,
  },
});

import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  Pressable,
  ActivityIndicator,
  Alert,
  ScrollView,
  RefreshControl,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import Colors from '@/constants/colors';
import { useAuth } from '@/lib/auth-context';

export function EmailVerificationScreen() {
  const { user, logout, token } = useAuth();
  const [verificationCode, setVerificationCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [timeLeft, setTimeLeft] = useState(0);

  // Timer for resend button
  useEffect(() => {
    if (timeLeft <= 0) return;
    const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
    return () => clearTimeout(timer);
  }, [timeLeft]);

  const handleVerifyEmail = async () => {
    if (!verificationCode.trim()) {
      Alert.alert('Error', 'Please enter the verification code');
      return;
    }

    setIsLoading(true);
    try {
      const apiDomain = process.env.EXPO_PUBLIC_DOMAIN || 'http://localhost:8000';
      const baseUrl = `http://${apiDomain}`;

      const response = await fetch(`${baseUrl}/api/verify-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          token: verificationCode,
          userId: user?.id,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        Alert.alert('Verification Failed', data.error || 'Invalid verification code');
        return;
      }

      Alert.alert('Success', 'Your email has been verified!', [
        {
          text: 'OK',
          onPress: () => {
            // The app will automatically redirect since isVerified is now true
          },
        },
      ]);
    } catch (error: any) {
      Alert.alert('Error', error.message || 'Failed to verify email');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendEmail = async () => {
    setIsResending(true);
    try {
      const apiDomain = process.env.EXPO_PUBLIC_DOMAIN || 'http://localhost:8000';
      const baseUrl = `http://${apiDomain}`;

      const response = await fetch(`${baseUrl}/api/resend-verification`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          email: user?.email,
        }),
      });

      if (response.ok) {
        Alert.alert('Success', 'Verification email sent! Check your inbox.');
        setTimeLeft(60); // 60 second cooldown
      } else {
        const data = await response.json();
        Alert.alert('Error', data.error || 'Failed to resend email');
      }
    } catch (error: any) {
      Alert.alert('Error', error.message || 'Network error');
    } finally {
      setIsResending(false);
    }
  };

  const onRefresh = () => {
    setRefreshing(true);
    // Simulate refresh delay
    setTimeout(() => setRefreshing(false), 1000);
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      >
        {/* Header */}
        <View style={styles.header}>
          <View style={styles.iconContainer}>
            <Ionicons name="mail-outline" size={60} color={Colors.dark.accent} />
          </View>
          <Text style={styles.title}>Verify Your Email</Text>
          <Text style={styles.subtitle}>
            We&apos;ve sent a verification code to{'\n'}
            <Text style={styles.email}>{user?.email}</Text>
          </Text>
        </View>

        {/* Input Section */}
        <View style={styles.inputSection}>
          <Text style={styles.label}>Verification Code</Text>
          <TextInput
            style={[styles.input, { borderColor: verificationCode ? Colors.dark.accentPurple : '#333' }]}
            placeholder="Enter 6-digit code from email"
            placeholderTextColor="#666"
            value={verificationCode}
            onChangeText={setVerificationCode}
            maxLength={6}
            keyboardType="number-pad"
            editable={!isLoading}
          />
          <Text style={styles.hint}>Check your spam folder if you don&apos;t see the email</Text>
        </View>

        {/* Verify Button */}
        <Pressable
          style={[
            styles.verifyButton,
            isLoading && styles.buttonDisabled,
          ]}
          onPress={handleVerifyEmail}
          disabled={isLoading}
        >
          {isLoading ? (
            <ActivityIndicator color="#000" size="small" />
          ) : (
            <Text style={styles.verifyButtonText}>Verify Email</Text>
          )}
        </Pressable>

        {/* Resend Section */}
        <View style={styles.resendSection}>
          <Text style={styles.resendLabel}>Didn&apos;t receive the code?</Text>
          <Pressable
            onPress={handleResendEmail}
            disabled={isResending || timeLeft > 0}
            style={[
              styles.resendButton,
              (isResending || timeLeft > 0) && styles.resendButtonDisabled,
            ]}
          >
            {isResending ? (
              <ActivityIndicator color={Colors.dark.accent} size="small" />
            ) : (
              <Text style={[
                styles.resendButtonText,
                (timeLeft > 0) && styles.resendButtonTextDisabled,
              ]}>
                {timeLeft > 0 ? `Resend in ${timeLeft}s` : 'Resend Code'}
              </Text>
            )}
          </Pressable>
        </View>

        {/* Logout */}
        <Pressable
          style={styles.logoutButton}
          onPress={() => {
            Alert.alert('Sign Out', 'Are you sure?', [
              { text: 'Cancel', onPress: () => {} },
              {
                text: 'Sign Out',
                onPress: () => logout(),
                style: 'destructive',
              },
            ]);
          }}
        >
          <Ionicons name="log-out-outline" size={18} color={Colors.dark.accentCoral} />
          <Text style={styles.logoutButtonText}>Sign Out</Text>
        </Pressable>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0F0F1F',
  },
  scrollContent: {
    flexGrow: 1,
    padding: 20,
    justifyContent: 'center',
  },
  header: {
    alignItems: 'center',
    marginBottom: 40,
  },
  iconContainer: {
    width: 100,
    height: 100,
    borderRadius: 50,
    backgroundColor: 'rgba(0, 240, 255, 0.1)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 20,
  },
  title: {
    fontSize: 28,
    fontWeight: '700',
    color: '#FFFFFF',
    marginBottom: 10,
    fontFamily: 'Orbitron_700Bold',
  },
  subtitle: {
    fontSize: 16,
    color: '#AAAAAA',
    textAlign: 'center',
    lineHeight: 24,
  },
  email: {
    color: Colors.dark.accent,
    fontWeight: '600',
  },
  inputSection: {
    marginBottom: 30,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#FFFFFF',
    marginBottom: 10,
  },
  input: {
    borderWidth: 1,
    borderColor: '#333',
    borderRadius: 10,
    padding: 14,
    fontSize: 16,
    color: '#FFFFFF',
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    marginBottom: 8,
    textAlign: 'center',
    letterSpacing: 4,
  },
  hint: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
  },
  verifyButton: {
    backgroundColor: Colors.dark.accent,
    borderRadius: 10,
    padding: 16,
    alignItems: 'center',
    marginBottom: 20,
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  verifyButtonText: {
    fontSize: 16,
    fontWeight: '700',
    color: '#000',
  },
  resendSection: {
    alignItems: 'center',
    marginBottom: 30,
  },
  resendLabel: {
    fontSize: 14,
    color: '#AAAAAA',
    marginBottom: 10,
  },
  resendButton: {
    paddingHorizontal: 20,
    paddingVertical: 10,
  },
  resendButtonDisabled: {
    opacity: 0.5,
  },
  resendButtonText: {
    fontSize: 14,
    fontWeight: '600',
    color: Colors.dark.accent,
  },
  resendButtonTextDisabled: {
    color: '#666',
  },
  logoutButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 12,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: Colors.dark.accentCoral,
    marginTop: 20,
  },
  logoutButtonText: {
    fontSize: 14,
    fontWeight: '600',
    color: Colors.dark.accentCoral,
    marginLeft: 8,
  },
});

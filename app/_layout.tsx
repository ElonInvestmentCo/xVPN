import { QueryClientProvider } from "@tanstack/react-query";
import { Stack } from "expo-router";
import * as SplashScreen from "expo-splash-screen";
import React, { useEffect, useState } from "react";
import { Platform } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { KeyboardProvider } from "react-native-keyboard-controller";
import { StatusBar } from "expo-status-bar";
import * as Font from "expo-font";
import { SpaceGrotesk_400Regular, SpaceGrotesk_600SemiBold } from "@expo-google-fonts/space-grotesk";
import { Orbitron_700Bold } from "@expo-google-fonts/orbitron";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { queryClient } from "@/lib/query-client";
import { VpnProvider } from "@/lib/vpn-context";
import { FingerprintShieldProvider } from "@/lib/fingerprint-context";
import { BiometricGate } from "@/components/BiometricGate";
import { AuthProvider, useAuth } from "@/lib/auth-context";
import { AuthScreen } from "@/components/AuthScreen";
import { EmailVerificationScreen } from "@/components/EmailVerificationScreen";
import { View, ActivityIndicator } from "react-native";

SplashScreen.preventAutoHideAsync();

function RootLayoutNav() {
  return (
    <Stack screenOptions={{ headerBackTitle: "Back", contentStyle: { backgroundColor: '#0F0F0F' } }}>
      <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
    </Stack>
  );
}

function AuthGate() {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) {
    return (
      <View style={{ flex: 1, backgroundColor: '#0A0A1A', justifyContent: 'center', alignItems: 'center' }}>
        <ActivityIndicator size="large" color="#00F0FF" />
      </View>
    );
  }

  if (!isAuthenticated) {
    return <AuthScreen />;
  }

  // Show email verification screen if user is not verified
  if (isAuthenticated && !user?.isVerified) {
    return <EmailVerificationScreen />;
  }

  return (
    <VpnProvider>
      <FingerprintShieldProvider>
        <BiometricGate>
          <StatusBar style="light" />
          <RootLayoutNav />
        </BiometricGate>
      </FingerprintShieldProvider>
    </VpnProvider>
  );
}

export default function RootLayout() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    async function loadFonts() {
      try {
        await Font.loadAsync({
          SpaceGrotesk_400Regular,
          SpaceGrotesk_600SemiBold,
          Orbitron_700Bold,
        });
      } catch (e) {
        console.warn("Font loading failed, using fallback fonts:", e);
      } finally {
        setReady(true);
        SplashScreen.hideAsync();
      }
    }
    loadFonts();
  }, []);

  if (!ready) return null;

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <GestureHandlerRootView style={{ flex: 1, backgroundColor: '#0F0F0F' }}>
          <KeyboardProvider>
            <AuthProvider>
              <StatusBar style="light" />
              <AuthGate />
            </AuthProvider>
          </KeyboardProvider>
        </GestureHandlerRootView>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: { id: string; email: string; username: string; displayName?: string; isPro?: boolean; isVerified?: boolean } | null;
  token: string | null;
  login: (email: string, password: string) => Promise<{ success: boolean; message?: string }>;
  signup: (email: string, password: string, username: string) => Promise<{ success: boolean; message?: string }>;
  logout: () => Promise<void>;
  setAuthToken: (token: string, user: any) => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  isLoading: true,
  user: null,
  token: null,
  login: async () => ({ success: false }),
  signup: async () => ({ success: false }),
  logout: async () => {},
  setAuthToken: async () => {},
});

export const useAuth = () => useContext(AuthContext);

const SESSION_KEY = 'xvpn_session';
const TOKEN_KEY = 'xvpn_token';
const USERS_KEY = 'xvpn_users';

async function secureGet(key: string): Promise<string | null> {
  if (Platform.OS === 'web') {
    return AsyncStorage.getItem(key);
  }
  return SecureStore.getItemAsync(key);
}

async function secureSet(key: string, value: string): Promise<void> {
  if (Platform.OS === 'web') {
    return AsyncStorage.setItem(key, value);
  }
  return SecureStore.setItemAsync(key, value);
}

async function secureDelete(key: string): Promise<void> {
  if (Platform.OS === 'web') {
    return AsyncStorage.removeItem(key);
  }
  return SecureStore.deleteItemAsync(key);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<{ id: string; email: string; username: string; displayName?: string; isPro?: boolean; isVerified?: boolean } | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const sessionToken = await secureGet(TOKEN_KEY);
        const sessionData = await secureGet(SESSION_KEY);
        
        if (sessionToken && sessionData) {
          const parsed = JSON.parse(sessionData);
          setUser(parsed);
          setToken(sessionToken);
          setIsAuthenticated(true);
        }
      } catch (error) {
        console.error('Error loading session:', error);
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  const getUsers = useCallback(async (): Promise<Record<string, { password: string; displayName: string }>> => {
    try {
      const data = await secureGet(USERS_KEY);
      return data ? JSON.parse(data) : {};
    } catch {
      return {};
    }
  }, []);

  const setAuthToken = useCallback(async (authToken: string, userData: any) => {
    await secureSet(TOKEN_KEY, authToken);
    await secureSet(SESSION_KEY, JSON.stringify(userData));
    setToken(authToken);
    setUser(userData);
    setIsAuthenticated(true);
  }, []);

  const login = useCallback(async (email: string, password: string): Promise<{ success: boolean; message?: string }> => {
    try {
      const apiDomain = process.env.EXPO_PUBLIC_DOMAIN || 'http://localhost:8000';
      const baseUrl = `http://${apiDomain}`;
      
      const response = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        return { success: false, message: data.error || 'Login failed' };
      }

      // Store JWT token and user data
      await setAuthToken(data.token, {
        id: data.user.id,
        email: data.user.email,
        username: data.user.username,
        displayName: data.user.username,
        isPro: data.user.isPro,
        isVerified: data.user.isVerified,
      });

      return { success: true };
    } catch (error: any) {
      console.error('Login error:', error);
      return { success: false, message: error.message || 'Network error' };
    }
  }, [setAuthToken]);

  const signup = useCallback(async (email: string, password: string, username: string): Promise<{ success: boolean; message?: string }> => {
    try {
      const apiDomain = process.env.EXPO_PUBLIC_DOMAIN || 'http://localhost:8000';
      const baseUrl = `http://${apiDomain}`;
      
      const response = await fetch(`${baseUrl}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          username,
          email,
          password 
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        return { success: false, message: data.error || 'Registration failed' };
      }

      // Store JWT token and user data (account is created but isVerified is false)
      await setAuthToken(data.token, {
        id: data.user.id,
        email: data.user.email,
        username: data.user.username,
        displayName: username,
        isPro: data.user.isPro,
        isVerified: data.user.isVerified,
      });

      return { success: true, message: 'Check your email to verify your account' };
    } catch (error: any) {
      console.error('Signup error:', error);
      return { success: false, message: error.message || 'Network error' };
    }
  }, [setAuthToken]);

  const logout = useCallback(async () => {
    await secureDelete(SESSION_KEY);
    await secureDelete(TOKEN_KEY);
    setUser(null);
    setToken(null);
    setIsAuthenticated(false);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, user, token, login, signup, logout, setAuthToken }}>
      {children}
    </AuthContext.Provider>
  );
}

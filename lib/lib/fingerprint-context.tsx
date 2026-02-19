import React, { createContext, useContext, useState, useCallback, useMemo, useEffect, ReactNode } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {
  FingerprintShieldState,
  DEFAULT_SHIELD_STATE,
  UserAgentProfile,
  getTimezoneForServer,
  getTimezoneOffsetForServer,
  getRandomUserAgent,
  rotateUserAgent,
  getShieldSummary,
  ShieldSummary,
} from './fingerprint-shield';
import { applyWebRTCMask, applyTimezoneSpoofing, applyCanvasNoise } from './fingerprint-runtime';

interface FingerprintShieldContextValue {
  state: FingerprintShieldState;
  summary: ShieldSummary;
  setWebRTCMask: (enabled: boolean) => void;
  setTimezoneSpoofing: (enabled: boolean) => void;
  setCanvasNoise: (enabled: boolean) => void;
  setUserAgentRotation: (enabled: boolean) => void;
  setActiveUserAgent: (profile: UserAgentProfile) => void;
  cycleUserAgent: () => void;
  updateForServer: (serverFlag: string | null, city?: string) => void;
  serverFlag: string | null;
}

const FingerprintShieldContext = createContext<FingerprintShieldContextValue | null>(null);

const STORAGE_KEY = 'xvpn_fingerprint_shield';

export function FingerprintShieldProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<FingerprintShieldState>(DEFAULT_SHIELD_STATE);
  const [serverFlag, setServerFlag] = useState<string | null>(null);
  const [serverCity, setServerCity] = useState<string | undefined>(undefined);

  useEffect(() => {
    AsyncStorage.getItem(STORAGE_KEY).then(data => {
      if (data) {
        const saved = JSON.parse(data);
        setState(prev => ({ ...prev, ...saved }));
      }
    });
  }, []);

  useEffect(() => {
    applyWebRTCMask(state.webrtcMask);
  }, [state.webrtcMask]);

  useEffect(() => {
    if (state.timezoneSpoofing && serverFlag) {
      const tz = getTimezoneForServer(serverFlag, serverCity);
      const offset = getTimezoneOffsetForServer(serverFlag, serverCity);
      applyTimezoneSpoofing(true, tz, offset);
    } else {
      applyTimezoneSpoofing(false, null, 0);
    }
  }, [state.timezoneSpoofing, serverFlag, serverCity]);

  useEffect(() => {
    applyCanvasNoise(state.canvasNoise, state.canvasNoiseLevel);
  }, [state.canvasNoise, state.canvasNoiseLevel]);

  const persistState = useCallback((newState: Partial<FingerprintShieldState>) => {
    setState(prev => {
      const updated = { ...prev, ...newState };
      AsyncStorage.setItem(STORAGE_KEY, JSON.stringify({
        webrtcMask: updated.webrtcMask,
        timezoneSpoofing: updated.timezoneSpoofing,
        canvasNoise: updated.canvasNoise,
        userAgentRotation: updated.userAgentRotation,
        activeUserAgent: updated.activeUserAgent,
        canvasNoiseLevel: updated.canvasNoiseLevel,
      }));
      return updated;
    });
  }, []);

  const setWebRTCMask = useCallback((enabled: boolean) => {
    persistState({ webrtcMask: enabled });
  }, [persistState]);

  const setTimezoneSpoofing = useCallback((enabled: boolean) => {
    persistState({ timezoneSpoofing: enabled });
  }, [persistState]);

  const setCanvasNoise = useCallback((enabled: boolean) => {
    persistState({ canvasNoise: enabled });
  }, [persistState]);

  const setUserAgentRotation = useCallback((enabled: boolean) => {
    if (enabled) {
      const ua = getRandomUserAgent(state.activeUserAgent);
      persistState({ userAgentRotation: true, currentUserAgentString: ua });
    } else {
      persistState({ userAgentRotation: false, currentUserAgentString: null });
    }
  }, [persistState, state.activeUserAgent]);

  const setActiveUserAgent = useCallback((profile: UserAgentProfile) => {
    const ua = getRandomUserAgent(profile);
    persistState({ activeUserAgent: profile, currentUserAgentString: state.userAgentRotation ? ua : null });
  }, [persistState, state.userAgentRotation]);

  const cycleUserAgent = useCallback(() => {
    const nextProfile = rotateUserAgent(state.activeUserAgent);
    const ua = getRandomUserAgent(nextProfile);
    persistState({ activeUserAgent: nextProfile, currentUserAgentString: ua });
  }, [persistState, state.activeUserAgent]);

  const updateForServer = useCallback((flag: string | null, city?: string) => {
    setServerFlag(flag);
    setServerCity(city);
    if (flag && state.timezoneSpoofing) {
      const tz = getTimezoneForServer(flag, city);
      setState(prev => ({ ...prev, spoofedTimezone: tz }));
    } else {
      setState(prev => ({ ...prev, spoofedTimezone: null }));
    }
  }, [state.timezoneSpoofing]);

  const summary = useMemo(() => getShieldSummary(state, serverFlag), [state, serverFlag]);

  const value = useMemo(() => ({
    state,
    summary,
    setWebRTCMask,
    setTimezoneSpoofing,
    setCanvasNoise,
    setUserAgentRotation,
    setActiveUserAgent,
    cycleUserAgent,
    updateForServer,
    serverFlag,
  }), [state, summary, setWebRTCMask, setTimezoneSpoofing, setCanvasNoise, setUserAgentRotation, setActiveUserAgent, cycleUserAgent, updateForServer, serverFlag]);

  return (
    <FingerprintShieldContext.Provider value={value}>
      {children}
    </FingerprintShieldContext.Provider>
  );
}

export function useFingerprintShield() {
  const ctx = useContext(FingerprintShieldContext);
  if (!ctx) throw new Error('useFingerprintShield must be used within FingerprintShieldProvider');
  return ctx;
}

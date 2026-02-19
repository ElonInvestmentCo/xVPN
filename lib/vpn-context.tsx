import React, { createContext, useContext, useState, useEffect, useCallback, useMemo, useRef, ReactNode } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { connectSOCKS5, disconnectSOCKS5, probeSOCKS5 } from './socks5-proxy';

export interface VpnServer {
  id: string;
  name: string;
  country: string;
  city: string;
  flag: string;
  ping: number;
  load: number;
  premium: boolean;
}

export interface ConnectionStats {
  downloadSpeed: number;
  uploadSpeed: number;
  dataUsed: number;
  sessionDuration: number;
  ping: number;
}

export type ConnectionState = 'disconnected' | 'connecting' | 'protecting' | 'connected';
export type ConnectionError = { type: 'identity_check_failed'; message: string } | null;

interface VpnContextValue {
  connectionState: ConnectionState;
  connectionError: ConnectionError;
  isConnected: boolean;
  isConnecting: boolean;
  isProtecting: boolean;
  selectedServer: VpnServer | null;
  servers: VpnServer[];
  stats: ConnectionStats;
  favoriteServerIds: string[];
  connect: () => void;
  cancelConnection: () => void;
  completeConnection: () => void;
  disconnect: () => void;
  clearError: () => void;
  selectServer: (server: VpnServer) => void;
  toggleFavorite: (serverId: string) => void;
  protocol: string;
  setProtocol: (p: string) => void;
  killSwitch: boolean;
  setKillSwitch: (v: boolean) => void;
  autoConnect: boolean;
  setAutoConnect: (v: boolean) => void;
  doubleVpn: boolean;
  setDoubleVpn: (v: boolean) => void;
  doubleVpnServer: VpnServer | null;
  setDoubleVpnServer: (s: VpnServer | null) => void;
  virtualIp: string;
  isPremium: boolean;
  setPremium: (v: boolean) => void;
  subscriptionType: string | null;
  subscriptionExpiresAt: string | null;
  setSubscription: (type: string, expiresAt: string) => void;
  biometricLock: boolean;
  setBiometricLock: (v: boolean) => void;
  dnsLeakProtection: boolean;
  setDnsLeakProtection: (v: boolean) => void;
  adBlocker: boolean;
  setAdBlocker: (v: boolean) => void;
  setAuthToken: (token: string | null) => void;
  vpnConfigError: string | null;
}

const VpnContext = createContext<VpnContextValue | null>(null);

const SERVERS: VpnServer[] = [
  { id: '1', name: 'US - New York', country: 'United States', city: 'New York', flag: 'US', ping: 12, load: 34, premium: false },
  { id: '2', name: 'US - Los Angeles', country: 'United States', city: 'Los Angeles', flag: 'US', ping: 28, load: 52, premium: false },
  { id: '3', name: 'US - Dallas', country: 'United States', city: 'Dallas, TX', flag: 'US', ping: 22, load: 29, premium: false },
  { id: '4', name: 'US - Miami', country: 'United States', city: 'Miami, FL', flag: 'US', ping: 18, load: 41, premium: false },
  { id: '5', name: 'US - Chicago', country: 'United States', city: 'Chicago, IL', flag: 'US', ping: 16, load: 38, premium: false },
  { id: '6', name: 'US - Seattle', country: 'United States', city: 'Seattle, WA', flag: 'US', ping: 32, load: 25, premium: false },
  { id: '7', name: 'US - Atlanta', country: 'United States', city: 'Atlanta, GA', flag: 'US', ping: 19, load: 44, premium: false },
  { id: '8', name: 'US - Denver', country: 'United States', city: 'Denver, CO', flag: 'US', ping: 26, load: 18, premium: false },
  { id: '9', name: 'US - Phoenix', country: 'United States', city: 'Phoenix, AZ', flag: 'US', ping: 30, load: 22, premium: false },
  { id: '10', name: 'US - San Francisco', country: 'United States', city: 'San Francisco, CA', flag: 'US', ping: 31, load: 58, premium: true },
  { id: '11', name: 'US - Washington DC', country: 'United States', city: 'Washington, DC', flag: 'US', ping: 14, load: 47, premium: true },
  { id: '12', name: 'US - Houston', country: 'United States', city: 'Houston, TX', flag: 'US', ping: 24, load: 33, premium: false },
  { id: '13', name: 'Canada - Toronto', country: 'Canada', city: 'Toronto', flag: 'CA', ping: 18, load: 37, premium: false },
  { id: '14', name: 'Canada - Vancouver', country: 'Canada', city: 'Vancouver', flag: 'CA', ping: 35, load: 28, premium: false },
  { id: '15', name: 'Canada - Montreal', country: 'Canada', city: 'Montreal', flag: 'CA', ping: 20, load: 31, premium: false },
  { id: '16', name: 'UK - London', country: 'United Kingdom', city: 'London', flag: 'GB', ping: 45, load: 41, premium: false },
  { id: '17', name: 'UK - Manchester', country: 'United Kingdom', city: 'Manchester', flag: 'GB', ping: 48, load: 32, premium: false },
  { id: '18', name: 'Germany - Frankfurt', country: 'Germany', city: 'Frankfurt', flag: 'DE', ping: 52, load: 28, premium: false },
  { id: '19', name: 'Germany - Berlin', country: 'Germany', city: 'Berlin', flag: 'DE', ping: 55, load: 35, premium: false },
  { id: '20', name: 'France - Paris', country: 'France', city: 'Paris', flag: 'FR', ping: 42, load: 31, premium: false },
  { id: '21', name: 'France - Marseille', country: 'France', city: 'Marseille', flag: 'FR', ping: 46, load: 19, premium: false },
  { id: '22', name: 'Netherlands - Amsterdam', country: 'Netherlands', city: 'Amsterdam', flag: 'NL', ping: 48, load: 55, premium: true },
  { id: '23', name: 'Switzerland - Zurich', country: 'Switzerland', city: 'Zurich', flag: 'CH', ping: 56, load: 18, premium: true },
  { id: '24', name: 'Sweden - Stockholm', country: 'Sweden', city: 'Stockholm', flag: 'SE', ping: 61, load: 15, premium: true },
  { id: '25', name: 'Norway - Oslo', country: 'Norway', city: 'Oslo', flag: 'NO', ping: 63, load: 12, premium: true },
  { id: '26', name: 'Denmark - Copenhagen', country: 'Denmark', city: 'Copenhagen', flag: 'DK', ping: 58, load: 20, premium: false },
  { id: '27', name: 'Spain - Madrid', country: 'Spain', city: 'Madrid', flag: 'ES', ping: 50, load: 36, premium: false },
  { id: '28', name: 'Italy - Milan', country: 'Italy', city: 'Milan', flag: 'IT', ping: 54, load: 42, premium: false },
  { id: '29', name: 'Austria - Vienna', country: 'Austria', city: 'Vienna', flag: 'AT', ping: 57, load: 24, premium: false },
  { id: '30', name: 'Poland - Warsaw', country: 'Poland', city: 'Warsaw', flag: 'PL', ping: 60, load: 30, premium: false },
  { id: '31', name: 'Ireland - Dublin', country: 'Ireland', city: 'Dublin', flag: 'IE', ping: 44, load: 26, premium: false },
  { id: '32', name: 'Japan - Tokyo', country: 'Japan', city: 'Tokyo', flag: 'JP', ping: 89, load: 63, premium: true },
  { id: '33', name: 'Japan - Osaka', country: 'Japan', city: 'Osaka', flag: 'JP', ping: 92, load: 48, premium: true },
  { id: '34', name: 'Singapore', country: 'Singapore', city: 'Singapore', flag: 'SG', ping: 78, load: 45, premium: true },
  { id: '35', name: 'South Korea - Seoul', country: 'South Korea', city: 'Seoul', flag: 'KR', ping: 95, load: 71, premium: true },
  { id: '36', name: 'Hong Kong', country: 'Hong Kong', city: 'Hong Kong', flag: 'HK', ping: 82, load: 54, premium: true },
  { id: '37', name: 'Taiwan - Taipei', country: 'Taiwan', city: 'Taipei', flag: 'TW', ping: 86, load: 39, premium: true },
  { id: '38', name: 'Australia - Sydney', country: 'Australia', city: 'Sydney', flag: 'AU', ping: 112, load: 22, premium: false },
  { id: '39', name: 'Australia - Melbourne', country: 'Australia', city: 'Melbourne', flag: 'AU', ping: 118, load: 28, premium: false },
  { id: '40', name: 'New Zealand - Auckland', country: 'New Zealand', city: 'Auckland', flag: 'NZ', ping: 125, load: 14, premium: false },
  { id: '41', name: 'Brazil - Sao Paulo', country: 'Brazil', city: 'Sao Paulo', flag: 'BR', ping: 134, load: 42, premium: false },
  { id: '42', name: 'Mexico - Mexico City', country: 'Mexico', city: 'Mexico City', flag: 'MX', ping: 38, load: 35, premium: false },
  { id: '43', name: 'Argentina - Buenos Aires', country: 'Argentina', city: 'Buenos Aires', flag: 'AR', ping: 142, load: 20, premium: false },
  { id: '44', name: 'India - Mumbai', country: 'India', city: 'Mumbai', flag: 'IN', ping: 108, load: 67, premium: false },
  { id: '45', name: 'India - Chennai', country: 'India', city: 'Chennai', flag: 'IN', ping: 115, load: 52, premium: false },
  { id: '46', name: 'UAE - Dubai', country: 'UAE', city: 'Dubai', flag: 'AE', ping: 98, load: 40, premium: true },
  { id: '47', name: 'Israel - Tel Aviv', country: 'Israel', city: 'Tel Aviv', flag: 'IL', ping: 72, load: 33, premium: true },
  { id: '48', name: 'South Africa - Johannesburg', country: 'South Africa', city: 'Johannesburg', flag: 'ZA', ping: 155, load: 18, premium: false },
  { id: '49', name: 'Romania - Bucharest', country: 'Romania', city: 'Bucharest', flag: 'RO', ping: 62, load: 16, premium: false },
  { id: '50', name: 'Czech Republic - Prague', country: 'Czech Republic', city: 'Prague', flag: 'CZ', ping: 53, load: 21, premium: false },
];

function generateVirtualIp(): string {
  const c = Math.floor(Math.random() * 254) + 1;
  const d = Math.floor(Math.random() * 254) + 1;
  return `185.203.${c}.${d}`;
}

const CONNECTION_TIMEOUT_MS = 10000;
const SOCKS5_PROBE_MS = 3500;
const PROTECTING_DURATION_MS = 2500;

const US_RESIDENTIAL_ISPS = [
  'Comcast Cable', 'AT&T Internet', 'Spectrum Residential', 'Verizon Fios',
  'Cox Communications', 'CenturyLink', 'Frontier Communications', 'Mediacom',
  'Windstream', 'Charter Spectrum', 'Optimum Residential', 'Xfinity',
];

function simulateIpCheck(): { trusted: boolean; isp: string; ipAddress: string } {
  const isp = US_RESIDENTIAL_ISPS[Math.floor(Math.random() * US_RESIDENTIAL_ISPS.length)];
  const a = Math.floor(Math.random() * 200) + 10;
  const b = Math.floor(Math.random() * 254) + 1;
  const c = Math.floor(Math.random() * 254) + 1;
  const d = Math.floor(Math.random() * 254) + 1;
  const trusted = Math.random() > 0.15;
  return { trusted, isp, ipAddress: `${a}.${b}.${c}.${d}` };
}

export function VpnProvider({ children }: { children: ReactNode }) {
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [connectionError, setConnectionError] = useState<ConnectionError>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isProtecting, setIsProtecting] = useState(false);
  const [selectedServer, setSelectedServer] = useState<VpnServer | null>(SERVERS[0]);
  const [favoriteServerIds, setFavoriteServerIds] = useState<string[]>([]);
  const [protocol, setProtocol] = useState('WireGuard');
  const [killSwitch, setKillSwitch] = useState(true);
  const [autoConnect, setAutoConnect] = useState(false);
  const [doubleVpn, setDoubleVpn] = useState(false);
  const [doubleVpnServer, setDoubleVpnServer] = useState<VpnServer | null>(SERVERS[3]);
  const [virtualIp, setVirtualIp] = useState('---');
  const [isPremium, setIsPremium] = useState(false);
  const [subscriptionType, setSubscriptionType] = useState<string | null>(null);
  const [subscriptionExpiresAt, setSubscriptionExpiresAt] = useState<string | null>(null);
  const [biometricLock, setBiometricLockState] = useState(false);
  const [dnsLeakProtection, setDnsLeakProtectionState] = useState(true);
  const [adBlocker, setAdBlockerState] = useState(true);
  const connectionTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const protectingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const socksProbeRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelledRef = useRef(false);
  const probePassedRef = useRef(false);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [vpnConfigError, setVpnConfigError] = useState<string | null>(null);
  const [stats, setStats] = useState<ConnectionStats>({
    downloadSpeed: 0,
    uploadSpeed: 0,
    dataUsed: 0,
    sessionDuration: 0,
    ping: 0,
  });

  useEffect(() => {
    AsyncStorage.getItem('xvpn_favorites').then(data => {
      if (data) setFavoriteServerIds(JSON.parse(data));
    });
    AsyncStorage.getItem('xvpn_server').then(data => {
      if (data) {
        const s = SERVERS.find(srv => srv.id === data);
        if (s) setSelectedServer(s);
      }
    });
    AsyncStorage.getItem('xvpn_settings').then(data => {
      if (data) {
        const settings = JSON.parse(data);
        if (settings.protocol) setProtocol(settings.protocol);
        if (settings.killSwitch !== undefined) setKillSwitch(settings.killSwitch);
        if (settings.autoConnect !== undefined) setAutoConnect(settings.autoConnect);
        if (settings.doubleVpn !== undefined) setDoubleVpn(settings.doubleVpn);
        if (settings.doubleVpnServerId) {
          const dvs = SERVERS.find(srv => srv.id === settings.doubleVpnServerId);
          if (dvs) setDoubleVpnServer(dvs);
        }
        if (settings.dnsLeakProtection !== undefined) setDnsLeakProtectionState(settings.dnsLeakProtection);
        if (settings.adBlocker !== undefined) setAdBlockerState(settings.adBlocker);
        if (settings.biometricLock !== undefined) setBiometricLockState(settings.biometricLock);
      }
    });
    AsyncStorage.getItem('xvpn_premium').then(data => {
      if (data) {
        const premium = JSON.parse(data);
        if (premium.isPremium) setIsPremium(true);
        if (premium.subscriptionType) setSubscriptionType(premium.subscriptionType);
        if (premium.subscriptionExpiresAt) setSubscriptionExpiresAt(premium.subscriptionExpiresAt);
      }
    });
  }, []);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (isConnected) {
      let baseDown = 45 + Math.random() * 30;
      let baseUp = 15 + Math.random() * 15;
      let driftDirection = 1;
      let tickCounter = 0;

      interval = setInterval(() => {
        tickCounter++;

        if (tickCounter % 7 === 0) {
          driftDirection = Math.random() > 0.5 ? 1 : -1;
          baseDown = Math.max(20, Math.min(120, baseDown + driftDirection * (Math.random() * 8)));
          baseUp = Math.max(5, Math.min(50, baseUp + driftDirection * (Math.random() * 4)));
        }

        const jitterDown = (Math.random() - 0.5) * 12;
        const jitterUp = (Math.random() - 0.5) * 6;

        const microPause = Math.random() > 0.95 ? -baseDown * 0.3 : 0;

        const burstFactor = Math.random() > 0.92 ? 1.4 + Math.random() * 0.3 : 1;

        const dataJitter = 0.015 + Math.random() * 0.06 + (Math.random() > 0.9 ? Math.random() * 0.08 : 0);

        const intervalJitter = Math.random() > 0.85 ? Math.floor(Math.random() * 2) : 0;

        setStats(prev => ({
          downloadSpeed: Math.max(0, (baseDown + jitterDown + microPause) * burstFactor),
          uploadSpeed: Math.max(0, (baseUp + jitterUp) * burstFactor),
          dataUsed: prev.dataUsed + dataJitter,
          sessionDuration: prev.sessionDuration + 1 + intervalJitter,
          ping: Math.max(1, (selectedServer?.ping || 20) + Math.floor(Math.random() * 12) - 6 + (Math.random() > 0.9 ? Math.floor(Math.random() * 15) : 0)),
        }));
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isConnected, selectedServer]);

  useEffect(() => {
    if (!isConnected || !killSwitch) return;
    const heartbeat = setInterval(() => {
      const heartbeatLost = Math.random() < 0.003;
      if (heartbeatLost) {
        console.warn('[KillSwitch] Heartbeat lost — terminating connection');
        setConnectionState('disconnected');
        setIsConnected(false);
        setIsConnecting(false);
        setVirtualIp('---');
        setStats({ downloadSpeed: 0, uploadSpeed: 0, dataUsed: 0, sessionDuration: 0, ping: 0 });
      }
    }, 5000);
    return () => clearInterval(heartbeat);
  }, [isConnected, killSwitch]);

  const clearTimers = useCallback(() => {
    if (connectionTimeoutRef.current) {
      clearTimeout(connectionTimeoutRef.current);
      connectionTimeoutRef.current = null;
    }
    if (protectingTimeoutRef.current) {
      clearTimeout(protectingTimeoutRef.current);
      protectingTimeoutRef.current = null;
    }
    if (socksProbeRef.current) {
      clearTimeout(socksProbeRef.current);
      socksProbeRef.current = null;
    }
  }, []);

  const resetToDisconnected = useCallback(() => {
    clearTimers();
    disconnectSOCKS5();
    setConnectionState('disconnected');
    setIsConnected(false);
    setIsConnecting(false);
    setIsProtecting(false);
    setVirtualIp('---');
    setStats({ downloadSpeed: 0, uploadSpeed: 0, dataUsed: 0, sessionDuration: 0, ping: 0 });
  }, [clearTimers]);

  const attemptIpVerification = useCallback((attemptsLeft: number) => {
    if (cancelledRef.current) return;
    const ipCheck = simulateIpCheck();
    if (ipCheck.trusted) {
      setIsProtecting(false);
      setIsConnected(true);
      setConnectionState('connected');
      setVirtualIp(generateVirtualIp());
    } else if (attemptsLeft > 0) {
      protectingTimeoutRef.current = setTimeout(() => {
        attemptIpVerification(attemptsLeft - 1);
      }, 1500);
    } else {
      setConnectionError({
        type: 'identity_check_failed',
        message: 'Identity Check Failed — Could not verify high-trust US Residential ISP',
      });
      resetToDisconnected();
    }
  }, [resetToDisconnected]);

  const connect = useCallback(() => {
    const initiateConnection = async () => {
      // Attempt real SOCKS5 connection
      const socksResult = await connectSOCKS5();
      
      socksProbeRef.current = setTimeout(() => {
        if (cancelledRef.current) return;
        
        if (!socksResult.success) {
          setConnectionError({
            type: 'identity_check_failed',
            message: socksResult.error || 'SOCKS5 proxy connection failed',
          });
          resetToDisconnected();
          return;
        }
        
        probePassedRef.current = true;
        setIsConnecting(false);
        setIsProtecting(true);
        setConnectionState('protecting');

        if (connectionTimeoutRef.current) {
          clearTimeout(connectionTimeoutRef.current);
          connectionTimeoutRef.current = null;
        }

        protectingTimeoutRef.current = setTimeout(() => {
          if (cancelledRef.current) return;
          attemptIpVerification(3);
        }, PROTECTING_DURATION_MS);
      }, 1000); // Brief delay after SOCKS5 connection
    };

    cancelledRef.current = false;
    probePassedRef.current = false;
    setConnectionError(null);
    setVpnConfigError(null);
    setConnectionState('connecting');
    setIsConnecting(true);
    setIsProtecting(false);
    setStats({ downloadSpeed: 0, uploadSpeed: 0, dataUsed: 0, sessionDuration: 0, ping: 0 });

    // First, fetch VPN config from server if we have a token
    if (authToken) {
      const fetchVpnConfig = async () => {
        try {
          const domain = typeof window !== 'undefined' 
            ? window.location.origin 
            : process.env.EXPO_PUBLIC_DOMAIN || '192.168.0.160:8000';
          const baseUrl = domain.startsWith('http') ? domain : `https://${domain}`;

          const response = await fetch(`${baseUrl}/api/vpn/config`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${authToken}`,
              'Content-Type': 'application/json',
            },
          });

          if (!response.ok) {
            const data = await response.json();
            if (response.status === 403) {
              setVpnConfigError('Elite Stealth subscription required. Please upgrade to access VPN.');
            } else {
              setVpnConfigError(data.error || 'Failed to fetch VPN configuration');
            }
            setConnectionError({
              type: 'identity_check_failed',
              message: data.error || 'Failed to get VPN configuration',
            });
            resetToDisconnected();
            return;
          }

          const config = await response.json();
          console.log('[VPN] Config received:', { location: config.location, provider: config.provider });
          
          // Continue with SOCKS5 connection attempt
          initiateConnection();
        } catch (error: any) {
          console.error('[VPN] Config fetch error:', error);
          setVpnConfigError('Network error fetching VPN configuration');
          setConnectionError({
            type: 'identity_check_failed',
            message: 'Failed to fetch VPN configuration',
          });
          resetToDisconnected();
        }
      };

      fetchVpnConfig();
    } else {
      // If no auth token, proceed with SOCKS5 connection
      initiateConnection();
    }
  }, [resetToDisconnected, attemptIpVerification, authToken]);

  const cancelConnection = useCallback(() => {
    cancelledRef.current = true;
    clearTimers();
    resetToDisconnected();
  }, [clearTimers, resetToDisconnected]);

  const completeConnection = useCallback(() => {
  }, []);

  const disconnect = useCallback(() => {
    cancelledRef.current = true;
    resetToDisconnected();
  }, [resetToDisconnected]);

  const clearError = useCallback(() => {
    setConnectionError(null);
  }, []);

  const selectServer = useCallback((server: VpnServer) => {
    setSelectedServer(server);
    AsyncStorage.setItem('xvpn_server', server.id);
  }, []);

  const toggleFavorite = useCallback((serverId: string) => {
    setFavoriteServerIds(prev => {
      const next = prev.includes(serverId)
        ? prev.filter(id => id !== serverId)
        : [...prev, serverId];
      AsyncStorage.setItem('xvpn_favorites', JSON.stringify(next));
      return next;
    });
  }, []);

  const saveSetting = useCallback((key: string, val: unknown) => {
    AsyncStorage.getItem('xvpn_settings').then(data => {
      const settings = data ? JSON.parse(data) : {};
      settings[key] = val;
      AsyncStorage.setItem('xvpn_settings', JSON.stringify(settings));
    });
  }, []);

  const handleSetProtocol = useCallback((p: string) => {
    setProtocol(p);
    saveSetting('protocol', p);
  }, [saveSetting]);

  const handleSetKillSwitch = useCallback((v: boolean) => {
    setKillSwitch(v);
    saveSetting('killSwitch', v);
  }, [saveSetting]);

  const handleSetAutoConnect = useCallback((v: boolean) => {
    setAutoConnect(v);
    saveSetting('autoConnect', v);
  }, [saveSetting]);

  const handleSetDoubleVpn = useCallback((v: boolean) => {
    setDoubleVpn(v);
    saveSetting('doubleVpn', v);
  }, [saveSetting]);

  const handleSetDoubleVpnServer = useCallback((s: VpnServer | null) => {
    setDoubleVpnServer(s);
    saveSetting('doubleVpnServerId', s?.id || null);
  }, [saveSetting]);

  const handleSetPremium = useCallback((v: boolean) => {
    setIsPremium(v);
    AsyncStorage.getItem('xvpn_premium').then(data => {
      const premium = data ? JSON.parse(data) : {};
      premium.isPremium = v;
      AsyncStorage.setItem('xvpn_premium', JSON.stringify(premium));
    });
  }, []);

  const handleSetSubscription = useCallback((type: string, expiresAt: string) => {
    setIsPremium(true);
    setSubscriptionType(type);
    setSubscriptionExpiresAt(expiresAt);
    AsyncStorage.setItem('xvpn_premium', JSON.stringify({
      isPremium: true,
      subscriptionType: type,
      subscriptionExpiresAt: expiresAt,
    }));
  }, []);

  const handleSetBiometricLock = useCallback((v: boolean) => {
    setBiometricLockState(v);
    saveSetting('biometricLock', v);
  }, [saveSetting]);

  const handleSetDnsLeakProtection = useCallback((v: boolean) => {
    setDnsLeakProtectionState(v);
    saveSetting('dnsLeakProtection', v);
  }, [saveSetting]);

  const handleSetAdBlocker = useCallback((v: boolean) => {
    setAdBlockerState(v);
    saveSetting('adBlocker', v);
  }, [saveSetting]);

  const value = useMemo(() => ({
    connectionState,
    connectionError,
    isConnected,
    isConnecting,
    isProtecting,
    selectedServer,
    servers: SERVERS,
    stats,
    favoriteServerIds,
    connect,
    cancelConnection,
    disconnect,
    selectServer,
    toggleFavorite,
    clearError,
    protocol,
    setProtocol: handleSetProtocol,
    killSwitch,
    setKillSwitch: handleSetKillSwitch,
    autoConnect,
    setAutoConnect: handleSetAutoConnect,
    doubleVpn,
    setDoubleVpn: handleSetDoubleVpn,
    doubleVpnServer,
    setDoubleVpnServer: handleSetDoubleVpnServer,
    virtualIp,
    completeConnection,
    isPremium,
    setPremium: handleSetPremium,
    subscriptionType,
    subscriptionExpiresAt,
    setSubscription: handleSetSubscription,
    biometricLock,
    setBiometricLock: handleSetBiometricLock,
    dnsLeakProtection,
    setDnsLeakProtection: handleSetDnsLeakProtection,
    adBlocker,
    setAdBlocker: handleSetAdBlocker,
    setAuthToken,
    vpnConfigError,
  }), [connectionState, connectionError, isConnected, isConnecting, isProtecting, selectedServer, stats, favoriteServerIds, connect, cancelConnection, completeConnection, disconnect, selectServer, toggleFavorite, clearError, protocol, handleSetProtocol, killSwitch, handleSetKillSwitch, autoConnect, handleSetAutoConnect, doubleVpn, handleSetDoubleVpn, doubleVpnServer, handleSetDoubleVpnServer, virtualIp, isPremium, handleSetPremium, subscriptionType, subscriptionExpiresAt, handleSetSubscription, biometricLock, handleSetBiometricLock, dnsLeakProtection, handleSetDnsLeakProtection, adBlocker, handleSetAdBlocker, authToken, vpnConfigError]);

  return <VpnContext.Provider value={value}>{children}</VpnContext.Provider>;
}

export function useVpn() {
  const ctx = useContext(VpnContext);
  if (!ctx) throw new Error('useVpn must be used within VpnProvider');
  return ctx;
}

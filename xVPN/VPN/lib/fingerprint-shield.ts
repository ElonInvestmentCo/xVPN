import { Platform } from 'react-native';

const CITY_TIMEZONES: Record<string, { tz: string; offset: number }> = {
  'New York': { tz: 'America/New_York', offset: -5 },
  'Los Angeles': { tz: 'America/Los_Angeles', offset: -8 },
  'Dallas, TX': { tz: 'America/Chicago', offset: -6 },
  'Miami, FL': { tz: 'America/New_York', offset: -5 },
  'Chicago, IL': { tz: 'America/Chicago', offset: -6 },
  'Seattle, WA': { tz: 'America/Los_Angeles', offset: -8 },
  'Atlanta, GA': { tz: 'America/New_York', offset: -5 },
  'Denver, CO': { tz: 'America/Denver', offset: -7 },
  'Phoenix, AZ': { tz: 'America/Phoenix', offset: -7 },
  'San Francisco, CA': { tz: 'America/Los_Angeles', offset: -8 },
  'Washington, DC': { tz: 'America/New_York', offset: -5 },
  'Houston, TX': { tz: 'America/Chicago', offset: -6 },
  'Toronto': { tz: 'America/Toronto', offset: -5 },
  'Vancouver': { tz: 'America/Vancouver', offset: -8 },
  'Montreal': { tz: 'America/Toronto', offset: -5 },
  'London': { tz: 'Europe/London', offset: 0 },
  'Manchester': { tz: 'Europe/London', offset: 0 },
  'Frankfurt': { tz: 'Europe/Berlin', offset: 1 },
  'Berlin': { tz: 'Europe/Berlin', offset: 1 },
  'Paris': { tz: 'Europe/Paris', offset: 1 },
  'Marseille': { tz: 'Europe/Paris', offset: 1 },
  'Amsterdam': { tz: 'Europe/Amsterdam', offset: 1 },
  'Zurich': { tz: 'Europe/Zurich', offset: 1 },
  'Stockholm': { tz: 'Europe/Stockholm', offset: 1 },
  'Oslo': { tz: 'Europe/Oslo', offset: 1 },
  'Copenhagen': { tz: 'Europe/Copenhagen', offset: 1 },
  'Madrid': { tz: 'Europe/Madrid', offset: 1 },
  'Milan': { tz: 'Europe/Rome', offset: 1 },
  'Vienna': { tz: 'Europe/Vienna', offset: 1 },
  'Warsaw': { tz: 'Europe/Warsaw', offset: 1 },
  'Dublin': { tz: 'Europe/Dublin', offset: 0 },
  'Tokyo': { tz: 'Asia/Tokyo', offset: 9 },
  'Osaka': { tz: 'Asia/Tokyo', offset: 9 },
  'Singapore': { tz: 'Asia/Singapore', offset: 8 },
  'Seoul': { tz: 'Asia/Seoul', offset: 9 },
  'Hong Kong': { tz: 'Asia/Hong_Kong', offset: 8 },
  'Taipei': { tz: 'Asia/Taipei', offset: 8 },
  'Sydney': { tz: 'Australia/Sydney', offset: 11 },
  'Melbourne': { tz: 'Australia/Melbourne', offset: 11 },
  'Auckland': { tz: 'Pacific/Auckland', offset: 13 },
  'Sao Paulo': { tz: 'America/Sao_Paulo', offset: -3 },
  'Mexico City': { tz: 'America/Mexico_City', offset: -6 },
  'Buenos Aires': { tz: 'America/Argentina/Buenos_Aires', offset: -3 },
  'Mumbai': { tz: 'Asia/Kolkata', offset: 5.5 },
  'Chennai': { tz: 'Asia/Kolkata', offset: 5.5 },
  'Dubai': { tz: 'Asia/Dubai', offset: 4 },
  'Tel Aviv': { tz: 'Asia/Jerusalem', offset: 2 },
  'Johannesburg': { tz: 'Africa/Johannesburg', offset: 2 },
  'Bucharest': { tz: 'Europe/Bucharest', offset: 2 },
  'Prague': { tz: 'Europe/Prague', offset: 1 },
};

const SERVER_TIMEZONES: Record<string, string> = {
  'US': 'America/New_York',
  'GB': 'Europe/London',
  'DE': 'Europe/Berlin',
  'JP': 'Asia/Tokyo',
  'SG': 'Asia/Singapore',
  'AU': 'Australia/Sydney',
  'CA': 'America/Toronto',
  'NL': 'Europe/Amsterdam',
  'CH': 'Europe/Zurich',
  'FR': 'Europe/Paris',
  'KR': 'Asia/Seoul',
  'BR': 'America/Sao_Paulo',
  'IN': 'Asia/Kolkata',
  'SE': 'Europe/Stockholm',
  'NO': 'Europe/Oslo',
  'DK': 'Europe/Copenhagen',
  'ES': 'Europe/Madrid',
  'IT': 'Europe/Rome',
  'AT': 'Europe/Vienna',
  'PL': 'Europe/Warsaw',
  'IE': 'Europe/Dublin',
  'HK': 'Asia/Hong_Kong',
  'TW': 'Asia/Taipei',
  'NZ': 'Pacific/Auckland',
  'MX': 'America/Mexico_City',
  'AR': 'America/Argentina/Buenos_Aires',
  'AE': 'Asia/Dubai',
  'IL': 'Asia/Jerusalem',
  'ZA': 'Africa/Johannesburg',
  'RO': 'Europe/Bucharest',
  'CZ': 'Europe/Prague',
};

const SERVER_TIMEZONE_OFFSETS: Record<string, number> = {
  'US': -5,
  'GB': 0,
  'DE': 1,
  'JP': 9,
  'SG': 8,
  'AU': 11,
  'CA': -5,
  'NL': 1,
  'CH': 1,
  'FR': 1,
  'KR': 9,
  'BR': -3,
  'IN': 5.5,
  'SE': 1,
  'NO': 1,
  'DK': 1,
  'ES': 1,
  'IT': 1,
  'AT': 1,
  'PL': 1,
  'IE': 0,
  'HK': 8,
  'TW': 8,
  'NZ': 13,
  'MX': -6,
  'AR': -3,
  'AE': 4,
  'IL': 2,
  'ZA': 2,
  'RO': 2,
  'CZ': 1,
};

const USER_AGENTS = {
  windows_chrome: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  ],
  windows_firefox: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  ],
  mac_safari: [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  ],
  mac_chrome: [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  ],
  iphone_safari: [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  ],
};

export type UserAgentProfile = keyof typeof USER_AGENTS;

export const USER_AGENT_LABELS: Record<UserAgentProfile, string> = {
  windows_chrome: 'Windows / Chrome',
  windows_firefox: 'Windows / Firefox',
  mac_safari: 'Mac / Safari',
  mac_chrome: 'Mac / Chrome',
  iphone_safari: 'iPhone / Safari',
};

export interface FingerprintShieldState {
  webrtcMask: boolean;
  timezoneSpoofing: boolean;
  canvasNoise: boolean;
  userAgentRotation: boolean;
  activeUserAgent: UserAgentProfile;
  spoofedTimezone: string | null;
  currentUserAgentString: string | null;
  canvasNoiseLevel: number;
}

export const DEFAULT_SHIELD_STATE: FingerprintShieldState = {
  webrtcMask: true,
  timezoneSpoofing: true,
  canvasNoise: true,
  userAgentRotation: false,
  activeUserAgent: 'windows_chrome',
  spoofedTimezone: null,
  currentUserAgentString: null,
  canvasNoiseLevel: 0.02,
};

export function getTimezoneForServer(serverFlag: string, city?: string): string {
  if (city) {
    const cityData = CITY_TIMEZONES[city];
    if (cityData) return cityData.tz;
  }
  return SERVER_TIMEZONES[serverFlag] || 'America/New_York';
}

export function getTimezoneOffsetForServer(serverFlag: string, city?: string): number {
  if (city) {
    const cityData = CITY_TIMEZONES[city];
    if (cityData) return cityData.offset;
  }
  const offset = SERVER_TIMEZONE_OFFSETS[serverFlag];
  return offset !== undefined ? offset : -5;
}

export function getRandomUserAgent(profile: UserAgentProfile): string {
  const agents = USER_AGENTS[profile];
  return agents[Math.floor(Math.random() * agents.length)];
}

export function rotateUserAgent(currentProfile: UserAgentProfile): UserAgentProfile {
  const profiles = Object.keys(USER_AGENTS) as UserAgentProfile[];
  const currentIndex = profiles.indexOf(currentProfile);
  return profiles[(currentIndex + 1) % profiles.length];
}

export function generateCanvasNoise(noiseLevel: number = 0.02): number[] {
  const noiseData: number[] = [];
  for (let i = 0; i < 16; i++) {
    noiseData.push((Math.random() - 0.5) * 2 * noiseLevel * 255);
  }
  return noiseData;
}

export interface WebRTCLeakStatus {
  blocked: boolean;
  localIpHidden: boolean;
  stunBlocked: boolean;
  turnBlocked: boolean;
  mdnsEnabled: boolean;
}

export function getWebRTCLeakStatus(maskEnabled: boolean): WebRTCLeakStatus {
  if (maskEnabled) {
    return {
      blocked: true,
      localIpHidden: true,
      stunBlocked: true,
      turnBlocked: true,
      mdnsEnabled: true,
    };
  }
  return {
    blocked: false,
    localIpHidden: false,
    stunBlocked: false,
    turnBlocked: false,
    mdnsEnabled: false,
  };
}

export interface CanvasProtectionStatus {
  noiseInjected: boolean;
  noiseLevel: number;
  hashRandomized: boolean;
  gpuInfoMasked: boolean;
}

export function getCanvasProtectionStatus(enabled: boolean, noiseLevel: number): CanvasProtectionStatus {
  if (enabled) {
    return {
      noiseInjected: true,
      noiseLevel,
      hashRandomized: true,
      gpuInfoMasked: true,
    };
  }
  return {
    noiseInjected: false,
    noiseLevel: 0,
    hashRandomized: false,
    gpuInfoMasked: false,
  };
}

export interface TimezoneProtectionStatus {
  spoofed: boolean;
  originalTimezone: string;
  spoofedTimezone: string | null;
  offsetMatch: boolean;
  intlApiPatched: boolean;
  dateApiPatched: boolean;
}

export function getTimezoneProtectionStatus(
  enabled: boolean,
  serverFlag: string | null
): TimezoneProtectionStatus {
  const original = Intl.DateTimeFormat().resolvedOptions().timeZone;
  if (enabled && serverFlag) {
    const spoofed = getTimezoneForServer(serverFlag);
    return {
      spoofed: true,
      originalTimezone: original,
      spoofedTimezone: spoofed,
      offsetMatch: true,
      intlApiPatched: true,
      dateApiPatched: true,
    };
  }
  return {
    spoofed: false,
    originalTimezone: original,
    spoofedTimezone: null,
    offsetMatch: false,
    intlApiPatched: false,
    dateApiPatched: false,
  };
}

export interface ShieldSummary {
  totalProtections: number;
  activeProtections: number;
  protectionLevel: 'none' | 'basic' | 'moderate' | 'maximum';
  webrtc: WebRTCLeakStatus;
  canvas: CanvasProtectionStatus;
  timezone: TimezoneProtectionStatus;
  userAgent: {
    rotated: boolean;
    profile: UserAgentProfile;
    currentString: string | null;
  };
}

export function getShieldSummary(
  state: FingerprintShieldState,
  serverFlag: string | null
): ShieldSummary {
  const webrtc = getWebRTCLeakStatus(state.webrtcMask);
  const canvas = getCanvasProtectionStatus(state.canvasNoise, state.canvasNoiseLevel);
  const timezone = getTimezoneProtectionStatus(state.timezoneSpoofing, serverFlag);

  const activeCount = [state.webrtcMask, state.timezoneSpoofing, state.canvasNoise, state.userAgentRotation].filter(Boolean).length;

  let level: ShieldSummary['protectionLevel'] = 'none';
  if (activeCount === 4) level = 'maximum';
  else if (activeCount >= 2) level = 'moderate';
  else if (activeCount >= 1) level = 'basic';

  return {
    totalProtections: 4,
    activeProtections: activeCount,
    protectionLevel: level,
    webrtc,
    canvas,
    timezone,
    userAgent: {
      rotated: state.userAgentRotation,
      profile: state.activeUserAgent,
      currentString: state.currentUserAgentString,
    },
  };
}

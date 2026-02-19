import { Platform } from 'react-native';

let originalRTCPeerConnection: typeof RTCPeerConnection | null = null;
let originalDateTimeFormat: typeof Intl.DateTimeFormat | null = null;
let originalGetTimezoneOffset: (() => number) | null = null;
let originalToDataURL: ((type?: string, quality?: any) => string) | null = null;
let originalGetImageData: ((sx: number, sy: number, sw: number, sh: number) => ImageData) | null = null;

let webrtcActive = false;
let timezoneActive = false;
let canvasActive = false;

export function applyWebRTCMask(enabled: boolean): void {
  if (Platform.OS !== 'web') return;
  if (typeof window === 'undefined') return;

  if (enabled && !webrtcActive) {
    const g = window as any;
    originalRTCPeerConnection = g.RTCPeerConnection || g.webkitRTCPeerConnection;

    if (originalRTCPeerConnection) {
      g.RTCPeerConnection = function () {
        return {
          createOffer: () => Promise.resolve({ type: 'offer', sdp: '' }),
          createAnswer: () => Promise.resolve({ type: 'answer', sdp: '' }),
          setLocalDescription: () => Promise.resolve(),
          setRemoteDescription: () => Promise.resolve(),
          addIceCandidate: () => Promise.resolve(),
          close: () => {},
          addEventListener: () => {},
          removeEventListener: () => {},
          getStats: () => Promise.resolve(new Map()),
          getSenders: () => [],
          getReceivers: () => [],
          onicecandidate: null,
          ontrack: null,
          ondatachannel: null,
          onconnectionstatechange: null,
          localDescription: null,
          remoteDescription: null,
          connectionState: 'closed',
          iceConnectionState: 'closed',
          iceGatheringState: 'complete',
          signalingState: 'closed',
        };
      } as any;
    }

    if (g.webkitRTCPeerConnection) {
      g.webkitRTCPeerConnection = g.RTCPeerConnection;
    }

    webrtcActive = true;
  } else if (!enabled && webrtcActive) {
    if (originalRTCPeerConnection) {
      const g = window as any;
      g.RTCPeerConnection = originalRTCPeerConnection;
      if (g.webkitRTCPeerConnection) {
        g.webkitRTCPeerConnection = originalRTCPeerConnection;
      }
      originalRTCPeerConnection = null;
    }
    webrtcActive = false;
  }
}

export function applyTimezoneSpoofing(enabled: boolean, timezone: string | null, offsetHours: number): void {
  if (Platform.OS !== 'web') return;
  if (typeof window === 'undefined') return;

  if (enabled && timezone) {
    if (!originalDateTimeFormat) {
      originalDateTimeFormat = Intl.DateTimeFormat;
    }
    if (!originalGetTimezoneOffset) {
      originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
    }

    const spoofedTimezone = timezone;
    const spoofedOffset = -(offsetHours * 60);

    const OrigDTF = originalDateTimeFormat;
    (Intl as any).DateTimeFormat = function (...args: any[]) {
      if (args.length >= 2 && args[1]) {
        args[1] = { ...args[1], timeZone: args[1].timeZone || spoofedTimezone };
      } else if (args.length < 2) {
        args[1] = { timeZone: spoofedTimezone };
      }
      return new OrigDTF(...args);
    };
    (Intl as any).DateTimeFormat.prototype = OrigDTF.prototype;
    (Intl as any).DateTimeFormat.supportedLocalesOf = OrigDTF.supportedLocalesOf;

    Date.prototype.getTimezoneOffset = function () {
      return spoofedOffset;
    };

    timezoneActive = true;
  } else if (!enabled && timezoneActive) {
    if (originalDateTimeFormat) {
      (Intl as any).DateTimeFormat = originalDateTimeFormat;
      originalDateTimeFormat = null;
    }
    if (originalGetTimezoneOffset) {
      Date.prototype.getTimezoneOffset = originalGetTimezoneOffset;
      originalGetTimezoneOffset = null;
    }
    timezoneActive = false;
  }
}

export function applyCanvasNoise(enabled: boolean, noiseLevel: number = 0.02): void {
  if (Platform.OS !== 'web') return;
  if (typeof window === 'undefined') return;
  if (typeof HTMLCanvasElement === 'undefined') return;

  if (enabled && !canvasActive) {
    const canvasProto = HTMLCanvasElement.prototype;
    originalToDataURL = canvasProto.toDataURL;

    canvasProto.toDataURL = function (type?: string, quality?: any): string {
      try {
        const ctx = this.getContext('2d');
        if (ctx) {
          const w = Math.min(this.width, 4);
          const h = Math.min(this.height, 4);
          const imageData = CanvasRenderingContext2D.prototype.getImageData.call(ctx, 0, 0, w, h);
          for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + (Math.random() - 0.5) * noiseLevel * 255));
            imageData.data[i + 1] = Math.max(0, Math.min(255, imageData.data[i + 1] + (Math.random() - 0.5) * noiseLevel * 255));
            imageData.data[i + 2] = Math.max(0, Math.min(255, imageData.data[i + 2] + (Math.random() - 0.5) * noiseLevel * 255));
          }
          ctx.putImageData(imageData, 0, 0);
        }
      } catch (_) {}
      return originalToDataURL!.call(this, type, quality);
    };

    const ctx2dProto = CanvasRenderingContext2D.prototype;
    originalGetImageData = ctx2dProto.getImageData;

    ctx2dProto.getImageData = function (sx: number, sy: number, sw: number, sh: number): ImageData {
      const data = originalGetImageData!.call(this, sx, sy, sw, sh);
      for (let i = 0; i < data.data.length; i += 4) {
        data.data[i] = Math.max(0, Math.min(255, data.data[i] + (Math.random() - 0.5) * noiseLevel * 255));
        data.data[i + 1] = Math.max(0, Math.min(255, data.data[i + 1] + (Math.random() - 0.5) * noiseLevel * 255));
        data.data[i + 2] = Math.max(0, Math.min(255, data.data[i + 2] + (Math.random() - 0.5) * noiseLevel * 255));
      }
      return data;
    };

    canvasActive = true;
  } else if (!enabled && canvasActive) {
    if (originalToDataURL) {
      HTMLCanvasElement.prototype.toDataURL = originalToDataURL;
      originalToDataURL = null;
    }
    if (originalGetImageData) {
      CanvasRenderingContext2D.prototype.getImageData = originalGetImageData;
      originalGetImageData = null;
    }
    canvasActive = false;
  }
}

export function getAppliedProtections(): { webrtc: boolean; timezone: boolean; canvas: boolean } {
  return {
    webrtc: webrtcActive,
    timezone: timezoneActive,
    canvas: canvasActive,
  };
}

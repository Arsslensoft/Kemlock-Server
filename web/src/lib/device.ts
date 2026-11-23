// What this browser calls itself to the server, and the device id it keeps between sign-ins.
import type { DeviceDto } from '@/api/types';

const KEY = 'kemlock.deviceId';

export function getDeviceId(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function rememberDeviceId(id: string): void {
  try {
    localStorage.setItem(KEY, id);
  } catch {
    // Storage is blocked: the server just makes a new device next time.
  }
}

/** "Firefox on Linux", from the user agent: good enough for a device list. */
export function browserName(userAgent: string = navigator.userAgent): string {
  const browser = /Edg\//.test(userAgent)
    ? 'Edge'
    : /Firefox\//.test(userAgent)
      ? 'Firefox'
      : /Chrome\//.test(userAgent)
        ? 'Chrome'
        : /Safari\//.test(userAgent)
          ? 'Safari'
          : 'a browser';
  const system = /Windows/.test(userAgent)
    ? 'Windows'
    : /Android/.test(userAgent)
      ? 'Android'
      : /iPhone|iPad/.test(userAgent)
        ? 'iOS'
        : /Mac OS X/.test(userAgent)
          ? 'macOS'
          : /Linux/.test(userAgent)
            ? 'Linux'
            : null;
  return system ? `${browser} on ${system}` : browser;
}

export function thisDevice(): DeviceDto {
  return { id: getDeviceId(), name: `Web vault, ${browserName()}`, kind: 'kemlock-web' };
}

/**
 * DeviceSecurityService — best-effort tamper signals from the native DeviceSecurity module.
 *
 * These are heuristics: a root/Frida attacker who targets this app can hide every one of
 * them. They raise the bar and inform the user; they are not a security boundary.
 *   critical: debugger/tracer attached, Frida artefacts, debuggable release build
 *   warning : su binary / root-manager package present, or native module missing in release
 */

import { NativeModules } from 'react-native';

export interface SecurityStatus {
  isSecure: boolean;
  detectedTampering: boolean;
  detectionMethod: string | null;
  securityLevel: 'secure' | 'warning' | 'critical';
}

let compromised = false;

async function safe<T>(fn: (() => Promise<T>) | undefined, fallback: T): Promise<T> {
  try {
    return fn ? await fn() : fallback;
  } catch {
    return fallback;
  }
}

export class DeviceSecurityService {
  static async checkDeviceSecurity(): Promise<SecurityStatus> {
    const ds = (NativeModules as any).DeviceSecurity;
    if (!ds) {
      const isDev = typeof __DEV__ !== 'undefined' && __DEV__;
      return {
        isSecure: isDev,
        detectedTampering: false,
        detectionMethod: isDev ? null : 'native_module_missing',
        securityLevel: isDev ? 'secure' : 'warning',
      };
    }

    const [tracer, frida, debuggable, su, rootPkg] = await Promise.all([
      safe<number>(ds.getTracerPid ? () => ds.getTracerPid() : undefined, 0),
      safe<string[]>(ds.checkFridaModules ? () => ds.checkFridaModules() : undefined, []),
      safe<boolean>(ds.checkDebuggable ? () => ds.checkDebuggable() : undefined, false),
      safe<boolean>(ds.checkSuBinary ? () => ds.checkSuBinary() : undefined, false),
      safe<boolean>(ds.checkRootKeysInPackage ? () => ds.checkRootKeysInPackage() : undefined, false),
    ]);
    const isDev = typeof __DEV__ !== 'undefined' && __DEV__;

    const critical: string[] = [];
    if (tracer && tracer !== 0) critical.push('tracer_attached');
    if (Array.isArray(frida) && frida.length > 0) critical.push(...frida);
    if (debuggable && !isDev) critical.push('debuggable_release');
    const warning: string[] = [];
    if (su) warning.push('su_binary');
    if (rootPkg) warning.push('root_package');

    const level = critical.length ? 'critical' : warning.length ? 'warning' : 'secure';
    if (level !== 'secure') compromised = true;
    return {
      isSecure: level === 'secure',
      detectedTampering: level !== 'secure',
      detectionMethod: [...critical, ...warning].join(',') || null,
      securityLevel: level,
    };
  }

  /** True if any check flagged this process since start (or since the last reset). */
  static async wasCompromised(): Promise<boolean> {
    return compromised;
  }

  static async resetSecurityChecks(): Promise<void> {
    compromised = false;
  }
}

export default DeviceSecurityService;

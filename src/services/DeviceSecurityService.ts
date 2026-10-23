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

// A native check that THROWS (or is stripped from a present module) is an unknown, not a pass:
// hooking a check to reject must not read as "clean". Recorded as a warning-level indicator.
let failedChecks: string[] = [];

async function safe<T>(name: string, fn: (() => Promise<T>) | undefined, fallback: T): Promise<T> {
  if (!fn) { failedChecks.push(`${name}_unavailable`); return fallback; }
  try {
    return await fn();
  } catch {
    failedChecks.push(`${name}_failed`);
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

    failedChecks = [];
    const [tracer, frida, debuggable, su, rootPkg] = await Promise.all([
      safe<number>('getTracerPid', ds.getTracerPid ? () => ds.getTracerPid() : undefined, 0),
      safe<string[]>('checkFridaModules', ds.checkFridaModules ? () => ds.checkFridaModules() : undefined, []),
      safe<boolean>('checkDebuggable', ds.checkDebuggable ? () => ds.checkDebuggable() : undefined, false),
      safe<boolean>('checkSuBinary', ds.checkSuBinary ? () => ds.checkSuBinary() : undefined, false),
      safe<boolean>('checkRootKeysInPackage', ds.checkRootKeysInPackage ? () => ds.checkRootKeysInPackage() : undefined, false),
    ]);
    const isDev = typeof __DEV__ !== 'undefined' && __DEV__;

    const critical: string[] = [];
    if (tracer && tracer !== 0) critical.push('tracer_attached');
    if (Array.isArray(frida)) {
      if (frida.length > 0) critical.push(...frida.map(String));
    } else if (frida) {
      critical.push('frida_forged_result'); // truthy non-array = malformed/forged native result
    }
    if (debuggable && !isDev) critical.push('debuggable_release');
    const warning: string[] = [];
    if (su) warning.push('su_binary');
    if (rootPkg) warning.push('root_package');
    warning.push(...failedChecks);

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

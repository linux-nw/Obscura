/**
 * DeviceSecurityService — Anti-Tampering stubs.
 *
 * NOT_IMPLEMENTED: All detection methods (root, jailbreak, Frida, debugger)
 * require native modules for meaningful results.
 *
 * Current status: all checks return 'secure' unconditionally.
 * A future native implementation should check:
 *   Android: /system/bin/su, /system/app/Superuser.apk, TracerPid, Frida port 27042
 *   iOS:     Cydia.app, ptrace(PT_DENY_ATTACH), UIDevice.isJailbroken
 *
 * WARNING: Do NOT add heuristic JS-only checks here — they are trivially
 * bypassable and may cause false positives that lock legitimate users out.
 */

export interface SecurityStatus {
  isSecure: boolean;
  detectedTampering: boolean;
  detectionMethod: string | null;
  securityLevel: 'secure' | 'warning' | 'critical';
}

export class DeviceSecurityService {
  /**
   * Returns a 'secure' status unconditionally until native checks are implemented.
   */
  static async checkDeviceSecurity(): Promise<SecurityStatus> {
    return {
      isSecure: true,
      detectedTampering: false,
      detectionMethod: null,
      securityLevel: 'secure',
    };
  }

  /** Always false until native checks are implemented. */
  static async wasCompromised(): Promise<boolean> {
    return false;
  }

  static async resetSecurityChecks(): Promise<void> {
    // no-op until native checks are implemented
  }
}

export default DeviceSecurityService;

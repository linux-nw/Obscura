/**
 * Services Export
 * Zentraler Export für alle Sicherheits- und Data Services
 */

// Crypto Services
export { XChaCha20CryptoService } from './XChaCha20CryptoService';
export { SecureCryptoService } from './CryptoService';

// Storage Services
export { FileManager } from './FileManager';
export { NotesService } from './NotesService';

// Security Services
export { DeviceSecurityService } from './DeviceSecurityService';
export { IntegrityService } from './IntegrityService';
export { ScreenProtectionService } from './ScreenProtectionService';
export { AutoLockService } from './AutoLockService';
export { PanicService } from './PanicService';
export { DecoyVaultService } from './DecoyVaultService';

// Memory Safety
export { MemoryProtection, SafeBuffer, ZeroingArrayBuffer } from './MemorySafetyService';

// Backup & Rotation
export { BackupService } from './BackupService';
export { KeyRotationService } from './KeyRotationService';

// Secure Delete
export { SecureDeleteService } from './SecureDeleteService';

// Penetration Testing
export { PenTestService } from './PenTestService';

// Types
export interface VaultConfig {
  autoLockTimeoutSeconds: number;
  keyRotationIntervalDays: number;
  secureDeleteMethod: 'quick' | 'dod' | 'guttman';
  enableScreenProtection: boolean;
  enableDecoyVault: boolean;
  enableKeyRotation: boolean;
}

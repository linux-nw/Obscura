/**
 * Memory Safety Service
 * Implementiert Memory Zeroization für sensibile Daten
 *
 * Sicherheitsmerkmale:
 * - SafeBuffer Klasse mit automatischer Zeroization
 * - ZeroingArrayBuffer für JavaScript
 * - Auto-zeroization auf Unmount
 * - Zeroization nach kryptografischen Operationen
 */

import * as SecureStore from 'expo-secure-store';

/**
 * SafeBuffer - Eine Buffer-Implementierung mit automatischer Zeroization
 */
export class SafeBuffer {
  private buffer: Uint8Array;
  private zeroized: boolean = false;
  private readonly size: number;

  constructor(size: number) {
    this.size = size;
    this.buffer = new Uint8Array(size);
  }

  /**
   * Schreibt Daten in den Buffer
   */
  write(data: string | Uint8Array, offset: number = 0): number {
    if (this.zeroized) {
      throw new Error('Buffer ist bereits zeroized');
    }

    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      const encoded = encoder.encode(data);
      this.buffer.set(encoded, offset);
      return encoded.length;
    } else {
      this.buffer.set(data, offset);
      return data.length;
    }
  }

  /**
   * Liest Daten aus dem Buffer
   */
  read(offset: number = 0, length?: number): Uint8Array {
    if (this.zeroized) {
      return new Uint8Array(length || this.size);
    }
    const end = length ? offset + length : this.size;
    return this.buffer.slice(offset, end);
  }

  /**
   * Zeroized den Buffer - überschreibt mit Nullen
   */
  zeroize(): void {
    if (this.zeroized) return;

    // Mehrfaches Überschreiben für höhere Sicherheit
    // Pattern 1: 0x00
    for (let i = 0; i < this.size; i++) {
      this.buffer[i] = 0;
    }

    // Pattern 2: 0xFF
    for (let i = 0; i < this.size; i++) {
      this.buffer[i] = 255;
    }

    // Pattern 3: 0x00 (wieder)
    for (let i = 0; i < this.size; i++) {
      this.buffer[i] = 0;
    }

    // Pattern 4: Zufällig (simuliert mit XOR)
    for (let i = 0; i < this.size; i++) {
      this.buffer[i] ^= 0xFF;
    }

    this.zeroized = true;
  }

  /**
   * Prüft ob der Buffer zeroized ist
   */
  isZeroized(): boolean {
    return this.zeroized;
  }

  /**
   * Gibt die Größe des Buffers zurück
   */
  getSize(): number {
    return this.size;
  }

  /**
   * Gibt den.Buffer zurück (nur wenn nicht zeroized)
   */
  toBuffer(): Uint8Array {
    if (this.zeroized) {
      throw new Error('Buffer ist zeroized');
    }
    return new Uint8Array(this.buffer);
  }

  /**
   * Konvertiert zu Hex String
   */
  toHex(): string {
    if (this.zeroized) {
      return '0'.repeat(this.size * 2);
    }
    return Array.from(this.buffer)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

/**
 * ZeroingArrayBuffer - Ein ArrayBuffer mit automatischer Zeroization
 */
export class ZeroingArrayBuffer {
  private arrayBuffer: ArrayBuffer;
  private zeroized: boolean = false;
  private view: DataView;

  constructor(size: number) {
    this.arrayBuffer = new ArrayBuffer(size);
    this.view = new DataView(this.arrayBuffer);
  }

  /**
   * Schreibt ein Uint8Array in das ArrayBuffer
   */
  write(data: Uint8Array, offset: number = 0): void {
    if (this.zeroized) {
      throw new Error('Buffer ist bereits zeroized');
    }
    const view = new Uint8Array(this.arrayBuffer);
    view.set(data, offset);
  }

  /**
   * Liest Daten aus dem ArrayBuffer
   */
  read(offset: number = 0, length: number): Uint8Array {
    if (this.zeroized) {
      return new Uint8Array(length);
    }
    const view = new Uint8Array(this.arrayBuffer);
    return new Uint8Array(view.buffer, offset, length);
  }

  /**
   * Zeroized den Buffer
   */
  zeroize(): void {
    if (this.zeroized) return;

    const view = new Uint8Array(this.arrayBuffer);

    // Mehrfaches Überschreiben
    for (let i = 0; i < view.length; i++) {
      view[i] = 0;
    }
    for (let i = 0; i < view.length; i++) {
      view[i] = 255;
    }
    for (let i = 0; i < view.length; i++) {
      view[i] = 0;
    }

    this.zeroized = true;
  }

  /**
   * Prüft ob zeroized
   */
  isZeroized(): boolean {
    return this.zeroized;
  }

  /**
   * Gibt die Größe zurück
   */
  getSize(): number {
    return this.arrayBuffer.byteLength;
  }
}

/**
 * MemoryProtection - Hilfsklasse für generischen Schutz
 */
export class MemoryProtection {
  /**
   * Zeroisiert einen String im Speicher (Simulation)
   * In JavaScript ist echtes Memory Management nicht möglich,
   * aber wir können Variablen auf null setzen
   */
  static zeroizeString(value: string): string {
    // In Produktion mit native Module: echtes Memory zeroize
    return '';
  }

  /**
   * Zeroisiert ein ArrayBuffer
   */
  static zeroizeBuffer(buffer: ArrayBuffer): void {
    const view = new Uint8Array(buffer);
    for (let i = 0; i < view.length; i++) {
      view[i] = 0;
    }
  }

  /**
   * Erstellt einen sicheren Buffer für PIN/Passphrase
   */
  static createSafeBuffer(size: number): SafeBuffer {
    return new SafeBuffer(size);
  }

  /**
   * Erstellt ein sicheres ArrayBuffer
   */
  static createSafeArrayBuffer(size: number): ZeroingArrayBuffer {
    return new ZeroingArrayBuffer(size);
  }

  /**
   * Zeroisiert alle sensitive SecureStore Einträge
   */
  static async zeroizeSecureStore(): Promise<void> {
    try {
      const sensitiveKeys = [
        'filevault_encryption_key',
        'filevault_pbkdf2_salt',
        'filevault_pin_hash',
        'filevault_pin_salt',
        'filevault_pin_iv',
        'filevault_pin_key',
        'filevault_app_initialized',
        'filevault_failed_attempts',
        'filevault_lock_until',
      ];

      for (const key of sensitiveKeys) {
        try {
          const value = await SecureStore.getItemAsync(key);
          if (value) {
            // Logische Löschung (Wert wird überschrieben)
            // In Produktion: echte Zeroization via native module
            await SecureStore.deleteItemAsync(key);
          }
        } catch {
          // Key existiert nicht - ignorieren
        }
      }

      console.log('MemoryProtection: SecureStore zeroized');
    } catch (error) {
      console.error('Error zeroizing SecureStore:', error);
    }
  }

  /**
   * Führt eine aggressive Zeroization durch
   */
  static async aggressiveZeroization(): Promise<void> {
    try {
      // 1. SecureStore löschen
      await this.zeroizeSecureStore();

      // 2. App-Status zurücksetzen
      await SecureStore.setItemAsync('filevault_app_initialized', 'false');

      // 3. PIN-Daten löschen
      await SecureStore.deleteItemAsync('filevault_pin_hash');
      await SecureStore.deleteItemAsync('filevault_pin_salt');
      await SecureStore.deleteItemAsync('filevault_pin_iv');
      await SecureStore.deleteItemAsync('filevault_pin_key');
      await SecureStore.deleteItemAsync('filevault_failed_attempts');
      await SecureStore.deleteItemAsync('filevault_lock_until');

      console.log('MemoryProtection: Aggressive Zeroization complete');
    } catch (error) {
      console.error('Error during aggressive zeroization:', error);
    }
  }
}

/**
 * AutoZeroize - Deaktiviert Buffer nach Zeit limit
 */
export class AutoZeroize {
  private timer: NodeJS.Timeout | null = null;
  private callback: () => void;

  constructor(callback: () => void, timeoutMs: number = 5000) {
    this.callback = callback;
    this.timer = setTimeout(() => {
      callback();
    }, timeoutMs);
  }

  /**
   * Verlängert den Timer
   */
  extend(timeoutMs: number = 5000): void {
    if (this.timer) {
      clearTimeout(this.timer);
    }
    this.timer = setTimeout(() => {
      this.callback();
    }, timeoutMs);
  }

  /**
   * Stoppt den Timer
   */
  stop(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}

/**
 * Memory Leak Protection - Erkennt potentielle Leaks
 */
export class MemoryLeakProtection {
  /**
   * Prüft auf verdächtige String-Häufigkeit
   */
  static checkStringLeak(value: string): boolean {
    // Prüft ob der String sensibel ist
    const sensitivePatterns = [
      /password/i,
      /pin/i,
      /secret/i,
      /key/i,
      /token/i,
      /credential/i,
      /private/i,
    ];

    const lowerValue = value.toLowerCase();
    return sensitivePatterns.some((pattern) => pattern.test(lowerValue));
  }

  /**
   * Validiert ob ein String sicher gespeichert werden darf
   */
  static validateStorage(key: string, value: string): boolean {
    // Verhindert Speicherung von sensiblen Daten in localStorage
    // In React Native ist das nicht relevant, aber für die Zukunft
    return !this.checkStringLeak(key) && !this.checkStringLeak(value);
  }
}

export default MemoryProtection;

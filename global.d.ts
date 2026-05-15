// Globale TypeScript-Definitionen für Expo SDK 54+

declare module 'expo-file-system' {
  export const documentDirectory: string | null;
  export function getInfoAsync(fileUri: string): Promise<{ exists: boolean; isDirectory?: boolean }>;
  export function readDirectoryAsync(fileUri: string): Promise<string[]>;
  export function makeDirectoryAsync(fileUri: string, options?: { intermediates: boolean }): Promise<void>;
  export function readAsStringAsync(fileUri: string, options?: { encoding: 'utf8' | 'base64' }): Promise<string>;
  export function writeAsStringAsync(fileUri: string, contents: string): Promise<void>;
  export function deleteAsync(fileUri: string): Promise<void>;
  export const cacheDirectory: string | null;
}

declare module 'expo-local-authentication' {
  export function hasHardwareAsync(): Promise<boolean>;
  export function isEnrolledAsync(): Promise<boolean>;
  export function authenticateAsync(options?: {
    promptMessage?: string;
    fallbackLabel?: string;
  }): Promise<{ success: boolean }>;
}

declare module 'expo-document-picker' {
  export function getDocumentAsync(options?: {
    type?: string;
    copyToCacheDirectory?: boolean;
  }): Promise<{
    assets?: Array<{ uri: string; name: string }>;
    canceled?: boolean;
  }>;
}

declare module 'expo-image-picker' {
  export function requestMediaLibraryPermissionsAsync(): Promise<{ granted: boolean }>;
  export function launchImageLibraryAsync(options?: {
    mediaTypes?: any;
    allowsEditing?: boolean;
    quality?: number;
  }): Promise<{
    assets?: Array<{ uri: string; fileName?: string }>;
    canceled?: boolean;
  }>;

  export const MediaTypeOptions: any;
}

// crypto-js Typ-Definitionen
declare module 'crypto-js' {
  export namespace enc {
    const Utf8: {
      parse(str: string): any;
      stringify(words: any): string;
    };
    const Hex: {
      parse(str: string): any;
      stringify(words: any): string;
    };
    const Base64: {
      parse(str: string): any;
      stringify(words: any): string;
    };
  }

  export namespace lib {
    class WordArray {
      constructor(words?: any[], sigBytes?: number);
      static create(words: ArrayBuffer | number[], sigBytes?: number): WordArray;
      concat(words: WordArray): WordArray;
      clone(): WordArray;
      sigBytes: number;
      words: number[];
      toString(encoder?: any): string;
    }

    class CipherParams {
      constructor(options: any);
      ciphertext: WordArray;
      key: WordArray;
      iv: WordArray;
      salt: WordArray;
      static create(options: any): CipherParams;
    }
  }

  export namespace mode {
    const CBC: any;
  }

  export namespace pad {
    const Pkcs7: any;
  }

  export namespace format {
    const Hex: {
      stringify(cipherParams: any): string;
      parse(input: string): any;
    };
  }

  export const AES: {
    encrypt(plaintext: any, key: any, options?: any): {
      ciphertext: any;
      key: any;
      iv: any;
      salt: any;
      decrypt: (key: any, options?: any) => any;
      toString: (converter?: any) => string;
    };
    decrypt(ciphertext: any, key: any, options?: any): any;
  };

  export namespace algo {
    const SHA256: any;
    const SHA512: any;
    const MD5: any;
  }

  export namespace mode {
    const CBC: any;
    const CFB: any;
    const CTR: any;
    const OFB: any;
    const ECB: any;
  }

  export namespace pad {
    const Pkcs7: any;
    const AnsiX923: any;
    const Iso10126: any;
    const Iso97971: any;
    const NoPadding: any;
    const ZeroPadding: any;
  }

  export const PBKDF2: (password: any, salt: any, cfg?: any) => any;
  export const HmacSHA256: (message: any, key: any) => any;
  export const SHA256: (message: any) => any;
}

// Globale Browser-Funktionen für React Native
declare function btoa(data: string): string;
declare function atob(data: string): string;

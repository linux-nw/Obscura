// Legacy Encryption Service für Kompatibilität mit alten Dateien
// Wird nur für Migration von Base64-verschlüsselten Dateien verwendet

class LegacyEncryptionService {
  static async encryptData(_data: string): Promise<string> {
    // Base64 is encoding, not encryption: never produce new "ciphertext" with it.
    throw new Error('Legacy-Verschlüsselung ist deaktiviert');
  }

  static async decryptData(encryptedData: string): Promise<string> {
    try {
      // Einfache Base64-Entschlüsselung (nur für Migration)
      return decodeURIComponent(escape(atob(encryptedData)));
    } catch {
      throw new Error('Legacy-Entschlüsselung fehlgeschlagen');
    }
  }

  static async encryptFile(_fileData: string): Promise<{ encryptedData: string; iv: string }> {
    throw new Error('Legacy-Verschlüsselung ist deaktiviert');
  }

  static async decryptFile(encryptedData: string, _iv: string): Promise<string> {
    try {
      return await this.decryptData(encryptedData);
    } catch {
      throw new Error('Legacy-Dateientschlüsselung fehlgeschlagen');
    }
  }
}

export default LegacyEncryptionService;
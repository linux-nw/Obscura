// Legacy Encryption Service für Kompatibilität mit alten Dateien
// Wird nur für Migration von Base64-verschlüsselten Dateien verwendet

class LegacyEncryptionService {
  static async encryptData(data: string): Promise<string> {
    try {
      // Einfache Base64-Verschlüsselung (nur für Migration)
      return btoa(unescape(encodeURIComponent(data)));
    } catch (error) {
      console.error('Legacy encryption error:', error);
      throw new Error('Legacy-Verschlüsselung fehlgeschlagen');
    }
  }

  static async decryptData(encryptedData: string): Promise<string> {
    try {
      // Einfache Base64-Entschlüsselung (nur für Migration)
      return decodeURIComponent(escape(atob(encryptedData)));
    } catch (error) {
      console.error('Legacy decryption error:', error);
      throw new Error('Legacy-Entschlüsselung fehlgeschlagen');
    }
  }

  static async encryptFile(fileData: string): Promise<{ encryptedData: string; iv: string }> {
    try {
      const encryptedData = await this.encryptData(fileData);
      return {
        encryptedData,
        iv: 'legacy-iv', // Für Kompatibilität
      };
    } catch (error) {
      console.error('Legacy file encryption error:', error);
      throw new Error('Legacy-Dateiverschlüsselung fehlgeschlagen');
    }
  }

  static async decryptFile(encryptedData: string, iv: string): Promise<string> {
    try {
      return await this.decryptData(encryptedData);
    } catch (error) {
      console.error('Legacy file decryption error:', error);
      throw new Error('Legacy-Dateientschlüsselung fehlgeschlagen');
    }
  }
}

export default LegacyEncryptionService;
# FileVault - Privater Datei-Tresor

Eine sichere React Native/Expo App für Android, die private Dateien (Fotos, Videos, Dokumente) in einem verschlüsselten, versteckten Bereich speichert.

## Features

- 🔐 **Sichere Authentifizierung**: PIN-Eingabe + Fingerprint-Support
- 🔒 **Verschlüsselung**: Alle Dateien werden lokal mit AES-256 verschlüsselt
- 📁 **Datei-Import**: Aus Galerie oder Dateisystem
- 👀 **Versteckter Speicher**: Dateien erscheinen nicht in der normalen Galerie
- 💾 **100% lokal**: Keine Cloud-Synchronisation
- 🎨 **Modernes Design**: Dunkles Theme, minimalistisches Interface
- ⚡ **Performance**: Schnelle Verschlüsselung/Entschlüsselung

## Technischer Stack

- React Native mit Expo
- TypeScript
- expo-file-system (Dateioperationen)
- expo-local-authentication (Biometrie)
- expo-document-picker (Dokumentenauswahl)
- expo-image-picker (Bilderauswahl)
- crypto-js (Verschlüsselung)
- expo-secure-store (Schlüsselspeicherung)

## Installation

1. Repository klonen:
```bash
git clone <repository-url>
cd FileVault
```

2. Abhängigkeiten installieren:
```bash
npm install
```

3. App starten:
```bash
npm run android
```

## Verwendung

### Ersteinrichtung
1. Beim ersten Start wird eine PIN abgefragt
2. PIN muss mindestens 4-stellig sein
3. Biometrische Authentifizierung kann eingerichtet werden

### Dateien importieren
1. App entsperren
2. "+ Datei importieren" drücken
3. Quelle wählen (Galerie oder Dokumente)
4. Datei auswählen - wird automatisch verschlüsselt gespeichert

### Dateien exportieren
1. Auf Export-Button (📤) neben der Datei drücken
2. Datei wird entschlüsselt und im Cache-Verzeichnis gespeichert

### Dateien löschen
1. Auf Löschen-Button (🗑️) neben der Datei drücken
2. Bestätigung abwarten

## Sicherheit

- **Verschlüsselung**: AES-256 mit CBC-Modus und PKCS7-Padding
- **Schlüsselverwaltung**: Schlüssel wird sicher in expo-secure-store gespeichert
- **Isolation**: Dateien sind in app-internem Verzeichnis gespeichert
- **Biometrie**: Unterstützung für Fingerprint/Face ID

## Projektstruktur

```
FileVault/
├── src/
│   ├── screens/
│   │   ├── AuthScreen.tsx      # Authentifizierungs-UI
│   │   └── MainScreenV2.tsx    # Haupt-UI mit Dateiverwaltung
│   ├── services/
│   │   ├── EncryptionService.ts # Verschlüsselungslogik
│   │   └── FileManager.ts      # Dateimanagement
├── App.tsx                     # Hauptkomponente
├── app.json                    # Expo Konfiguration
└── tsconfig.json              # TypeScript Konfiguration
```

## Entwicklung

### Wichtige Befehle

```bash
# Development Server starten
npm start

# Android build
npm run android

# iOS build (nur auf macOS)
npm run ios

# TypeScript prüfen
npx tsc --noEmit
```

### Hinzufügen neuer Features

1. **Neue Screens**: In `/src/screens/` erstellen
2. **Services**: In `/src/services/` für Geschäftslogik
3. **Komponenten**: Für wiederverwendbare UI-Elemente

## Build & Deployment

### Android

1. Expo Build erstellen:
```bash
expo build:android
```

2. Oder lokal bauen:
```bash
npm run android
```

### Produktions-Hinweise

- **Schlüsselmanagement**: In Produktion Secure Storage Service verwenden
- **Verschlüsselung**: Hardware-basierte Verschlüsselung für bessere Sicherheit
- **Backup**: Lokale Backup-Lösung implementieren
- **Monitoring**: Error Tracking einrichten

## Lizenz

MIT License - siehe LICENSE Datei für Details.

## Beitrag

Beiträge sind willkommen! Bitte erstellen Sie einen Pull Request oder issue für Verbesserungen.

## Support

Bei Fragen oder Problemen:
1. Issues auf GitHub öffnen
2. Dokumentation durchlesen
3. Expo Dokumentation konsultieren
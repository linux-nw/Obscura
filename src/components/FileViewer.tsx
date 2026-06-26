import React, { useEffect, useRef, useState } from 'react';
import {
  View, Text, Image, ScrollView, StyleSheet, Modal,
  ActivityIndicator, TouchableOpacity, Dimensions,
} from 'react-native';
import { FileManager, FileMetadata } from '../services/FileManager';
import Icon from './Icon';
import { c, rs, font, radius } from '../theme';

// expo-video / expo-sharing sind native Module. Sie werden LAZY geladen, damit die
// App auch dann baut und läuft, wenn sie (noch) nicht installiert sind — dann zeigt
// der Viewer für diese Typen einen Hinweis statt zu crashen.
const expoVideo: any = (() => { try { return require('expo-video'); } catch { return null; } })();
const expoSharing: any = (() => { try { return require('expo-sharing'); } catch { return null; } })();

// ─────────────────────────────── Typ-Erkennung ───────────────────────────────

type ViewerKind = 'image' | 'text' | 'av' | 'external';

const IMAGE_EXTS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic', 'heif']);
const AV_EXTS    = new Set(['mp4', 'mov', 'mkv', 'webm', 'avi', 'm4v', '3gp', 'mp3', 'm4a', 'aac', 'wav', 'ogg', 'oga', 'flac']);
const TEXT_EXTS  = new Set([
  'txt', 'md', 'markdown', 'json', 'csv', 'tsv', 'log', 'xml', 'html', 'htm',
  'js', 'jsx', 'ts', 'tsx', 'css', 'scss', 'yaml', 'yml', 'ini', 'conf', 'cfg',
  'sh', 'bash', 'py', 'java', 'kt', 'kts', 'c', 'cpp', 'cc', 'h', 'hpp', 'rb',
  'go', 'rs', 'php', 'sql', 'toml', 'env', 'gradle', 'properties',
]);

const MAX_TEXT_BYTES = 512 * 1024; // große Dateien nicht komplett rendern

function extOf(name: string): string {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(name || '');
  return m ? m[1].toLowerCase() : '';
}

function kindForFile(file: FileMetadata): ViewerKind {
  const ext = extOf(file.originalName);
  if (file.type === 'image' || IMAGE_EXTS.has(ext)) return 'image';
  if (file.type === 'video' || AV_EXTS.has(ext))    return 'av';
  if (TEXT_EXTS.has(ext))                            return 'text';
  return 'external';
}

function imageMime(ext: string): string {
  switch (ext) {
    case 'png':  return 'image/png';
    case 'gif':  return 'image/gif';
    case 'webp': return 'image/webp';
    case 'bmp':  return 'image/bmp';
    case 'heic':
    case 'heif': return 'image/heic';
    default:     return 'image/jpeg';
  }
}

function isAudioExt(ext: string): boolean {
  return ['mp3', 'm4a', 'aac', 'wav', 'ogg', 'oga', 'flac'].includes(ext);
}

function base64ToUtf8(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// ─────────────────────────────── AV Sub-Player ───────────────────────────────
// Eigene Komponente, weil useVideoPlayer ein Hook ist. Wird NUR gerendert, wenn
// expo-video geladen ist → der Hook wird konsistent aufgerufen (Rules of Hooks).

function AVPlayer({ uri, audio }: { uri: string; audio: boolean }) {
  const player = expoVideo.useVideoPlayer(uri, (p: any) => {
    p.loop = false;
    p.play();
  });
  return (
    <View style={s.avWrap}>
      {audio && <Text style={s.avLabel}>🎵 Audio</Text>}
      <expoVideo.VideoView
        player={player}
        style={audio ? s.audioView : s.videoView}
        contentFit="contain"
        allowsFullscreen
        nativeControls
      />
    </View>
  );
}

// ─────────────────────────────── FileViewer ───────────────────────────────

interface Props {
  file: FileMetadata | null;
  onClose: () => void;
}

export default function FileViewer({ file, onClose }: Props) {
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const [imageUri, setImageUri] = useState<string | null>(null);
  const [text, setText]         = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [tempUri, setTempUri]   = useState<string | null>(null);

  // Temp-Datei (Klartext im Cache) beim Schließen IMMER löschen.
  const tempRef = useRef<string | null>(null);
  tempRef.current = tempUri;

  useEffect(() => {
    let cancelled = false;
    // Reset
    setImageUri(null); setText(null); setError(null); setTruncated(false);
    setTempUri(null);

    if (!file) return;

    const kind = kindForFile(file);
    const ext = extOf(file.originalName);

    (async () => {
      setLoading(true);
      try {
        if (kind === 'image') {
          const b64 = await FileManager.getFileContent(file.id);
          if (cancelled) return;
          setImageUri(`data:${imageMime(ext)};base64,${b64}`);
        } else if (kind === 'text') {
          const b64 = await FileManager.getFileContent(file.id);
          if (cancelled) return;
          // base64 → bytes-Länge ~ 3/4 der b64-Länge
          const approxBytes = Math.floor((b64.length * 3) / 4);
          const decoded = base64ToUtf8(b64);
          if (approxBytes > MAX_TEXT_BYTES) {
            setText(decoded.slice(0, MAX_TEXT_BYTES));
            setTruncated(true);
          } else {
            setText(decoded);
          }
        } else {
          // av / external → Klartext-Tempdatei erzeugen
          const uri = await FileManager.exportToTempFile(file.id);
          if (cancelled) { await FileManager.deleteTempFile(uri); return; }
          setTempUri(uri);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      const t = tempRef.current;
      if (t) FileManager.deleteTempFile(t);
    };
  }, [file?.id]);

  const handleClose = () => {
    const t = tempRef.current;
    if (t) FileManager.deleteTempFile(t);
    onClose();
  };

  const handleShareExternal = async () => {
    if (!tempUri) return;
    if (!expoSharing || !(await expoSharing.isAvailableAsync().catch(() => false))) {
      setError('Teilen ist auf diesem Gerät nicht verfügbar.');
      return;
    }
    try {
      await expoSharing.shareAsync(tempUri);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  if (!file) return null;

  const kind = kindForFile(file);
  const ext  = extOf(file.originalName);

  return (
    <Modal visible transparent animationType="fade" onRequestClose={handleClose}>
      <View style={s.root}>
        {/* Header */}
        <View style={s.header}>
          <Text style={s.title} numberOfLines={1}>{file.originalName}</Text>
          <TouchableOpacity onPress={handleClose} style={s.closeBtn} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
            <Icon name="x" size={rs(18)} color={c.text} />
          </TouchableOpacity>
        </View>

        {/* Body */}
        <View style={s.body}>
          {loading && (
            <View style={s.center}>
              <ActivityIndicator size="large" color={c.accent} />
              <Text style={s.hint}>Wird entschlüsselt …</Text>
            </View>
          )}

          {!loading && error && (
            <View style={s.center}>
              <Icon name="alert-triangle" size={rs(36)} color={c.danger} stroke={1.5} />
              <Text style={s.errTxt}>{error}</Text>
            </View>
          )}

          {!loading && !error && kind === 'image' && imageUri && (
            <Image source={{ uri: imageUri }} style={s.image} resizeMode="contain" />
          )}

          {!loading && !error && kind === 'text' && text !== null && (
            <ScrollView style={s.textScroll} contentContainerStyle={s.textContent}>
              <Text style={s.textBody} selectable>{text}</Text>
              {truncated && (
                <Text style={s.truncated}>… Datei gekürzt (Vorschau begrenzt auf 512 KB)</Text>
              )}
            </ScrollView>
          )}

          {!loading && !error && kind === 'av' && tempUri && (
            expoVideo
              ? <AVPlayer uri={tempUri} audio={isAudioExt(ext)} />
              : <ModuleHint type="Video/Audio" pkg="expo-video" onExternal={expoSharing ? handleShareExternal : undefined} />
          )}

          {!loading && !error && kind === 'external' && tempUri && (
            <View style={s.center}>
              <View style={s.extMark}>
                <Icon name="file" size={rs(34)} color={c.accent} stroke={1.4} />
              </View>
              <Text style={s.extTitle}>{ext ? ext.toUpperCase() : 'Datei'}</Text>
              <Text style={s.hint}>
                Für diesen Dateityp gibt es keinen eingebauten Viewer.
              </Text>
              {expoSharing ? (
                <>
                  <TouchableOpacity style={s.extBtn} onPress={handleShareExternal} activeOpacity={0.85}>
                    <Text style={s.extBtnTxt}>In anderer App öffnen</Text>
                  </TouchableOpacity>
                  <Text style={s.warn}>
                    Achtung: Dabei wird eine entschlüsselte Kopie an die gewählte App
                    übergeben — der Inhalt verlässt damit den Tresor.
                  </Text>
                </>
              ) : (
                <Text style={s.warn}>Modul „expo-sharing“ nicht installiert.</Text>
              )}
            </View>
          )}
        </View>
      </View>
    </Modal>
  );
}

function ModuleHint({ type, pkg, onExternal }: { type: string; pkg: string; onExternal?: () => void }) {
  return (
    <View style={s.center}>
      <View style={s.extMark}>
        <Icon name="file" size={rs(34)} color={c.accent} stroke={1.4} />
      </View>
      <Text style={s.hint}>{type}-Wiedergabe benötigt das Modul „{pkg}“.</Text>
      <Text style={s.warn}>Installieren mit „npx expo install {pkg}“ und neu bauen.</Text>
      {onExternal && (
        <TouchableOpacity style={s.extBtn} onPress={onExternal} activeOpacity={0.85}>
          <Text style={s.extBtnTxt}>In anderer App öffnen</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

const { width: W, height: H } = Dimensions.get('window');

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: 'rgba(0,0,0,0.96)' },
  header: {
    flexDirection: 'row', alignItems: 'center',
    paddingTop: rs(50), paddingBottom: rs(12), paddingHorizontal: rs(16),
    borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: c.sep,
  },
  title: { flex: 1, fontFamily: font.mono, fontSize: rs(13), color: c.text, letterSpacing: rs(0.3) },
  closeBtn: {
    width: rs(34), height: rs(34), borderRadius: radius.btn,
    borderWidth: 1, borderColor: c.border2,
    alignItems: 'center', justifyContent: 'center', marginLeft: rs(12),
  },
  body: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  center: { alignItems: 'center', justifyContent: 'center', padding: rs(28) },
  hint: { fontFamily: font.sans, fontSize: rs(14), color: c.textSec, marginTop: rs(14), textAlign: 'center' },
  image: { width: W, height: H * 0.8 },
  textScroll: { flex: 1, alignSelf: 'stretch' },
  textContent: { padding: rs(16) },
  textBody: { fontFamily: font.mono, fontSize: rs(13), color: c.text, lineHeight: rs(20) },
  truncated: { fontFamily: font.mono, fontSize: rs(11), color: c.warning, marginTop: rs(16) },
  avWrap: { width: '100%', flex: 1, alignItems: 'center', justifyContent: 'center' },
  avLabel: { fontFamily: font.mono, fontSize: rs(13), color: c.textSec, marginBottom: rs(16), letterSpacing: rs(1) },
  videoView: { width: W, height: H * 0.6, backgroundColor: '#000' },
  audioView: { width: W * 0.9, height: rs(60) },
  errTxt: { fontFamily: font.sans, fontSize: rs(14), color: c.danger, textAlign: 'center', marginTop: rs(12) },
  extMark: {
    width: rs(72), height: rs(72), borderWidth: 1.5, borderColor: c.border2,
    alignItems: 'center', justifyContent: 'center', marginBottom: rs(16),
  },
  extTitle: { fontFamily: font.displayBold, fontSize: rs(20), color: c.text, marginBottom: rs(4) },
  extBtn: {
    marginTop: rs(20), backgroundColor: c.accent,
    paddingHorizontal: rs(22), paddingVertical: rs(13), borderRadius: radius.btn,
  },
  extBtnTxt: { fontFamily: font.monoBold, fontSize: rs(13), letterSpacing: rs(1), textTransform: 'uppercase', color: c.accentFg },
  warn: {
    fontFamily: font.sans, fontSize: rs(12), color: c.warning, textAlign: 'center',
    marginTop: rs(16), paddingHorizontal: rs(12), lineHeight: rs(17),
  },
});

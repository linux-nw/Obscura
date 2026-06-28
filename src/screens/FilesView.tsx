import React, { useState, useEffect } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  FlatList, Alert, ActivityIndicator, Modal,
  TouchableWithoutFeedback, Image,
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';
import * as ImagePicker from 'expo-image-picker';
import { FileManager, FileMetadata } from '../services/FileManager';
import { DecoyVaultService } from '../services/DecoyVaultService';
import { SecureCryptoService } from '../services/CryptoService';
import { AutoLockService } from '../services/AutoLockService';
import FileIcon from '../components/FileIcon';
import FileViewer from '../components/FileViewer';
import Icon from '../components/Icon';
import { c, rs, font, radius, TAB_BAR_HEIGHT, useBottomInset, fileColor } from '../theme';

const FREE_LIMIT = 10;

export default function FilesView({ isDecoy = false }: { isDecoy?: boolean }) {
  const [files,    setFiles]    = useState<FileMetadata[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showPicker, setShowPicker] = useState(false);
  const [viewerFile, setViewerFile] = useState<FileMetadata | null>(null);
  const [thumbs,     setThumbs]     = useState<Record<string, string>>({});
  const [initialized, setInitialized] = useState(false);
  const safeBot = useBottomInset();

  useEffect(() => { initialize(); }, []);

  // Dateien laden, sobald die Services bereit sind — sonst bleibt die Liste beim
  // erneuten Öffnen leer (es gab keinen initialen Ladevorgang nach der Init).
  useEffect(() => { if (initialized) loadFiles(); }, [initialized]);

  const initialize = async () => {
    try {
      await SecureCryptoService.initialize();
      await FileManager.initialize();
      setInitialized(true);
    } catch (error) {
      console.error('FilesView initialization error:', error);
      setInitialized(true); // Trotzdem initialisieren, um Fehler anzuzeigen
    }
  };

  // L6: in the guest vault, list/read/write go through DecoyVaultService (sealed with the
  // guest key) — never FileManager's master-key path or the real vault/ dir.
  const listFiles = async (): Promise<FileMetadata[]> => {
    if (!isDecoy) return FileManager.getFiles();
    const guest = await DecoyVaultService.getFakeFiles();
    return guest.map(f => ({
      id: f.id,
      name: f.name,
      originalName: f.originalName,
      type: f.type,
      size: f.size,
      createdAt: f.createdAt,
      iv: '',
      mac: '',
      version: 1,
    }));
  };

  // Kein initialized-Guard: FileManager.getFiles() initialisiert sich selbst.
  const loadFiles = async () => {
    setLoading(true);
    try {
      const loaded = await listFiles();
      setFiles(loaded);
      loadThumbs(loaded);
    } catch {
      Alert.alert('Fehler', 'Dateien konnten nicht geladen werden.');
    } finally {
      setLoading(false);
    }
  };

  // Lazy: entschlüsselt Bild-Inhalte für Listen-Thumbnails. Nur Bilder; bei einem
  // Free-Limit von 10 Dateien ist das vertretbar. Bereits geladene werden übersprungen.
  const loadThumbs = async (list: FileMetadata[]) => {
    for (const f of list) {
      if (f.type !== 'image') continue;
      try {
        const b64 = isDecoy
          ? await DecoyVaultService.getFakeFileContent(f.id)
          : await FileManager.getFileContent(f.id);
        setThumbs(prev => prev[f.id] ? prev : { ...prev, [f.id]: `data:image/jpeg;base64,${b64}` });
      } catch {
        // Thumbnail-Fehler ignorieren — Karte fällt auf das Icon zurück.
      }
    }
  };

  // ── Selection helpers ──────────────────────────────────────────────

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const clearSelect = () => setSelected(new Set());

  // ── Import flow ────────────────────────────────────────────────────

  const handleImport = () => {
    if (files.length >= FREE_LIMIT) {
      Alert.alert('Limit erreicht', `Kostenlose Version: max. ${FREE_LIMIT} Dateien.`);
      return;
    }
    setShowPicker(true);
  };

  const pickGallery = async () => {
    setShowPicker(false);
    AutoLockService.beginPickerSession();
    try {
      const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
      if (!perm.granted) {
        Alert.alert('Berechtigung benötigt', 'Bitte Zugriff auf Fotos erlauben.');
        return;
      }
      const result = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ImagePicker.MediaTypeOptions.ImagesAndVideos,
        allowsEditing: false,
        allowsMultipleSelection: true,
        quality: 1,
      } as any);
      if (!result.canceled && result.assets?.length) {
        setLoading(true);
        let saved = 0;
        for (const asset of result.assets) {
          const currentFiles = await listFiles();
          if (currentFiles.length >= FREE_LIMIT) {
            Alert.alert('Limit erreicht', `Kostenlose Version: max. ${FREE_LIMIT} Dateien. ${saved} von ${result.assets.length} importiert.`);
            break;
          }
          const assetType = (asset as any).type;
          const type: 'video' | 'image' = assetType === 'video' ? 'video' : 'image';
          await saveFileNoReload(asset.uri, type, asset.fileName ?? (type === 'video' ? 'Video' : 'Bild'));
          saved++;
        }
        await loadFiles();
        setLoading(false);
      }
    } catch (e) {
      Alert.alert('Fehler', `Importfehler: ${String(e)}`);
      setLoading(false);
    } finally {
      AutoLockService.endPickerSession();
    }
  };

  const pickDocument = async () => {
    setShowPicker(false);
    AutoLockService.beginPickerSession();
    await new Promise(r => setTimeout(r, 300));
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: true,
        multiple: true,
      } as any);
      if (!result.canceled && result.assets?.length) {
        setLoading(true);
        let saved = 0;
        for (const asset of result.assets) {
          const currentFiles = await listFiles();
          if (currentFiles.length >= FREE_LIMIT) {
            Alert.alert('Limit erreicht', `Kostenlose Version: max. ${FREE_LIMIT} Dateien. ${saved} von ${result.assets.length} importiert.`);
            break;
          }
          await saveFileNoReload(asset.uri, 'document', asset.name ?? 'Dokument');
          saved++;
        }
        await loadFiles();
        setLoading(false);
      }
    } catch (e) {
      Alert.alert('Fehler', `Importfehler: ${String(e)}`);
      setLoading(false);
    } finally {
      AutoLockService.endPickerSession();
    }
  };

  const persistFile = async (uri: string, type: 'image' | 'video' | 'document', name: string) => {
    if (isDecoy) {
      await DecoyVaultService.saveFile(uri, type, name);
    } else {
      await FileManager.saveFile(uri, type, name);
    }
  };

  const saveFileNoReload = async (uri: string, type: 'image' | 'video' | 'document', name: string) => {
    try {
      await persistFile(uri, type, name);
    } catch (e) {
      Alert.alert('Fehler', `Datei konnte nicht gespeichert werden: ${String(e)}`);
    }
  };

  const saveFile = async (uri: string, type: 'image' | 'video' | 'document', name: string) => {
    setLoading(true);
    try {
      await persistFile(uri, type, name);
      await loadFiles();
    } catch (e) {
      Alert.alert('Fehler', `Datei konnte nicht gespeichert werden: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  // ── Delete ─────────────────────────────────────────────────────────

  const confirmDelete = (ids: string[]) => {
    Alert.alert(
      `${ids.length === 1 ? 'Datei' : `${ids.length} Dateien`} löschen`,
      'Dieser Vorgang kann nicht rückgängig gemacht werden.',
      [
        { text: 'Abbrechen', style: 'cancel' },
        {
          text: 'Löschen',
          style: 'destructive',
          onPress: async () => {
            setLoading(true);
            for (const id of ids) {
              if (isDecoy) {
                await DecoyVaultService.deleteFile(id).catch(() => {});
              } else {
                await FileManager.deleteFile(id).catch(() => {});
              }
            }
            clearSelect();
            await loadFiles();
          },
        },
      ],
    );
  };

  // ── Render file card ───────────────────────────────────────────────

  const renderItem = ({ item }: { item: FileMetadata }) => {
    const isSelected = selected.has(item.id);
    const fc = fileColor[item.type];
    const isSelecting = selected.size > 0;

    return (
      <TouchableOpacity
        style={[s.card, isSelected && s.cardSelected]}
        onPress={() => isSelecting ? toggleSelect(item.id) : setViewerFile(item)}
        onLongPress={() => toggleSelect(item.id)}
        activeOpacity={0.72}
        delayLongPress={350}
      >
        {/* Type-colored left bar */}
        <View style={[s.cardBar, { backgroundColor: fc.accent }]} />

        {/* Thumbnail (images) or type icon + EXT badge */}
        <View style={[s.iconWrap, { backgroundColor: fc.dim }]}>
          {item.type === 'image' && thumbs[item.id] ? (
            <Image source={{ uri: thumbs[item.id] }} style={s.thumb} resizeMode="cover" />
          ) : (
            <View style={s.iconContent}>
              <FileIcon type={item.type} size={rs(22)} color={fc.accent} />
              <Text style={s.extBadge} numberOfLines={1}>
                {item.originalName.split('.').pop()?.toUpperCase().slice(0, 4) ?? item.type.toUpperCase().slice(0, 3)}
              </Text>
            </View>
          )}
        </View>

        {/* Info */}
        <View style={s.cardInfo}>
          <Text style={s.cardName} numberOfLines={1}>{item.originalName}</Text>
          <Text style={s.cardMeta}>
            {fileTypeLabel(item.type)}  ·  {formatSize(item.size)}  ·  {formatDate(item.createdAt)}
          </Text>
        </View>

        {/* Selection indicator OR delete button */}
        {isSelecting ? (
          <View style={[s.checkCircle, isSelected && s.checkCircleOn]}>
            {isSelected && <Icon name="check" size={rs(14)} color={c.accentFg} stroke={2.4} />}
          </View>
        ) : (
          <TouchableOpacity
            style={s.deleteBtn}
            onPress={() => confirmDelete([item.id])}
            hitSlop={{ top: 10, right: 10, bottom: 10, left: 10 }}
            activeOpacity={0.7}
          >
            <Icon name="x" size={rs(17)} color={c.textTer} />
          </TouchableOpacity>
        )}
      </TouchableOpacity>
    );
  };

  // ── Multi-select bar ───────────────────────────────────────────────

  const SelectionBar = () => (
    <View style={s.selBar}>
      <TouchableOpacity onPress={clearSelect} activeOpacity={0.7} style={s.selBtn}>
        <Text style={s.selCancelTxt}>Abbrechen</Text>
      </TouchableOpacity>
      <Text style={s.selCount}>
        {selected.size} ausgewählt
      </Text>
      <TouchableOpacity
        onPress={() => confirmDelete(Array.from(selected))}
        activeOpacity={0.7}
        style={s.selBtn}
        disabled={selected.size === 0}
      >
        <Text style={[s.selDeleteTxt, selected.size === 0 && { opacity: 0.4 }]}>
          Löschen
        </Text>
      </TouchableOpacity>
    </View>
  );

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <View style={s.root}>
      {/* Stats / selection bar */}
      {selected.size > 0 ? (
        <SelectionBar />
      ) : (
        <View style={s.statsBar}>
          <Text style={s.statsTxt}>
            {files.length} / {FREE_LIMIT} Dateien
          </Text>
          <View style={s.storageBar}>
            <View style={[s.storageFill, { flex: Math.min(files.length / FREE_LIMIT, 1) }]} />
          </View>
        </View>
      )}

      {/* Loading overlay */}
      {loading && (
        <View style={s.loadingRow}>
          <ActivityIndicator size="small" color={c.accent} />
          <Text style={s.loadingTxt}>Wird verarbeitet …</Text>
        </View>
      )}

      {/* File list */}
      <FlatList
        data={files}
        keyExtractor={item => item.id}
        renderItem={renderItem}
        contentContainerStyle={[
          s.list,
          { paddingBottom: rs(56) + safeBot + rs(88) },
        ]}
        ListEmptyComponent={!loading ? (
          <View style={s.empty}>
            <View style={s.emptyMark}>
              <Icon name="shield" size={rs(38)} color={c.accent} stroke={1.4} />
            </View>
            <Text style={s.emptyTitle}>Tresor ist leer</Text>
            <Text style={s.emptySub}>
              Importiere dein erstes Dokument oder Foto. Alles wird sofort verschlüsselt.
            </Text>
          </View>
        ) : null}
      />

      {/* FAB — import button */}
      {selected.size === 0 && (
        <TouchableOpacity style={s.fab} onPress={handleImport} activeOpacity={0.85}>
          <Icon name="plus" size={rs(24)} color={c.accentFg} stroke={2.2} />
        </TouchableOpacity>
      )}

      {/* ── Import source picker (bottom sheet) ── */}
      <Modal
        visible={showPicker}
        transparent
        animationType="slide"
        onRequestClose={() => setShowPicker(false)}
      >
        <TouchableWithoutFeedback onPress={() => setShowPicker(false)}>
          <View style={s.sheetOverlay}>
            <TouchableWithoutFeedback>
              <View style={s.sheet}>
                <View style={s.sheetHandle} />
                <Text style={s.sheetTitle}>Datei importieren</Text>

                <TouchableOpacity style={s.sheetOption} onPress={pickGallery} activeOpacity={0.75}>
                  <View style={s.sheetOptionIcon}>
                    <Icon name="image" size={rs(20)} color={c.accent} />
                  </View>
                  <View style={s.sheetOptionInfo}>
                    <Text style={s.sheetOptionTitle}>Galerie</Text>
                    <Text style={s.sheetOptionSub}>Fotos & Videos auswählen</Text>
                  </View>
                  <Icon name="chevron-right" size={rs(18)} color={c.textTer} />
                </TouchableOpacity>

                <TouchableOpacity style={s.sheetOption} onPress={pickDocument} activeOpacity={0.75}>
                  <View style={s.sheetOptionIcon}>
                    <Icon name="file" size={rs(20)} color={c.accent} />
                  </View>
                  <View style={s.sheetOptionInfo}>
                    <Text style={s.sheetOptionTitle}>Dateien</Text>
                    <Text style={s.sheetOptionSub}>Dokumente und andere Dateien</Text>
                  </View>
                  <Icon name="chevron-right" size={rs(18)} color={c.textTer} />
                </TouchableOpacity>

                <TouchableOpacity style={s.sheetCancel} onPress={() => setShowPicker(false)} activeOpacity={0.7}>
                  <Text style={s.sheetCancelTxt}>Abbrechen</Text>
                </TouchableOpacity>
              </View>
            </TouchableWithoutFeedback>
          </View>
        </TouchableWithoutFeedback>
      </Modal>

      {/* ── In-App File Viewer (alle Typen) ── */}
      <FileViewer file={viewerFile} isDecoy={isDecoy} onClose={() => setViewerFile(null)} />
    </View>
  );
}

// ─────────────────────────────── Helpers ───────────────────────────────

function formatSize(bytes: number): string {
  if (bytes < 1024)         return `${bytes} B`;
  if (bytes < 1024 * 1024)  return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(d: Date): string {
  const now  = new Date();
  const diff = now.getTime() - d.getTime();
  const days = Math.floor(diff / 86_400_000);
  if (days === 0) return 'Heute';
  if (days === 1) return 'Gestern';
  if (days < 7)  return `Vor ${days} Tagen`;
  return d.toLocaleDateString('de-DE', { day: 'numeric', month: 'short' });
}

function fileTypeLabel(type: string): string {
  if (type === 'image')    return 'Bild';
  if (type === 'video')    return 'Video';
  if (type === 'document') return 'Dokument';
  return type;
}

// ─────────────────────────────── Styles ───────────────────────────────

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: c.bg },

  // Stats bar
  statsBar: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: rs(18),
    paddingTop: rs(12),
    paddingBottom: rs(8),
    gap: rs(10),
  },
  statsTxt: {
    fontFamily: font.mono,
    fontSize: rs(10.5),
    color: c.textTer,
    textTransform: 'uppercase',
    letterSpacing: rs(1),
    minWidth: rs(110),
  },
  storageBar: {
    flex: 1,
    height: rs(3),
    backgroundColor: c.inset,
    overflow: 'hidden',
  },
  storageFill: {
    height: '100%',
    backgroundColor: c.accent,
  },

  // Selection bar
  selBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: rs(16),
    paddingTop: rs(12),
    paddingBottom: rs(8),
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: c.sep,
  },
  selBtn: { minWidth: rs(80) },
  selCount: {
    fontFamily: font.monoBold,
    fontSize: rs(13),
    color: c.text,
  },
  selCancelTxt: {
    fontFamily: font.mono,
    fontSize: rs(13),
    color: c.accent,
  },
  selDeleteTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(13),
    color: c.danger,
    textAlign: 'right',
  },

  // Loading
  loadingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: rs(8),
    paddingVertical: rs(6),
  },
  loadingTxt: {
    fontFamily: font.mono,
    fontSize: rs(12),
    color: c.textSec,
  },

  // List
  list: {
    paddingHorizontal: rs(16),
    paddingTop: rs(4),
  },

  // Card
  card: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: c.surface,
    borderRadius: radius.card,
    borderWidth: 1,
    borderColor: c.border,
    marginBottom: rs(8),
    overflow: 'hidden',
  },
  cardSelected: {
    borderColor: c.accentBorder,
    backgroundColor: c.accentDim,
  },
  cardBar: {
    width: rs(2),
    alignSelf: 'stretch',
  },
  iconWrap: {
    width: rs(44),
    height: rs(44),
    margin: rs(12),
    alignItems: 'center',
    justifyContent: 'center',
    overflow: 'hidden',
    backgroundColor: c.inset,
  },
  thumb: {
    width: '100%',
    height: '100%',
  },
  iconContent: {
    alignItems: 'center',
    justifyContent: 'center',
    gap: rs(2),
  },
  extBadge: {
    fontFamily: font.monoBold,
    fontSize: rs(8),
    color: c.accent,
    letterSpacing: rs(0.5),
    textAlign: 'center',
  },
  cardInfo: {
    flex: 1,
    paddingVertical: rs(14),
    paddingRight: rs(4),
  },
  cardName: {
    fontFamily: font.sansMed,
    fontSize: rs(15),
    color: c.text,
    marginBottom: rs(4),
  },
  cardMeta: {
    fontFamily: font.mono,
    fontSize: rs(11),
    color: c.textTer,
    letterSpacing: rs(0.3),
  },

  // Check circle (multi-select)
  checkCircle: {
    width: rs(24),
    height: rs(24),
    borderWidth: 1.5,
    borderColor: c.textTer,
    marginRight: rs(14),
    alignItems: 'center',
    justifyContent: 'center',
  },
  checkCircleOn: {
    backgroundColor: c.accent,
    borderColor: c.accent,
  },

  // Delete button
  deleteBtn: {
    paddingHorizontal: rs(14),
    alignSelf: 'stretch',
    justifyContent: 'center',
  },

  // Empty state
  empty: {
    alignItems: 'center',
    paddingTop: rs(72),
    paddingHorizontal: rs(40),
  },
  emptyMark: {
    width: rs(78),
    height: rs(78),
    borderWidth: 1.5,
    borderColor: c.border2,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: rs(22),
  },
  emptyTitle: {
    fontFamily: font.displaySemi,
    fontSize: rs(22),
    color: c.text,
    marginBottom: rs(10),
  },
  emptySub: {
    fontFamily: font.sans,
    fontSize: rs(14),
    color: c.textTer,
    textAlign: 'center',
    lineHeight: rs(20),
    maxWidth: rs(260),
  },

  // FAB
  fab: {
    position: 'absolute',
    right: rs(20),
    bottom: rs(20),
    width: rs(52),
    height: rs(52),
    borderRadius: radius.card,
    backgroundColor: c.accent,
    alignItems: 'center',
    justifyContent: 'center',
    elevation: 6,
  },

  // Bottom sheet
  sheetOverlay: {
    flex: 1,
    justifyContent: 'flex-end',
    backgroundColor: c.overlay,
  },
  sheet: {
    backgroundColor: c.surface,
    borderTopWidth: 1,
    borderColor: c.border2,
    borderTopLeftRadius: radius.card,
    borderTopRightRadius: radius.card,
    paddingTop: rs(10),
    paddingHorizontal: rs(16),
    paddingBottom: rs(34),
  },
  sheetHandle: {
    width: rs(34),
    height: rs(3),
    backgroundColor: c.border2,
    alignSelf: 'center',
    marginBottom: rs(16),
  },
  sheetTitle: {
    fontFamily: font.displaySemi,
    fontSize: rs(17),
    color: c.text,
    marginBottom: rs(16),
    paddingHorizontal: rs(4),
  },
  sheetOption: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: c.surface2,
    borderRadius: radius.card,
    padding: rs(14),
    marginBottom: rs(10),
    borderWidth: 1,
    borderColor: c.border,
    gap: rs(12),
  },
  sheetOptionIcon: {
    width: rs(40),
    height: rs(40),
    borderRadius: rs(2),
    backgroundColor: c.accentDim,
    alignItems: 'center',
    justifyContent: 'center',
  },
  sheetOptionInfo: { flex: 1 },
  sheetOptionTitle: {
    fontFamily: font.sansMed,
    fontSize: rs(15),
    color: c.text,
    marginBottom: rs(2),
  },
  sheetOptionSub: {
    fontFamily: font.mono,
    fontSize: rs(11),
    color: c.textTer,
  },
  sheetCancel: {
    backgroundColor: c.surface2,
    borderRadius: radius.card,
    padding: rs(14),
    alignItems: 'center',
    borderWidth: 1,
    borderColor: c.border,
    marginTop: rs(4),
  },
  sheetCancelTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(13),
    letterSpacing: rs(1),
    textTransform: 'uppercase',
    color: c.danger,
  },
});

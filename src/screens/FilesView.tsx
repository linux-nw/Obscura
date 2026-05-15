import React, { useState, useEffect, useRef } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  FlatList, Alert, ActivityIndicator, Modal,
  TouchableWithoutFeedback, Image, Animated,
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';
import * as ImagePicker from 'expo-image-picker';
import { FileManager, FileMetadata } from '../services/FileManager';
import { SecureCryptoService } from '../services/CryptoService';
import FileIcon from '../components/FileIcon';
import { c, rs, TAB_BAR_HEIGHT, fileColor } from '../theme';

const FREE_LIMIT = 10;

export default function FilesView() {
  const [files,    setFiles]    = useState<FileMetadata[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showPicker, setShowPicker] = useState(false);
  const [preview,    setPreview]    = useState<{ uri: string; type: 'image' | 'video' } | null>(null);
  const [initialized, setInitialized] = useState(false);

  const overlayOpacity = useRef(new Animated.Value(0)).current;

  useEffect(() => { initialize(); }, []);

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

  const loadFiles = async () => {
    if (!initialized) return;
    setLoading(true);
    try {
      setFiles(await FileManager.getFiles());
    } catch {
      Alert.alert('Fehler', 'Dateien konnten nicht geladen werden.');
    } finally {
      setLoading(false);
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
    try {
      const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
      if (!perm.granted) {
        Alert.alert('Berechtigung benötigt', 'Bitte Zugriff auf Fotos erlauben.');
        return;
      }
      const result = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ImagePicker.MediaTypeOptions.ImagesAndVideos,
        allowsEditing: false,
        quality: 1,
      });
      if (!result.canceled && result.assets?.[0]) {
        const asset = result.assets[0];
        await saveFile(asset.uri, 'image', asset.fileName ?? 'Bild');
      }
    } catch (e) {
      Alert.alert('Fehler', `Importfehler: ${String(e)}`);
    }
  };

  const pickDocument = async () => {
    setShowPicker(false);
    await new Promise(r => setTimeout(r, 300));
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: true,
      });
      if (!result.canceled && result.assets?.[0]) {
        const asset = result.assets[0];
        await saveFile(asset.uri, 'document', asset.name ?? 'Dokument');
      }
    } catch (e) {
      Alert.alert('Fehler', `Importfehler: ${String(e)}`);
    }
  };

  const saveFile = async (uri: string, type: 'image' | 'video' | 'document', name: string) => {
    setLoading(true);
    try {
      await FileManager.saveFile(uri, type, name);
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
              await FileManager.deleteFile(id).catch(() => {});
            }
            clearSelect();
            await loadFiles();
          },
        },
      ],
    );
  };

  // ── Preview (images) ───────────────────────────────────────────────

  const openPreview = async (file: FileMetadata) => {
    if (file.type !== 'image') return;
    try {
      const b64 = await FileManager.getFileContent(file.id);
      const uri = `data:image/jpeg;base64,${b64}`;
      setPreview({ uri, type: file.type });
      Animated.timing(overlayOpacity, { toValue: 1, duration: 220, useNativeDriver: true }).start();
    } catch {
      Alert.alert('Fehler', 'Bild konnte nicht geladen werden.');
    }
  };

  const closePreview = () => {
    Animated.timing(overlayOpacity, { toValue: 0, duration: 180, useNativeDriver: true })
      .start(() => setPreview(null));
  };

  // ── Render file card ───────────────────────────────────────────────

  const renderItem = ({ item }: { item: FileMetadata }) => {
    const isSelected = selected.has(item.id);
    const fc = fileColor[item.type];
    const isSelecting = selected.size > 0;

    return (
      <TouchableOpacity
        style={[s.card, isSelected && s.cardSelected]}
        onPress={() => isSelecting ? toggleSelect(item.id) : openPreview(item)}
        onLongPress={() => toggleSelect(item.id)}
        activeOpacity={0.72}
        delayLongPress={350}
      >
        {/* Type-colored left bar */}
        <View style={[s.cardBar, { backgroundColor: fc.accent }]} />

        {/* Icon */}
        <View style={[s.iconWrap, { backgroundColor: fc.dim }]}>
          <FileIcon type={item.type} size={rs(28)} color={fc.accent} />
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
            {isSelected && <Text style={s.checkMark}>✓</Text>}
          </View>
        ) : (
          <TouchableOpacity
            style={s.deleteBtn}
            onPress={() => confirmDelete([item.id])}
            hitSlop={{ top: 10, right: 10, bottom: 10, left: 10 }}
            activeOpacity={0.7}
          >
            <Text style={s.deleteTxt}>✕</Text>
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
          { paddingBottom: TAB_BAR_HEIGHT + rs(88) },
        ]}
        ListEmptyComponent={!loading ? (
          <View style={s.empty}>
            <Text style={s.emptyIcon}>🔐</Text>
            <Text style={s.emptyTitle}>Tresor ist leer</Text>
            <Text style={s.emptySub}>
              Importiere Dateien über den + Button
            </Text>
          </View>
        ) : null}
      />

      {/* FAB — import button */}
      {selected.size === 0 && (
        <TouchableOpacity style={s.fab} onPress={handleImport} activeOpacity={0.85}>
          <Text style={s.fabTxt}>+</Text>
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
                  <View style={[s.sheetOptionIcon, { backgroundColor: fileColor.image.dim }]}>
                    <Text style={s.sheetOptionEmoji}>🖼️</Text>
                  </View>
                  <View style={s.sheetOptionInfo}>
                    <Text style={s.sheetOptionTitle}>Galerie</Text>
                    <Text style={s.sheetOptionSub}>Fotos & Videos auswählen</Text>
                  </View>
                  <Text style={s.sheetChevron}>›</Text>
                </TouchableOpacity>

                <TouchableOpacity style={s.sheetOption} onPress={pickDocument} activeOpacity={0.75}>
                  <View style={[s.sheetOptionIcon, { backgroundColor: fileColor.document.dim }]}>
                    <Text style={s.sheetOptionEmoji}>📄</Text>
                  </View>
                  <View style={s.sheetOptionInfo}>
                    <Text style={s.sheetOptionTitle}>Dateien</Text>
                    <Text style={s.sheetOptionSub}>Dokumente und andere Dateien</Text>
                  </View>
                  <Text style={s.sheetChevron}>›</Text>
                </TouchableOpacity>

                <TouchableOpacity style={s.sheetCancel} onPress={() => setShowPicker(false)} activeOpacity={0.7}>
                  <Text style={s.sheetCancelTxt}>Abbrechen</Text>
                </TouchableOpacity>
              </View>
            </TouchableWithoutFeedback>
          </View>
        </TouchableWithoutFeedback>
      </Modal>

      {/* ── Image preview overlay ── */}
      {preview && (
        <Animated.View style={[s.previewOverlay, { opacity: overlayOpacity }]}>
          <TouchableWithoutFeedback onPress={closePreview}>
            <View style={s.previewBg} />
          </TouchableWithoutFeedback>
          <Image
            source={{ uri: preview.uri }}
            style={s.previewImage}
            resizeMode="contain"
          />
          <TouchableOpacity style={s.previewClose} onPress={closePreview} activeOpacity={0.7}>
            <Text style={s.previewCloseTxt}>✕</Text>
          </TouchableOpacity>
        </Animated.View>
      )}
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
    fontSize: rs(12),
    fontWeight: '500',
    color: c.textSec,
    textTransform: 'uppercase',
    letterSpacing: 0.4,
    minWidth: rs(100),
  },
  storageBar: {
    flex: 1,
    height: rs(3),
    backgroundColor: c.card,
    borderRadius: rs(2),
    overflow: 'hidden',
  },
  storageFill: {
    height: '100%',
    backgroundColor: c.accent,
    borderRadius: rs(2),
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
    fontSize: rs(14),
    fontWeight: '600',
    color: c.text,
  },
  selCancelTxt: {
    fontSize: rs(14),
    color: c.accent,
  },
  selDeleteTxt: {
    fontSize: rs(14),
    fontWeight: '600',
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
    fontSize: rs(13),
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
    backgroundColor: c.card,
    borderRadius: rs(14),
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
    marginBottom: rs(10),
    overflow: 'hidden',
  },
  cardSelected: {
    borderColor: c.accentBorder,
    backgroundColor: c.accentDim,
  },
  cardBar: {
    width: rs(3),
    alignSelf: 'stretch',
  },
  iconWrap: {
    width: rs(46),
    height: rs(46),
    borderRadius: rs(10),
    margin: rs(12),
    alignItems: 'center',
    justifyContent: 'center',
  },
  cardInfo: {
    flex: 1,
    paddingVertical: rs(14),
    paddingRight: rs(4),
  },
  cardName: {
    fontSize: rs(14),
    fontWeight: '600',
    color: c.text,
    marginBottom: rs(3),
  },
  cardMeta: {
    fontSize: rs(12),
    color: c.textSec,
  },

  // Check circle (multi-select)
  checkCircle: {
    width: rs(24),
    height: rs(24),
    borderRadius: rs(12),
    borderWidth: 1.5,
    borderColor: c.textSec,
    marginRight: rs(14),
    alignItems: 'center',
    justifyContent: 'center',
  },
  checkCircleOn: {
    backgroundColor: c.accent,
    borderColor: c.accent,
  },
  checkMark: {
    fontSize: rs(13),
    color: '#fff',
    fontWeight: '700',
  },

  // Delete button
  deleteBtn: {
    paddingHorizontal: rs(14),
    alignSelf: 'stretch',
    justifyContent: 'center',
  },
  deleteTxt: {
    fontSize: rs(15),
    color: c.danger,
    fontWeight: '400',
  },

  // Empty state
  empty: {
    alignItems: 'center',
    paddingTop: rs(80),
    paddingHorizontal: rs(40),
  },
  emptyIcon: { fontSize: rs(52), marginBottom: rs(16) },
  emptyTitle: {
    fontSize: rs(18),
    fontWeight: '600',
    color: c.textSec,
    marginBottom: rs(6),
  },
  emptySub: {
    fontSize: rs(14),
    color: c.textTer,
    textAlign: 'center',
    lineHeight: rs(20),
  },

  // FAB
  fab: {
    position: 'absolute',
    right: rs(20),
    bottom: TAB_BAR_HEIGHT + rs(16),
    width: rs(56),
    height: rs(56),
    borderRadius: rs(28),
    backgroundColor: c.accent,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: c.accent,
    shadowOffset: { width: 0, height: rs(4) },
    shadowOpacity: 0.45,
    shadowRadius: rs(10),
    elevation: 8,
  },
  fabTxt: {
    fontSize: rs(32),
    color: '#fff',
    fontWeight: '300',
    lineHeight: rs(38),
  },

  // Bottom sheet
  sheetOverlay: {
    flex: 1,
    justifyContent: 'flex-end',
    backgroundColor: c.overlay,
  },
  sheet: {
    backgroundColor: c.surface,
    borderTopLeftRadius: rs(20),
    borderTopRightRadius: rs(20),
    paddingTop: rs(10),
    paddingHorizontal: rs(16),
    paddingBottom: rs(34),
  },
  sheetHandle: {
    width: rs(36),
    height: rs(4),
    borderRadius: rs(2),
    backgroundColor: c.border,
    alignSelf: 'center',
    marginBottom: rs(16),
  },
  sheetTitle: {
    fontSize: rs(17),
    fontWeight: '700',
    color: c.text,
    marginBottom: rs(16),
    paddingHorizontal: rs(4),
  },
  sheetOption: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: c.card,
    borderRadius: rs(12),
    padding: rs(14),
    marginBottom: rs(10),
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
    gap: rs(12),
  },
  sheetOptionIcon: {
    width: rs(44),
    height: rs(44),
    borderRadius: rs(10),
    alignItems: 'center',
    justifyContent: 'center',
  },
  sheetOptionEmoji: { fontSize: rs(22) },
  sheetOptionInfo: { flex: 1 },
  sheetOptionTitle: {
    fontSize: rs(15),
    fontWeight: '600',
    color: c.text,
    marginBottom: rs(2),
  },
  sheetOptionSub: {
    fontSize: rs(12),
    color: c.textSec,
  },
  sheetChevron: {
    fontSize: rs(20),
    color: c.textSec,
    fontWeight: '300',
  },
  sheetCancel: {
    backgroundColor: c.card,
    borderRadius: rs(12),
    padding: rs(14),
    alignItems: 'center',
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
    marginTop: rs(4),
  },
  sheetCancelTxt: {
    fontSize: rs(15),
    fontWeight: '600',
    color: c.danger,
  },

  // Image preview
  previewOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(0,0,0,0.92)',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 100,
  },
  previewBg: {
    ...StyleSheet.absoluteFillObject,
  },
  previewImage: {
    width: '92%',
    height: '72%',
    borderRadius: rs(10),
  },
  previewClose: {
    position: 'absolute',
    top: rs(56),
    right: rs(20),
    width: rs(36),
    height: rs(36),
    borderRadius: rs(18),
    backgroundColor: 'rgba(255,255,255,0.12)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  previewCloseTxt: {
    fontSize: rs(16),
    color: c.text,
    fontWeight: '400',
  },
});

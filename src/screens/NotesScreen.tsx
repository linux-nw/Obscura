import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  FlatList, TextInput, Modal, Alert,
} from 'react-native';
import { NotesService, Note } from '../services/NotesService';
import { SecureCryptoService } from '../services/CryptoService';
import NoteEditor from './NoteEditor';
import { c, rs, TAB_BAR_HEIGHT } from '../theme';
import ActionIcon from '../components/ActionIcon';

export default function NotesScreen() {
  const [notes,   setNotes]   = useState<Note[]>([]);
  const [query,   setQuery]   = useState('');
  const [editing, setEditing] = useState<Note | null | undefined>(undefined); // undefined = hidden
  const [loading, setLoading] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => { initialize(); }, []);

  const initialize = async () => {
    try {
      await SecureCryptoService.initialize();
      await NotesService.initialize();
      setInitialized(true);
    } catch (error) {
      console.error('NotesScreen initialization error:', error);
      setInitialized(true); // Trotzdem initialisieren, um Fehler anzuzeigen
    }
  };

  const loadNotes = async () => {
    if (!initialized) return;
    setLoading(true);
    try {
      setNotes(await NotesService.getNotes());
    } catch {
      Alert.alert('Fehler', 'Notizen konnten nicht geladen werden.');
    } finally {
      setLoading(false);
    }
  };

  const openCreate = () => setEditing(null);
  const openEdit   = (n: Note) => setEditing(n);
  const closeEditor = () => setEditing(undefined);
  const onSaved    = useCallback(() => { loadNotes(); }, []);

  const handleDelete = (noteId: string) => {
    Alert.alert(
      'Notiz löschen',
      'Diese Notiz wird dauerhaft gelöscht.',
      [
        { text: 'Abbrechen', style: 'cancel' },
        {
          text: 'Löschen',
          style: 'destructive',
          onPress: async () => {
            await NotesService.deleteNote(noteId).catch(() => {});
            loadNotes();
          },
        },
      ],
    );
  };

  const filtered = query.trim()
    ? notes.filter(n =>
        n.title.toLowerCase().includes(query.toLowerCase()) ||
        n.content.toLowerCase().includes(query.toLowerCase()) ||
        n.category?.toLowerCase().includes(query.toLowerCase()) ||
        n.tags?.some((t: string) => t.toLowerCase().includes(query.toLowerCase()))
      )
    : notes;

  const renderNote = ({ item }: { item: Note }) => (
    <TouchableOpacity
      style={s.card}
      onPress={() => openEdit(item)}
      activeOpacity={0.75}
    >
      {/* Left accent bar */}
      <View style={s.cardBar} />

      <View style={s.cardBody}>
        <Text style={s.cardTitle} numberOfLines={1}>{item.title}</Text>
        {item.content.trim().length > 0 && (
          <Text style={s.cardPreview} numberOfLines={2}>{item.content}</Text>
        )}

        <View style={s.cardMeta}>
          {item.category && (
            <View style={s.badge}>
              <Text style={s.badgeTxt}>{item.category}</Text>
            </View>
          )}
          <Text style={s.cardDate}>{formatDate(item.updatedAt)}</Text>
        </View>
      </View>

      <TouchableOpacity
        style={s.deleteBtn}
        onPress={() => handleDelete(item.id)}
        hitSlop={{ top: 10, right: 10, bottom: 10, left: 10 }}
        activeOpacity={0.7}
      >
        <ActionIcon type="delete" size={rs(28)} />
      </TouchableOpacity>
    </TouchableOpacity>
  );

  const editorVisible = editing !== undefined;

  return (
    <View style={s.root}>
      {/* ── Search bar ── */}
      <View style={s.searchBar}>
        <View style={s.searchIcon}>
          <Text style={s.searchIconTxt}>⌕</Text>
        </View>
        <TextInput
          style={s.searchInput}
          placeholder="Notizen durchsuchen …"
          placeholderTextColor={c.textSec}
          value={query}
          onChangeText={setQuery}
          returnKeyType="search"
          clearButtonMode="while-editing"
        />
        {query.length > 0 && (
          <TouchableOpacity onPress={() => setQuery('')} style={s.clearBtn} activeOpacity={0.7}>
            <Text style={s.clearTxt}>✕</Text>
          </TouchableOpacity>
        )}
      </View>

      {/* ── Note count strip ── */}
      <View style={s.strip}>
        <Text style={s.stripTxt}>
          {filtered.length} {filtered.length === 1 ? 'Notiz' : 'Notizen'}
        </Text>
      </View>

      {/* ── List ── */}
      <FlatList
        data={filtered}
        keyExtractor={item => item.id}
        renderItem={renderNote}
        contentContainerStyle={[
          s.list,
          { paddingBottom: TAB_BAR_HEIGHT + rs(80) },
        ]}
        ListEmptyComponent={
          <View style={s.empty}>
            <Text style={s.emptyIcon}>📝</Text>
            <Text style={s.emptyTitle}>
              {query ? 'Keine Treffer' : 'Noch keine Notizen'}
            </Text>
            <Text style={s.emptySub}>
              {query ? 'Anderen Suchbegriff versuchen' : 'Tippe + um eine Notiz zu erstellen'}
            </Text>
          </View>
        }
      />

      {/* ── FAB ── */}
      <TouchableOpacity style={s.fab} onPress={openCreate} activeOpacity={0.85}>
        <Text style={s.fabTxt}>+</Text>
      </TouchableOpacity>

      {/* ── Full-screen note editor ── */}
      <Modal
        visible={editorVisible}
        animationType="slide"
        presentationStyle="fullScreen"
        onRequestClose={closeEditor}
      >
        {editorVisible && (
          <NoteEditor
            note={editing}
            onClose={closeEditor}
            onSaved={onSaved}
          />
        )}
      </Modal>
    </View>
  );
}

// ─────────────────────────────── Helpers ───────────────────────────────

function formatDate(d: Date): string {
  const now  = new Date();
  const diff = now.getTime() - d.getTime();
  const days = Math.floor(diff / 86_400_000);
  if (days === 0) return 'Heute';
  if (days === 1) return 'Gestern';
  if (days < 7)  return `Vor ${days} Tagen`;
  return d.toLocaleDateString('de-DE', { day: 'numeric', month: 'short' });
}

// ─────────────────────────────── Styles ───────────────────────────────

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: c.bg },

  // Search
  searchBar: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: c.card,
    marginHorizontal: rs(16),
    marginTop: rs(12),
    marginBottom: rs(4),
    borderRadius: rs(12),
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: c.border,
    paddingHorizontal: rs(12),
    height: rs(44),
  },
  searchIcon: {
    marginRight: rs(6),
  },
  searchIconTxt: {
    fontSize: rs(18),
    color: c.textSec,
  },
  searchInput: {
    flex: 1,
    fontSize: rs(15),
    color: c.text,
    paddingVertical: 0,
  },
  clearBtn: {
    padding: rs(4),
  },
  clearTxt: {
    fontSize: rs(13),
    color: c.textSec,
  },

  // Strip
  strip: {
    paddingHorizontal: rs(18),
    paddingVertical: rs(8),
  },
  stripTxt: {
    fontSize: rs(12),
    fontWeight: '500',
    color: c.textSec,
    textTransform: 'uppercase',
    letterSpacing: 0.4,
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
  cardBar: {
    width: rs(3),
    alignSelf: 'stretch',
    backgroundColor: c.accent,
    borderTopLeftRadius: rs(14),
    borderBottomLeftRadius: rs(14),
  },
  cardBody: {
    flex: 1,
    paddingVertical: rs(13),
    paddingHorizontal: rs(12),
  },
  cardTitle: {
    fontSize: rs(15),
    fontWeight: '600',
    color: c.text,
    marginBottom: rs(3),
  },
  cardPreview: {
    fontSize: rs(13),
    color: c.textSec,
    lineHeight: rs(19),
    marginBottom: rs(6),
  },
  cardMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(8),
  },
  cardDate: {
    fontSize: rs(11),
    color: c.textTer,
    fontWeight: '500',
  },

  // Badge (category)
  badge: {
    backgroundColor: c.accentDim,
    borderRadius: rs(4),
    paddingHorizontal: rs(6),
    paddingVertical: rs(2),
  },
  badgeTxt: {
    fontSize: rs(10),
    fontWeight: '600',
    color: c.accent,
    letterSpacing: 0.2,
  },

  // Delete button
  deleteBtn: {
    paddingHorizontal: rs(12),
    alignSelf: 'stretch',
    justifyContent: 'center',
  },

  // Empty state
  empty: {
    alignItems: 'center',
    paddingTop: rs(80),
    paddingHorizontal: rs(40),
  },
  emptyIcon: {
    fontSize: rs(48),
    marginBottom: rs(16),
  },
  emptyTitle: {
    fontSize: rs(17),
    fontWeight: '600',
    color: c.textSec,
    marginBottom: rs(6),
    textAlign: 'center',
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
});

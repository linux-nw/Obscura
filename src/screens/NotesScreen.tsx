import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet,
  FlatList, TextInput, Modal, Alert,
} from 'react-native';
import { NotesService, Note } from '../services/NotesService';
import { DecoyVaultService } from '../services/DecoyVaultService';
import { SecureCryptoService } from '../services/CryptoService';
import NoteEditor from './NoteEditor';
import Icon from '../components/Icon';
import { c, rs, font, radius, TAB_BAR_HEIGHT, useBottomInset } from '../theme';

export default function NotesScreen({ isDecoy = false }: { isDecoy?: boolean }) {
  const safeBot = useBottomInset();
  const [notes,   setNotes]   = useState<Note[]>([]);
  const [query,   setQuery]   = useState('');
  const [editing, setEditing] = useState<Note | null | undefined>(undefined); // undefined = hidden
  const [loading, setLoading] = useState(false);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => { initialize(); }, []);

  // Notizen laden, sobald die Services bereit sind (und bei erneuter Bereitschaft).
  useEffect(() => { if (initialized) loadNotes(); }, [initialized]);

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

  // Kein initialized-Guard: NotesService.getNotes() initialisiert sich selbst. Der
  // frühere Guard las über einen stale Closure immer initialized=false → die Liste
  // wurde nach dem Speichern nie neu geladen.
  const loadNotes = async () => {
    setLoading(true);
    try {
      if (isDecoy) {
        // L6: guest vault — read sealed guest notes, never the real notes/ dir.
        const guest = await DecoyVaultService.getFakeNotes();
        setNotes(guest.map(n => ({
          id: n.id,
          title: n.title,
          content: n.content,
          category: n.category,
          tags: [],
          createdAt: n.createdAt,
          updatedAt: n.createdAt,
          isEncrypted: true,
        })));
      } else {
        setNotes(await NotesService.getNotes());
      }
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
            if (isDecoy) {
              await DecoyVaultService.deleteNote(noteId).catch(() => {});
            } else {
              await NotesService.deleteNote(noteId).catch(() => {});
            }
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
        <Icon name="trash-2" size={rs(18)} color={c.textTer} />
      </TouchableOpacity>
    </TouchableOpacity>
  );

  const editorVisible = editing !== undefined;

  return (
    <View style={s.root}>
      {/* ── Search bar ── */}
      <View style={s.searchBar}>
        <Icon name="search" size={rs(17)} color={c.textTer} />
        <TextInput
          style={s.searchInput}
          placeholder="Notizen durchsuchen …"
          placeholderTextColor={c.textFaint}
          value={query}
          onChangeText={setQuery}
          returnKeyType="search"
          clearButtonMode="while-editing"
        />
        {query.length > 0 && (
          <TouchableOpacity onPress={() => setQuery('')} style={s.clearBtn} activeOpacity={0.7}>
            <Icon name="x" size={rs(15)} color={c.textTer} />
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
          { paddingBottom: rs(56) + safeBot + rs(80) },
        ]}
        ListEmptyComponent={
          <View style={s.empty}>
            <View style={s.emptyMark}>
              <Icon name="sticky-note" size={rs(34)} color={c.accent} stroke={1.4} />
            </View>
            <Text style={s.emptyTitle}>
              {query ? 'Keine Treffer' : 'Keine Notizen'}
            </Text>
            <Text style={s.emptySub}>
              {query ? 'Anderen Suchbegriff versuchen' : 'Passwörter, Codes, alles Vertrauliche — verschlüsselt notiert.'}
            </Text>
          </View>
        }
      />

      {/* ── FAB ── */}
      <TouchableOpacity style={s.fab} onPress={openCreate} activeOpacity={0.85}>
        <Icon name="plus" size={rs(24)} color={c.accentFg} stroke={2.2} />
      </TouchableOpacity>

      {/* ── Full-screen note editor ── */}
      <Modal
        visible={editorVisible}
        animationType="fade"
        statusBarTranslucent
        onRequestClose={closeEditor}
      >
        {editorVisible && (
          <NoteEditor
            note={editing}
            isDecoy={isDecoy}
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
    gap: rs(10),
    backgroundColor: c.inset,
    marginHorizontal: rs(16),
    marginTop: rs(8),
    marginBottom: rs(4),
    borderRadius: radius.input,
    borderWidth: 1,
    borderColor: c.border2,
    paddingHorizontal: rs(13),
    height: rs(46),
  },
  searchInput: {
    flex: 1,
    fontFamily: font.mono,
    fontSize: rs(14),
    color: c.text,
    paddingVertical: 0,
  },
  clearBtn: {
    padding: rs(4),
  },

  // Strip
  strip: {
    paddingHorizontal: rs(18),
    paddingVertical: rs(8),
  },
  stripTxt: {
    fontFamily: font.mono,
    fontSize: rs(10.5),
    color: c.textTer,
    textTransform: 'uppercase',
    letterSpacing: rs(1),
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
  cardBar: {
    width: rs(2),
    alignSelf: 'stretch',
    backgroundColor: c.accent,
  },
  cardBody: {
    flex: 1,
    paddingVertical: rs(13),
    paddingHorizontal: rs(13),
  },
  cardTitle: {
    fontFamily: font.displaySemi,
    fontSize: rs(17),
    color: c.text,
    marginBottom: rs(4),
  },
  cardPreview: {
    fontFamily: font.sans,
    fontSize: rs(13),
    color: c.textSec,
    lineHeight: rs(19),
    marginBottom: rs(7),
  },
  cardMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: rs(8),
  },
  cardDate: {
    fontFamily: font.mono,
    fontSize: rs(10.5),
    color: c.textFaint,
    letterSpacing: rs(0.3),
  },

  // Badge (category)
  badge: {
    backgroundColor: c.accentDim,
    borderRadius: rs(2),
    paddingHorizontal: rs(7),
    paddingVertical: rs(3),
  },
  badgeTxt: {
    fontFamily: font.monoBold,
    fontSize: rs(9.5),
    color: c.accent,
    letterSpacing: rs(0.6),
    textTransform: 'uppercase',
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
    textAlign: 'center',
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
});

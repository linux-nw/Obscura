import React, { useState, useRef, useEffect } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet,
  KeyboardAvoidingView, Platform, StatusBar, Alert, ScrollView,
} from 'react-native';
import { NotesService, Note } from '../services/NotesService';
import { c, rs, SAFE_TOP, SAFE_BOTTOM } from '../theme';

interface Props {
  note?: Note | null;
  onClose: () => void;
  onSaved: () => void;
}

export default function NoteEditor({ note, onClose, onSaved }: Props) {
  const [title,   setTitle]   = useState(note?.title ?? '');
  const [content, setContent] = useState(note?.content ?? '');
  const [saving,  setSaving]  = useState(false);

  const titleRef = useRef<TextInput>(null);

  useEffect(() => {
    if (!note) {
      const t = setTimeout(() => titleRef.current?.focus(), 180);
      return () => clearTimeout(t);
    }
  }, []);

  const isDirty = note
    ? title !== note.title || content !== note.content
    : title.trim().length > 0 || content.trim().length > 0;

  const handleClose = () => {
    if (isDirty) {
      Alert.alert(
        'Änderungen verwerfen?',
        'Ungespeicherte Änderungen gehen verloren.',
        [
          { text: 'Weiter bearbeiten', style: 'cancel' },
          { text: 'Verwerfen', style: 'destructive', onPress: onClose },
        ],
      );
    } else {
      onClose();
    }
  };

  const handleSave = async () => {
    if (!title.trim()) {
      Alert.alert('Kein Titel', 'Bitte einen Titel eingeben.');
      return;
    }
    setSaving(true);
    try {
      if (note) {
        await NotesService.updateNote(note.id, {
          title: title.trim(),
          content: content.trim(),
        });
      } else {
        await NotesService.createNote(title.trim(), content.trim());
      }
      onSaved();
      onClose();
    } catch {
      Alert.alert('Fehler', 'Notiz konnte nicht gespeichert werden.');
    } finally {
      setSaving(false);
    }
  };

  const canSave = title.trim().length > 0 && !saving;

  return (
    <View style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent />
      <KeyboardAvoidingView
        style={s.flex}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        keyboardVerticalOffset={0}
      >
        {/* ── Header ── */}
        <View style={s.header}>
          <TouchableOpacity style={s.headerBtn} onPress={handleClose} activeOpacity={0.7}>
            <Text style={s.cancelTxt}>Abbrechen</Text>
          </TouchableOpacity>

          <Text style={s.headerTitle} numberOfLines={1}>
            {note ? 'Bearbeiten' : 'Neue Notiz'}
          </Text>

          <TouchableOpacity
            style={[s.headerBtn, s.saveBtn]}
            onPress={handleSave}
            disabled={!canSave}
            activeOpacity={0.7}
          >
            <Text style={[s.saveTxt, !canSave && s.saveTxtDisabled]}>
              {saving ? 'Speichern…' : 'Fertig'}
            </Text>
          </TouchableOpacity>
        </View>

        {/* ── Editor area ── */}
        <ScrollView
          style={s.scroll}
          contentContainerStyle={[s.scrollContent, { paddingBottom: SAFE_BOTTOM + rs(24) }]}
          keyboardShouldPersistTaps="handled"
        >
          <TextInput
            ref={titleRef}
            style={s.titleInput}
            placeholder="Titel"
            placeholderTextColor={c.textTer}
            value={title}
            onChangeText={setTitle}
            returnKeyType="next"
            maxLength={120}
            onSubmitEditing={() => {}}
          />
          <View style={s.divider} />
          <TextInput
            style={s.bodyInput}
            placeholder="Beginne zu schreiben …"
            placeholderTextColor={c.textTer}
            value={content}
            onChangeText={setContent}
            multiline
            textAlignVertical="top"
            scrollEnabled={false}
          />
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}

const s = StyleSheet.create({
  flex: { flex: 1 },
  root: {
    flex: 1,
    backgroundColor: c.bg,
    paddingTop: SAFE_TOP,
  },

  // Header
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: rs(16),
    paddingVertical: rs(12),
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: c.sep,
  },
  headerBtn: {
    minWidth: rs(90),
  },
  saveBtn: {
    alignItems: 'flex-end',
  },
  headerTitle: {
    flex: 1,
    textAlign: 'center',
    fontSize: rs(17),
    fontWeight: '600',
    color: c.text,
  },
  cancelTxt: {
    fontSize: rs(16),
    color: c.accent,
  },
  saveTxt: {
    fontSize: rs(16),
    fontWeight: '600',
    color: c.accent,
  },
  saveTxtDisabled: {
    opacity: 0.35,
  },

  // Editor
  scroll: { flex: 1 },
  scrollContent: {
    padding: rs(20),
  },
  titleInput: {
    fontSize: rs(26),
    fontWeight: '700',
    color: c.text,
    letterSpacing: -0.4,
    paddingVertical: rs(4),
    marginBottom: rs(14),
  },
  divider: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: c.sep,
    marginBottom: rs(16),
  },
  bodyInput: {
    fontSize: rs(16),
    color: c.text,
    lineHeight: rs(25),
    minHeight: rs(280),
  },
});

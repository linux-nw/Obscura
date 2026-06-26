// obscura/main.jsx — unlocked app: tabs (Dateien / Notizen / Einstellungen). Exports to window.
const { useState: useS4, useEffect: useE4, useRef: useR4 } = React;

/* ---------- small toggle ---------- */
function Toggle({ on, onChange }) {
  return (
    <button onClick={() => onChange(!on)} style={{
      width: 44, height: 26, borderRadius: 2, border: '1px solid ' + (on ? 'var(--ob-accent)' : 'var(--ob-border-2)'), cursor: 'pointer', flexShrink: 0,
      background: on ? 'var(--ob-accent-soft)' : 'transparent', position: 'relative',
      transition: 'all 180ms ease', padding: 0, WebkitTapHighlightColor: 'transparent',
    }}>
      <span style={{ position: 'absolute', top: 3, left: on ? 22 : 3, width: 17, height: 18, borderRadius: 1,
        background: on ? 'var(--ob-accent)' : 'var(--ob-fg-3)', transition: 'left 180ms cubic-bezier(0.16,1,0.3,1), background 180ms ease' }} />
    </button>
  );
}

/* ---------- settings building blocks ---------- */
function SettingsGroup({ label, children }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div className="overline" style={{ padding: '0 4px 8px' }}>{label}</div>
      <div className="ob-card" style={{ overflow: 'hidden' }}>{children}</div>
    </div>
  );
}
function SettingsRow({ icon, label, detail, onClick, toggle, danger, last, accentIcon }) {
  const color = danger ? 'var(--ob-danger)' : 'var(--ob-fg)';
  return (
    <div onClick={onClick} style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '13px 15px',
      cursor: onClick ? 'pointer' : 'default', borderBottom: last ? 'none' : '1px solid var(--ob-border)',
      WebkitTapHighlightColor: 'transparent' }}>
      <div style={{ width: 30, height: 30, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: danger ? 'var(--ob-danger-soft)' : 'var(--ob-surface-2)', flexShrink: 0 }}>
        <Icon name={icon} size={17} color={danger ? 'var(--ob-danger)' : (accentIcon ? 'var(--ob-accent)' : 'var(--ob-fg-2)')} />
      </div>
      <span style={{ flex: 1, fontSize: 15, color, fontWeight: 500 }}>{label}</span>
      {detail && <span className="mono" style={{ fontSize: 12.5, color: 'var(--ob-fg-3)', marginRight: 2 }}>{detail}</span>}
      {toggle !== undefined ? toggle :
        onClick && <Icon name="chevron-right" size={17} color="var(--ob-fg-faint)" />}
    </div>
  );
}

/* ============================================================
   FILES
   ============================================================ */
function FilesView({ files, onOpen, onImport }) {
  if (files.length === 0) {
    return (
      <EmptyState title="Tresor ist leer"
        sub="Importiere dein erstes Dokument oder Foto. Alles wird sofort verschlüsselt."
        cta="Datei importieren" icon="plus" onCta={onImport} />
    );
  }
  return (
    <div className="ob-fadein" style={{ padding: '4px 18px' }}>
      {files.map((f, i) => (
        <div key={f.id}>
          <FileListItem file={f} index={i} onOpen={onOpen} />
          {i < files.length - 1 && <div style={{ height: 1, background: 'var(--ob-border)' }} />}
        </div>
      ))}
      <div className="mono" style={{ textAlign: 'center', fontSize: 11, color: 'var(--ob-fg-faint)', padding: '22px 0 6px', letterSpacing: '0.03em' }}>
        {files.length} Objekte · Ende-zu-Ende verschlüsselt
      </div>
    </div>
  );
}

/* ============================================================
   NOTES
   ============================================================ */
function NotesView({ notes, onOpen, onNew }) {
  if (notes.length === 0) {
    return (
      <EmptyState icon="plus" cta="Notiz erstellen" onCta={onNew}
        title="Keine Notizen" sub="Passwörter, Codes, alles Vertrauliche — verschlüsselt notiert."
        illustration={<div style={{ width: 96, height: 96, border: '1.5px solid var(--ob-border-2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><span className="serif" style={{ fontSize: 46, color: 'var(--ob-accent)', fontStyle: 'italic' }}>N</span></div>} />
    );
  }
  return (
    <div className="ob-fadein" style={{ padding: '4px 18px' }}>
      {notes.map((n, i) => (
        <div key={n.id}>
          <NoteListItem note={n} index={i} onOpen={onOpen} />
          {i < notes.length - 1 && <div style={{ height: 1, background: 'var(--ob-border)' }} />}
        </div>
      ))}
    </div>
  );
}

/* ============================================================
   SETTINGS
   ============================================================ */
const AUTOLOCK_OPTS = ['Sofort', 'Nach 30 Sekunden', 'Nach 1 Minute', 'Nach 5 Minuten'];

function SettingsView({ st, set, onLock, onWipe, onChangePass, onBackup, onAutoLock }) {
  const [panicPinSet, setPanicPinSet] = useS4(false);
  const [panicTrigger, setPanicTrigger] = useS4('lock');
  const [decoyEnabled, setDecoyEnabled] = useS4(false);
  const [pinModal, setPinModal] = useS4(null); // null | 'panic' | 'decoy'
  const [pinNew, setPinNew] = useS4('');
  const [pinConfirm, setPinConfirm] = useS4('');
  const [pinErr, setPinErr] = useS4('');

  const openPinModal = (which) => { setPinModal(which); setPinNew(''); setPinConfirm(''); setPinErr(''); };
  const closePinModal = () => { setPinModal(null); };
  const submitPin = () => {
    if (pinNew.length < 12) { setPinErr('Mind. 12 Zeichen erforderlich'); return; }
    if (pinNew !== pinConfirm) { setPinErr('PINs stimmen nicht überein'); return; }
    if (pinModal === 'panic') setPanicPinSet(true);
    closePinModal();
  };

  const TRIGGERS = [
    { key: 'lock', label: 'Sperren' },
    { key: 'wipe', label: 'Löschen' },
    { key: 'decoy', label: 'Täuschung' },
    { key: 'all', label: 'Alles' },
  ];

  return (
    <div className="ob-fadein" style={{ padding: '6px 16px 0' }}>
      <SettingsGroup label="Sicherheit">
        <SettingsRow icon="clock" label="Auto-Sperre" detail={AUTOLOCK_OPTS[st.autoLock].replace('Nach ', '')} onClick={onAutoLock} />
        <SettingsRow icon="fingerprint" label="Fingerabdruck entsperren" accentIcon
          toggle={<Toggle on={st.biometrics} onChange={(v) => set('biometrics', v)} />} />
        <SettingsRow icon="eye-off" label="Im App-Wechsler verbergen"
          toggle={<Toggle on={st.privacyShield} onChange={(v) => set('privacyShield', v)} />} last />
      </SettingsGroup>

      <SettingsGroup label="Passphrase">
        <SettingsRow icon="key" label="Passphrase ändern" onClick={onChangePass} last />
      </SettingsGroup>

      <SettingsGroup label="Panic-PIN">
        <div style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '11px 15px', borderBottom: '1px solid var(--ob-border)' }}>
          <div style={{ width: 30, height: 30, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--ob-danger-soft)', flexShrink: 0 }}>
            <Icon name="zap" size={17} color="var(--ob-danger)" />
          </div>
          <span style={{ flex: 1, fontSize: 15, color: 'var(--ob-fg)', fontWeight: 500 }}>
            Status: <span className="mono" style={{ fontSize: 12, color: panicPinSet ? 'var(--ob-accent)' : 'var(--ob-fg-faint)' }}>{panicPinSet ? 'AKTIV' : 'NICHT GESETZT'}</span>
          </span>
          {panicPinSet && (
            <button onClick={() => setPanicPinSet(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 12.5, color: 'var(--ob-danger)', fontFamily: 'var(--font-mono)', padding: '4px 6px' }}>
              Entfernen
            </button>
          )}
        </div>
        <SettingsRow icon="key" label={panicPinSet ? 'Panic-PIN ändern' : 'Panic-PIN setzen'} onClick={() => openPinModal('panic')} />
        <div style={{ padding: '12px 15px 14px', borderTop: '1px solid var(--ob-border)' }}>
          <div className="overline" style={{ padding: '0 0 10px' }}>Auslöse-Aktion</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {TRIGGERS.map(t => (
              <button key={t.key} onClick={() => panicPinSet && setPanicTrigger(t.key)}
                style={{
                  padding: '6px 14px', borderRadius: 4, fontSize: 12, fontFamily: 'var(--font-mono)',
                  letterSpacing: '0.06em', cursor: panicPinSet ? 'pointer' : 'default', opacity: panicPinSet ? 1 : 0.38,
                  background: panicTrigger === t.key && panicPinSet ? 'var(--ob-danger-soft)' : 'var(--ob-surface-2)',
                  border: '1px solid ' + (panicTrigger === t.key && panicPinSet ? 'var(--ob-danger-line)' : 'var(--ob-border)'),
                  color: panicTrigger === t.key && panicPinSet ? 'var(--ob-danger)' : 'var(--ob-fg-3)',
                  transition: 'all 140ms ease',
                }}>
                {t.label}
              </button>
            ))}
          </div>
          <p style={{ fontSize: 12, color: 'var(--ob-fg-faint)', margin: '10px 0 0', lineHeight: 1.5 }}>
            Diese PIN öffnet keinen echten Tresor — sie löst die gewählte Aktion lautlos aus.
          </p>
        </div>
      </SettingsGroup>

      <SettingsGroup label="Täusch-Tresor">
        <SettingsRow icon="layers" label="Täusch-Tresor aktivieren" accentIcon
          toggle={<Toggle on={decoyEnabled} onChange={(v) => setDecoyEnabled(v)} />}
          last={!decoyEnabled} />
        {decoyEnabled && (
          <SettingsRow icon="key" label="Täusch-PIN setzen" onClick={() => openPinModal('decoy')} last />
        )}
      </SettingsGroup>

      <SettingsGroup label="Daten">
        <SettingsRow icon="hard-drive" label="Verschlüsseltes Backup" detail="" onClick={() => onBackup('export')} />
        <SettingsRow icon="rotate-ccw" label="Aus Backup wiederherstellen" onClick={() => onBackup('restore')} last />
      </SettingsGroup>

      <SettingsGroup label="Tresor">
        <SettingsRow icon="log-out" label="Jetzt sperren" accentIcon onClick={onLock} last />
      </SettingsGroup>

      <div className="overline" style={{ padding: '0 4px 8px', color: 'var(--ob-danger)' }}>Gefahrenzone</div>
      <button className="ob-btn ob-btn-danger-ghost" onClick={onWipe} style={{ marginBottom: 18 }}>
        <Icon name="trash-2" size={18} /> Tresor löschen
      </button>

      <div style={{ textAlign: 'center', padding: '6px 0 16px' }}>
        <div className="mono" style={{ fontSize: 11, color: 'var(--ob-fg-faint)', lineHeight: 1.7 }}>
          Obscura FileVault · 1.0.0<br />XChaCha20-Poly1305 · Argon2id · lokal
        </div>
      </div>

      {pinModal && (
        <Sheet title={pinModal === 'panic' ? 'Panic-PIN setzen' : 'Täusch-PIN setzen'} onClose={closePinModal}
          footer={<button className="ob-btn ob-btn-primary" onClick={submitPin}>Speichern</button>}>
          <div style={{ padding: '16px 18px' }}>
            <label className="overline" style={{ display: 'block', marginBottom: 8 }}>Neue PIN</label>
            <div className={'ob-field' + (pinErr && pinNew.length > 0 && pinNew.length < 12 ? ' err' : '')}>
              <input className="ob-input" type="password" value={pinNew} autoFocus
                onChange={(e) => { setPinNew(e.target.value); setPinErr(''); }}
                placeholder="Mind. 12 Zeichen"
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }} />
            </div>
            <label className="overline" style={{ display: 'block', margin: '16px 0 8px' }}>PIN wiederholen</label>
            <div className={'ob-field' + (pinErr && pinConfirm.length > 0 && pinNew !== pinConfirm ? ' err' : '')}>
              <input className="ob-input" type="password" value={pinConfirm}
                onChange={(e) => { setPinConfirm(e.target.value); setPinErr(''); }}
                placeholder="PIN erneut eingeben"
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }} />
            </div>
            {pinErr && <p style={{ fontSize: 12.5, color: 'var(--ob-danger)', margin: '10px 0 0', fontFamily: 'var(--font-mono)' }}>{pinErr}</p>}
            <div style={{ display: 'flex', gap: 9, padding: 13, marginTop: 16, borderRadius: 11, background: 'var(--ob-surface-2)' }}>
              <Icon name="info" size={16} color="var(--ob-fg-3)" style={{ marginTop: 1, flexShrink: 0 }} />
              <span style={{ fontSize: 12.5, color: 'var(--ob-fg-3)', lineHeight: 1.5 }}>
                {pinModal === 'panic'
                  ? 'Panic-PIN niemals identisch mit der Entsperr-Passphrase wählen. Mind. 12 Zeichen.'
                  : 'Täusch-PIN öffnet einen leeren Scheintresor statt des echten. Mind. 12 Zeichen.'}
              </span>
            </div>
          </div>
        </Sheet>
      )}
    </div>
  );
}

/* ---------- Auto-lock chooser ---------- */
function AutoLockSheet({ current, onPick, onClose }) {
  return (
    <Sheet title="Auto-Sperre" onClose={onClose}>
      <p style={{ fontSize: 13, color: 'var(--ob-fg-3)', padding: '12px 18px 4px', margin: 0, lineHeight: 1.5 }}>
        Der Tresor sperrt automatisch, wenn die App in den Hintergrund wechselt oder inaktiv ist.
      </p>
      <div style={{ padding: '6px 0 16px' }}>
        {AUTOLOCK_OPTS.map((o, i) => (
          <div key={i} className="ob-row" onClick={() => onPick(i)} style={{ justifyContent: 'space-between' }}>
            <span style={{ fontSize: 15, color: 'var(--ob-fg)' }}>{o}</span>
            {current === i && <Icon name="check" size={19} color="var(--ob-accent)" />}
          </div>
        ))}
      </div>
    </Sheet>
  );
}

/* ---------- Change passphrase ---------- */
function ChangePassSheet({ onClose, onDone }) {
  const [cur, setCur] = useS4('');
  const [nw, setNw] = useS4('');
  const [cf, setCf] = useS4('');
  const valid = cur.length > 0 && nw.length >= 8 && nw === cf;
  return (
    <Sheet title="Passphrase ändern" onClose={onClose}
      footer={<button className="ob-btn ob-btn-primary" disabled={!valid} onClick={onDone}>Passphrase ändern</button>}>
      <div style={{ padding: '16px 18px' }}>
        <label className="overline" style={{ display: 'block', marginBottom: 8 }}>Aktuelle Passphrase</label>
        <PinInput value={cur} onChange={setCur} placeholder="Aktuelle Passphrase" />
        <label className="overline" style={{ display: 'block', margin: '18px 0 8px' }}>Neue Passphrase</label>
        <PinInput value={nw} onChange={setNw} placeholder="Mindestens 8 Zeichen" />
        <div style={{ marginTop: 10 }}><StrengthMeter value={nw} /></div>
        <label className="overline" style={{ display: 'block', margin: '18px 0 8px' }}>Neue wiederholen</label>
        <PinInput value={cf} onChange={setCf} placeholder="Neue Passphrase erneut" error={cf.length > 0 && cf !== nw} />
        <div style={{ display: 'flex', gap: 9, padding: 13, marginTop: 16, borderRadius: 11, background: 'var(--ob-surface-2)' }}>
          <Icon name="info" size={16} color="var(--ob-fg-3)" style={{ marginTop: 1, flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--ob-fg-3)', lineHeight: 1.5 }}>Alle Schlüssel werden mit der neuen Passphrase neu verpackt. Der Tresorinhalt bleibt erhalten.</span>
        </div>
      </div>
    </Sheet>
  );
}

/* ---------- Backup / restore ---------- */
function BackupSheet({ mode, onClose, onDone }) {
  const [busy, setBusy] = useS4(false);
  const exp = mode === 'export';
  const run = () => { setBusy(true); setTimeout(() => { setBusy(false); onDone(exp ? 'Backup exportiert · obscura-2026-05-31.obx' : 'Wiederherstellung abgeschlossen'); }, 1600); };
  return (
    <Sheet title={exp ? 'Verschlüsseltes Backup' : 'Wiederherstellen'} onClose={onClose}
      footer={<button className="ob-btn ob-btn-primary" disabled={busy} onClick={run}>
        {busy ? <><span className="ob-spin" style={{ display: 'inline-flex' }}><Icon name="refresh" size={18} color="var(--ob-accent-fg)" /></span> {exp ? 'Wird exportiert…' : 'Wird wiederhergestellt…'}</> : (exp ? 'Backup exportieren' : 'Backup-Datei wählen')}
      </button>}>
      <div style={{ padding: '18px 18px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: '8px 0 18px' }}>
          <div style={{ width: 64, height: 64, borderRadius: 16, background: 'var(--ob-surface-2)', border: '1px solid var(--ob-border-2)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 14 }}>
            <Icon name={exp ? 'hard-drive' : 'rotate-ccw'} size={28} color="var(--ob-accent)" />
          </div>
          <p style={{ fontSize: 14, color: 'var(--ob-fg-2)', margin: 0, lineHeight: 1.55, maxWidth: 300 }}>
            {exp
              ? 'Das Backup ist eine einzelne, mit deiner Passphrase verschlüsselte Datei. Bewahre sie offline auf — ohne Passphrase ist sie wertlos für andere.'
              : 'Wähle eine .obx-Backupdatei. Du brauchst die Passphrase, mit der das Backup erstellt wurde.'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 9, padding: 13, borderRadius: 11, background: 'var(--ob-surface-2)' }}>
          <Icon name="shield" size={16} color="var(--ob-accent)" style={{ marginTop: 1, flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--ob-fg-3)', lineHeight: 1.5 }}>Backups werden mit demselben Verfahren wie der Tresor verschlüsselt und signiert.</span>
        </div>
      </div>
    </Sheet>
  );
}

/* ---------- Toast ---------- */
function Toast({ msg }) {
  return (
    <div style={{ position: 'absolute', left: 0, right: 0, bottom: 96, display: 'flex', justifyContent: 'center', zIndex: 70, pointerEvents: 'none' }}>
      <div className="ob-slidein" style={{ display: 'flex', alignItems: 'center', gap: 9, background: 'var(--ob-surface-2)', border: '1px solid var(--ob-border-2)',
        borderRadius: 2, padding: '10px 16px', boxShadow: '0 12px 30px rgba(0,0,0,0.5)', maxWidth: '86%' }}>
        <Icon name="check-circle" size={17} color="var(--ob-accent)" />
        <span style={{ fontSize: 13, color: 'var(--ob-fg)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{msg}</span>
      </div>
    </div>
  );
}

/* ============================================================
   MAIN SHELL
   ============================================================ */
function MainScreen({ store, setStore, onLock, onWipe, onPrivacy, lang }) {
  const [tab, setTab] = useS4('files');
  const [preview, setPreview] = useS4(null);
  const [editing, setEditing] = useS4(null);
  const [importing, setImporting] = useS4(false);
  const [autoLockOpen, setAutoLockOpen] = useS4(false);
  const [changePass, setChangePass] = useS4(false);
  const [backup, setBackup] = useS4(null);
  const [wipe, setWipe] = useS4(false);
  const [toast, setToast] = useS4(null);

  const showToast = (m) => { setToast(m); setTimeout(() => setToast(null), 2400); };

  const set = (k, v) => setStore(s => ({ ...s, [k]: v }));

  const titles = { files: 'Dateien', notes: 'Notizen', settings: 'Einstellungen' };
  const counts = { files: store.files.length + ' Objekte', notes: store.notes.length + ' Notizen', settings: 'Lokal & verschlüsselt' };

  const deleteFile = (f) => { set('files', store.files.filter(x => x.id !== f.id)); setPreview(null); showToast('Datei gelöscht'); };
  const saveNote = (n) => {
    if (n.id) set('notes', store.notes.map(x => x.id === n.id ? n : x));
    else set('notes', [{ ...n, id: 'n' + Date.now(), date: 'gerade eben' }, ...store.notes]);
    setEditing(null); showToast('Notiz gespeichert');
  };
  const deleteNote = (n) => { set('notes', store.notes.filter(x => x.id !== n.id)); setEditing(null); showToast('Notiz gelöscht'); };
  const doImport = (kind) => {
    const names = { pdf: 'Neues_Dokument.pdf', image: 'Neues_Foto.jpg', video: 'Neues_Video.mp4' };
    const sizes = { pdf: '420 KB', image: '2,7 MB', video: '84 MB' };
    const f = { id: 'f' + Date.now(), name: names[kind] || 'Datei', kind, size: sizes[kind] || '1 MB',
      date: '19. Jun. 2026', added: 'gerade eben', hue: 90 };
    set('files', [f, ...store.files]); setImporting(false); showToast('Importiert & verschlüsselt');
  };

  return (
    <div className="ob-screen">
      {/* header */}
      <div style={{ paddingTop: PAD_TOP, paddingBottom: 6, background: 'var(--ob-bg)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 16px 8px' }}>
          <VaultMark size={26} />
          <div style={{ flex: 1 }}>
            <div className="wordmark" style={{ fontSize: 14, color: 'var(--ob-fg)', lineHeight: 1 }}>Obscura</div>
            <div className="mono" style={{ fontSize: 9.5, color: 'var(--ob-accent)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6, letterSpacing: '0.14em' }}>
              <span style={{ width: 5, height: 5, background: 'var(--ob-accent)', display: 'inline-block' }} /> ENTSPERRT
            </div>
          </div>
          <button className="ob-iconbtn" onClick={onPrivacy} title="App wechseln (Demo)"><Icon name="eye-off" size={19} color="var(--ob-fg-3)" /></button>
          <button className="ob-iconbtn" onClick={onLock} title="Sperren"><Icon name="lock" size={19} color="var(--ob-fg-2)" /></button>
        </div>
        {/* title row */}
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', padding: '4px 18px 8px' }}>
          <div>
            <h2 className="display" style={{ fontSize: 26, color: 'var(--ob-fg)', margin: 0, lineHeight: 1 }}>{titles[tab]}</h2>
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--ob-fg-faint)', marginTop: 6, letterSpacing: '0.04em' }}>{counts[tab]}</div>
          </div>
          {tab === 'files' && <button className="ob-btn ob-btn-primary" style={{ width: 'auto', padding: '10px 14px', fontSize: 11 }} onClick={() => setImporting(true)}><Icon name="plus" size={16} color="var(--ob-accent-fg)" /> Import</button>}
          {tab === 'notes' && <button className="ob-btn ob-btn-primary" style={{ width: 'auto', padding: '10px 14px', fontSize: 11 }} onClick={() => setEditing({})}><Icon name="plus" size={16} color="var(--ob-accent-fg)" /> Neu</button>}
        </div>
        <div style={{ height: 1, background: 'var(--ob-border)' }} />
      </div>

      {/* content */}
      <div className="ob-scroll" style={{ display: 'flex', flexDirection: 'column' }}>
        {tab === 'files' && <FilesView files={store.files} onOpen={setPreview} onImport={() => setImporting(true)} />}
        {tab === 'notes' && <NotesView notes={store.notes} onOpen={setEditing} onNew={() => setEditing({})} />}
        {tab === 'settings' && <SettingsView st={store} set={set} onLock={onLock} onWipe={() => setWipe(true)}
          onChangePass={() => setChangePass(true)} onBackup={(m) => setBackup(m)} onAutoLock={() => setAutoLockOpen(true)} />}
      </div>

      {/* tab bar */}
      <div className="ob-tabbar">
        {[['files', 'folder', 'Dateien'], ['notes', 'sticky-note', 'Notizen'], ['settings', 'settings', 'Einstellungen']].map(([k, ic, lb]) => (
          <button key={k} className={'ob-tab' + (tab === k ? ' active' : '')} onClick={() => setTab(k)}>
            <Icon name={ic} size={22} color={tab === k ? 'var(--ob-accent)' : 'var(--ob-fg-3)'} stroke={tab === k ? 2 : 1.7} />
            {lb}
          </button>
        ))}
      </div>

      {/* overlays */}
      {preview && <FilePreview file={preview} onClose={() => setPreview(null)} onDelete={deleteFile} />}
      {editing && <NoteEditor note={editing} onClose={() => setEditing(null)} onSave={saveNote} onDelete={deleteNote} />}
      {importing && <ImportSheet onClose={() => setImporting(false)} onPick={doImport} />}
      {autoLockOpen && <AutoLockSheet current={store.autoLock} onClose={() => setAutoLockOpen(false)} onPick={(i) => { set('autoLock', i); setAutoLockOpen(false); }} />}
      {changePass && <ChangePassSheet onClose={() => setChangePass(false)} onDone={() => { setChangePass(false); showToast('Passphrase geändert'); }} />}
      {backup && <BackupSheet mode={backup} onClose={() => setBackup(null)} onDone={(m) => { setBackup(null); showToast(m); }} />}
      {wipe && <WipeDialog onClose={() => setWipe(false)} onWiped={() => { setWipe(false); onWipe(); }} />}
      {toast && <Toast msg={toast} />}
    </div>
  );
}

Object.assign(window, { MainScreen, Toggle });

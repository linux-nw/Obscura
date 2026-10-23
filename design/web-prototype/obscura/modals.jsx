// obscura/modals.jsx — sheets & dialogs. Exports to window.
const { useState: useS2, useEffect: useE2, useRef: useR2 } = React;

/* ---------- Generic bottom sheet ---------- */
function Sheet({ title, onClose, children, footer, full }) {
  return (
    <div className="ob-scrim" onClick={onClose}>
      <div className="ob-sheet" onClick={(e) => e.stopPropagation()} style={full ? { height: '92%' } : null}>
        <div className="ob-grabber" />
        {title !== undefined && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 16px 12px', borderBottom: '1px solid var(--ob-border)' }}>
            <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 18, color: 'var(--ob-fg)' }}>{title}</div>
            <button className="ob-iconbtn" onClick={onClose}><Icon name="x" size={20} color="var(--ob-fg-3)" /></button>
          </div>
        )}
        <div style={{ overflowY: 'auto', flex: 1 }}>{children}</div>
        {footer && <div style={{ padding: 16, borderTop: '1px solid var(--ob-border)', display: 'flex', gap: 10 }}>{footer}</div>}
      </div>
    </div>
  );
}

/* ---------- Confirm dialog (single, non-wipe) ---------- */
function ConfirmDialog({ icon = 'trash-2', title, body, confirmLabel, danger, onConfirm, onCancel }) {
  return (
    <div className="ob-scrim center" onClick={onCancel}>
      <div className="ob-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 320 }}>
        <div style={{ padding: '24px 22px 8px', textAlign: 'center' }}>
          <div style={{ width: 50, height: 50, borderRadius: 14, margin: '0 auto 14px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: danger ? 'var(--ob-danger-soft)' : 'var(--ob-accent-soft)' }}>
            <Icon name={icon} size={24} color={danger ? 'var(--ob-danger)' : 'var(--ob-accent)'} />
          </div>
          <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 18, color: 'var(--ob-fg)' }}>{title}</div>
          <p style={{ fontSize: 14, color: 'var(--ob-fg-3)', margin: '8px 0 0', lineHeight: 1.5 }}>{body}</p>
        </div>
        <div style={{ display: 'flex', gap: 10, padding: 16 }}>
          <button className="ob-btn ob-btn-soft" onClick={onCancel}>Abbrechen</button>
          <button className={'ob-btn ' + (danger ? 'ob-btn-danger' : 'ob-btn-primary')} onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

/* ---------- File preview ---------- */
function FilePreview({ file, onClose, onDelete }) {
  const [confirm, setConfirm] = useS2(false);
  const [playing, setPlaying] = useS2(false);
  const [progress, setProgress] = useS2(0);
  const ivRef = useR2(null);

  useE2(() => {
    if (playing) {
      ivRef.current = setInterval(() => {
        setProgress(p => {
          if (p >= 1) { setPlaying(false); return 0; }
          return p + 1 / 227;
        });
      }, 1000);
    } else {
      clearInterval(ivRef.current);
    }
    return () => clearInterval(ivRef.current);
  }, [playing]);

  const ext = (file.name.split('.').pop() || file.kind).toUpperCase();

  const renderBody = () => {
    /* ---- IMAGE ---- */
    if (file.kind === 'image') return (
      <div style={{ width: '100%', maxWidth: 320, aspectRatio: '4/3', borderRadius: 8, overflow: 'hidden',
        boxShadow: '0 20px 60px rgba(0,0,0,0.55)', position: 'relative',
        background: `linear-gradient(135deg, hsl(${file.hue||0},38%,18%), hsl(${(file.hue||0)+60},25%,10%))` }}>
        <img src="obscura/assets/placeholder.png" alt=""
          style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover',
            filter: `hue-rotate(${file.hue||0}deg) saturate(0.88) brightness(0.8)` }}
          onError={(e) => { e.target.style.display = 'none'; }} />
        <div style={{ position: 'absolute', inset: 0, background: 'linear-gradient(to top, rgba(0,0,0,0.45) 0%, transparent 55%)' }} />
        <div style={{ position: 'absolute', bottom: 10, left: 12 }}>
          <span className="ob-chip" style={{ fontSize: 9 }}><Icon name="lock" size={9} color="var(--ob-accent)" /> {ext}</span>
        </div>
      </div>
    );

    /* ---- PDF / DOC ---- */
    if (file.kind === 'pdf' || file.kind === 'doc') {
      const lines = [88,45,92,72,86,58,78,95,52,80,68,90,42,74,86,35,60,88];
      return (
        <div style={{ width: 210, background: '#f9f7f2', borderRadius: 3, padding: '26px 20px 22px',
          boxShadow: '0 24px 56px rgba(0,0,0,0.6)', position: 'relative', overflow: 'hidden', flexShrink: 0 }}>
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: '#c0392b' }} />
          <div style={{ height: 11, background: '#111', width: '65%', marginBottom: 14, borderRadius: 1 }} />
          <div style={{ height: 6, background: 'rgba(0,0,0,0.18)', width: '42%', marginBottom: 18, borderRadius: 1 }} />
          {lines.map((w, i) => (
            <div key={i} style={{ height: 4, background: `rgba(0,0,0,${0.07 + (i%4)*0.025})`,
              width: (i === lines.length - 1 ? 42 : w) + '%', borderRadius: 1,
              marginBottom: i % 6 === 5 ? 12 : 4 }} />
          ))}
          <div style={{ position: 'absolute', bottom: 9, left: 0, right: 0, display: 'flex', justifyContent: 'space-between', padding: '0 14px' }}>
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#bbb', letterSpacing: '0.06em' }}>{ext}</span>
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#bbb' }}>S. 1</span>
          </div>
        </div>
      );
    }

    /* ---- VIDEO ---- */
    if (file.kind === 'video') {
      const dur = '3:47';
      const t = Math.floor(progress * 227);
      const ts = `${Math.floor(t/60).toString().padStart(2,'0')}:${(t%60).toString().padStart(2,'0')}`;
      return (
        <div style={{ width: '100%', maxWidth: 340 }}>
          {/* frame */}
          <div style={{ aspectRatio: '16/9', borderRadius: 6, background: '#060610',
            border: '1px solid var(--ob-border-2)', overflow: 'hidden', position: 'relative',
            boxShadow: '0 20px 50px rgba(0,0,0,0.6)', cursor: 'pointer' }}
            onClick={() => setPlaying(p => !p)}>
            {/* scanlines */}
            <div style={{ position: 'absolute', inset: 0,
              backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(255,255,255,0.012) 3px, rgba(255,255,255,0.012) 4px)' }} />
            {/* waveform */}
            <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: '28%', display: 'flex', alignItems: 'flex-end', padding: '0 6px', gap: 2 }}>
              {Array.from({length: 28}, (_, i) => (
                <div key={i} style={{ flex: 1, borderRadius: '1px 1px 0 0',
                  background: `rgba(233,162,59,${playing ? 0.35 : 0.12})`,
                  height: `${18 + Math.abs(Math.sin(i * 1.4 + progress * 6) * 82)}%`,
                  transition: playing ? 'height 600ms ease' : 'none' }} />
              ))}
            </div>
            {/* play / pause */}
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ width: 56, height: 56, borderRadius: '50%',
                background: 'rgba(0,0,0,0.45)', border: '1.5px solid rgba(255,255,255,0.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', backdropFilter: 'blur(6px)' }}>
                {playing ? (
                  <div style={{ display: 'flex', gap: 5 }}>
                    <div style={{ width: 4, height: 18, background: 'rgba(255,255,255,0.85)', borderRadius: 2 }} />
                    <div style={{ width: 4, height: 18, background: 'rgba(255,255,255,0.85)', borderRadius: 2 }} />
                  </div>
                ) : (
                  <div style={{ width: 0, height: 0, marginLeft: 5,
                    borderTop: '10px solid transparent', borderBottom: '10px solid transparent',
                    borderLeft: '18px solid rgba(255,255,255,0.85)' }} />
                )}
              </div>
            </div>
            {/* badge */}
            <div style={{ position: 'absolute', top: 10, right: 10 }}>
              <span className="ob-chip" style={{ fontSize: 9 }}><Icon name="lock" size={9} color="var(--ob-accent)" /> {ext}</span>
            </div>
          </div>
          {/* timeline */}
          <div style={{ padding: '10px 2px 0' }}>
            <div style={{ height: 3, background: 'var(--ob-inset)', border: '1px solid var(--ob-border)',
              overflow: 'hidden', cursor: 'pointer', position: 'relative' }}
              onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); setProgress((e.clientX - r.left) / r.width); }}>
              <div style={{ height: '100%', width: `${progress * 100}%`, background: 'var(--ob-accent)', transition: playing ? 'none' : 'width 200ms' }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
              <span className="mono" style={{ fontSize: 10, color: 'var(--ob-fg-faint)' }}>{ts}</span>
              <span className="mono" style={{ fontSize: 10, color: 'var(--ob-fg-faint)' }}>{dur}</span>
            </div>
          </div>
        </div>
      );
    }

    /* ---- TEXT ---- */
    if (file.kind === 'text') {
      const isWallet = file.name.toLowerCase().includes('wallet') || file.name.toLowerCase().includes('seed');
      return (
        <div style={{ width: '100%', maxWidth: 320, background: 'var(--ob-inset)',
          border: '1px solid var(--ob-border-2)', borderRadius: 4, padding: '18px 16px',
          boxShadow: '0 20px 50px rgba(0,0,0,0.5)' }}>
          <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--ob-fg-2)',
            lineHeight: 1.7, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 280, overflowY: 'auto' }}>
            {isWallet
              ? 'witch collapse practice feed shame\nopen despair creek road again\nice least\n\n— Niemals abfotografieren.\n— Niemals online speichern.'
              : '— INHALT VERSCHLÜSSELT —\n\nDieser Text ist im Tresor\ngeschützt und wird hier\nim Klartext angezeigt.'}
          </pre>
        </div>
      );
    }

    /* ---- GENERIC ---- */
    return (
      <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
        <div style={{ width: 120, height: 155, borderRadius: 8, background: 'var(--ob-surface)',
          border: '1px solid var(--ob-border-2)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 20px 50px rgba(0,0,0,0.45)' }}>
          <Icon name="file-text" size={44} color="var(--ob-fg-2)" stroke={1.4} />
        </div>
        <div className="mono" style={{ fontSize: 12, color: 'var(--ob-fg-3)' }}>{ext}-Datei</div>
        <div style={{ fontSize: 13, color: 'var(--ob-fg-faint)', maxWidth: 220, lineHeight: 1.5 }}>
          Inhalt im entschlüsselten Speicher. Verlässt den Tresor nicht.
        </div>
      </div>
    );
  };

  return (
    <div className="ob-scrim" onClick={onClose} style={{ alignItems: 'stretch', background: 'rgba(3,6,4,0.84)' }}>
      <div className="ob-fadein" onClick={(e) => e.stopPropagation()} style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* top bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '56px 14px 12px', flexShrink: 0 }}>
          <button className="ob-iconbtn" onClick={onClose} style={{ color: 'var(--ob-fg)' }}><Icon name="x" size={22} /></button>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--ob-fg)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{file.name}</div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--ob-fg-3)' }}>{file.size} · {file.date}</div>
          </div>
          <div className="ob-chip"><Icon name="lock" size={12} color="var(--ob-accent)" /> {ext}</div>
        </div>
        {/* body */}
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '8px 20px', minHeight: 0, overflowY: 'auto' }}>
          {renderBody()}
        </div>
        {/* actions */}
        <div style={{ display: 'flex', gap: 10, padding: '12px 16px 30px', flexShrink: 0 }}>
          <button className="ob-btn ob-btn-ghost" style={{ flex: 1 }}><Icon name="download" size={18} /> Exportieren</button>
          <button className="ob-btn ob-btn-danger-ghost" style={{ width: 56, flex: 'none' }} onClick={() => setConfirm(true)}>
            <Icon name="trash-2" size={18} />
          </button>
        </div>
      </div>
      {confirm && (
        <ConfirmDialog danger icon="trash-2" title="Datei löschen?"
          body={`„${file.name}“ wird dauerhaft aus dem Tresor entfernt.`}
          confirmLabel="Löschen" onCancel={() => setConfirm(false)}
          onConfirm={() => { setConfirm(false); onDelete(file); }} />
      )}
    </div>
  );
}

/* ---------- Note editor ---------- */
function NoteEditor({ note, onClose, onSave, onDelete }) {
  const isNew = !note.id;
  const [title, setTitle] = useS2(note.title || '');
  const [category, setCategory] = useS2(note.category || '');
  const [body, setBody] = useS2(note.body || '');
  const [confirm, setConfirm] = useS2(false);
  return (
    <div className="ob-scrim" onClick={onClose}>
      <div className="ob-sheet" onClick={(e) => e.stopPropagation()} style={{ height: '88%' }}>
        <div className="ob-grabber" />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px 10px', borderBottom: '1px solid var(--ob-border)' }}>
          <button className="ob-iconbtn" onClick={onClose} style={{ color: 'var(--ob-fg-2)', width: 'auto', padding: '6px 8px', fontSize: 15 }}>Abbrechen</button>
          <div className="ob-chip"><Icon name="lock" size={12} color="var(--ob-accent)" /> verschlüsselt</div>
          <button className="ob-iconbtn" onClick={() => onSave({ ...note, title: title || 'Ohne Titel', category: category.trim() || undefined, body })}
            style={{ color: 'var(--ob-accent)', width: 'auto', padding: '6px 8px', fontSize: 15, fontWeight: 600 }}>Fertig</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '18px 18px 0' }}>
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Titel"
            style={{ width: '100%', background: 'transparent', border: 'none', outline: 'none', color: 'var(--ob-fg)',
              fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 24, letterSpacing: '-0.02em', marginBottom: 6 }} />
          <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Kategorie (optional)"
            maxLength={40}
            style={{ width: '100%', background: 'transparent', border: 'none', borderBottom: '1px solid var(--ob-border)', outline: 'none',
              color: 'var(--ob-fg-2)', fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: '0.07em',
              textTransform: 'uppercase', marginBottom: 14, paddingBottom: 10 }} />
          <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Notiz schreiben…"
            style={{ width: '100%', minHeight: 260, background: 'transparent', border: 'none', outline: 'none', resize: 'none',
              color: 'var(--ob-fg-2)', fontFamily: 'var(--font-sans)', fontSize: 16, lineHeight: 1.6 }} />
        </div>
        {!isNew && (
          <div style={{ padding: '10px 16px 26px', borderTop: '1px solid var(--ob-border)' }}>
            <button className="ob-btn ob-btn-danger-ghost" onClick={() => setConfirm(true)}><Icon name="trash-2" size={18} /> Notiz löschen</button>
          </div>
        )}
      </div>
      {confirm && (
        <ConfirmDialog danger icon="trash-2" title="Notiz löschen?" body="Diese Notiz wird dauerhaft entfernt."
          confirmLabel="Löschen" onCancel={() => setConfirm(false)}
          onConfirm={() => { setConfirm(false); onDelete(note); }} />
      )}
    </div>
  );
}

/* ---------- Import picker ---------- */
function ImportSheet({ onClose, onPick }) {
  const opt = (icon, label, desc, kind) => (
    <button className="ob-row" onClick={() => onPick(kind)} style={{ width: '100%', textAlign: 'left', background: 'transparent', border: 'none' }}>
      <div className="ob-tile" style={{ background: 'var(--ob-surface-2)', border: '1px solid var(--ob-border)' }}>
        <Icon name={icon} size={20} color="var(--ob-accent)" />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 15, fontWeight: 500, color: 'var(--ob-fg)' }}>{label}</div>
        <div style={{ fontSize: 12.5, color: 'var(--ob-fg-3)', marginTop: 2 }}>{desc}</div>
      </div>
      <Icon name="chevron-right" size={18} color="var(--ob-fg-faint)" />
    </button>
  );
  return (
    <Sheet title="Importieren" onClose={onClose}>
      <div style={{ padding: '6px 0 8px' }}>
        {opt('file-text', 'Dokument', 'PDF, Word oder andere Datei wählen', 'pdf')}
        {opt('image', 'Foto', 'JPG, PNG oder HEIC aus der Mediathek', 'image')}
        {opt('film', 'Video', 'MP4, MOV oder MKV importieren', 'video')}
        {opt('camera', 'Kamera', 'Direkt aufnehmen und verschlüsseln', 'image')}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 18px 22px', color: 'var(--ob-fg-faint)' }}>
        <Icon name="info" size={14} color="var(--ob-fg-faint)" />
        <span style={{ fontSize: 12, lineHeight: 1.4 }}>Importe werden sofort verschlüsselt. Das Original kannst du danach sicher löschen.</span>
      </div>
    </Sheet>
  );
}

/* ---------- Wipe dialog: double confirmation ---------- */
function WipeDialog({ onClose, onWiped, forced }) {
  const [step, setStep] = useS2(1);
  const [text, setText] = useS2('');
  const ok = text.trim().toUpperCase() === 'LÖSCHEN';
  return (
    <div className="ob-scrim center" onClick={forced ? undefined : onClose}>
      <div className="ob-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 340, borderColor: 'var(--ob-danger-line)' }}>
        {/* red header */}
        <div style={{ background: 'var(--ob-danger-soft)', padding: '18px 20px', display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--ob-danger-line)' }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: 'var(--ob-danger)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon name="alert-triangle" size={20} color="#1A0907" />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 17, color: 'var(--ob-danger)' }}>
              {forced ? 'Tresor gesperrt' : 'Tresor löschen'}
            </div>
            <div className="overline" style={{ color: 'var(--ob-danger)', opacity: 0.8 }}>Nicht umkehrbar</div>
          </div>
        </div>
        <div style={{ padding: '18px 20px 20px' }}>
          {forced && (
            <div style={{ background: 'var(--ob-danger-soft)', border: '1px solid var(--ob-danger-line)', borderRadius: 10, padding: '10px 12px', marginBottom: 14, display: 'flex', gap: 8 }}>
              <Icon name="alert-triangle" size={16} color="var(--ob-danger)" style={{ marginTop: 1 }} />
              <span style={{ fontSize: 13, color: 'var(--ob-fg-2)', lineHeight: 1.45 }}>5 Fehlversuche. Aus Sicherheitsgründen kann der Tresor jetzt nur gelöscht werden.</span>
            </div>
          )}
          {step === 1 ? (
            <p style={{ fontSize: 14, color: 'var(--ob-fg-2)', margin: 0, lineHeight: 1.55 }}>
              Alle <strong style={{ color: 'var(--ob-fg)' }}>Dateien und Notizen</strong> werden dauerhaft gelöscht und die Schlüssel vernichtet.
              Es gibt <strong style={{ color: 'var(--ob-danger)' }}>keine Wiederherstellung</strong>.
            </p>
          ) : (
            <div>
              <p style={{ fontSize: 14, color: 'var(--ob-fg-2)', margin: '0 0 12px', lineHeight: 1.5 }}>
                Zur Bestätigung <strong className="mono" style={{ color: 'var(--ob-danger)' }}>LÖSCHEN</strong> eingeben:
              </p>
              <div className={'ob-field' + (text && !ok ? ' err' : '')}>
                <input className="ob-input" value={text} autoFocus autoCapitalize="characters"
                  onChange={(e) => setText(e.target.value)} placeholder="LÖSCHEN"
                  style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.08em' }} />
                {ok && <Icon name="check" size={18} color="var(--ob-danger)" />}
              </div>
            </div>
          )}
        </div>
        <div style={{ display: 'flex', gap: 10, padding: 16, borderTop: '1px solid var(--ob-border)' }}>
          {!forced && step === 1 && <button className="ob-btn ob-btn-soft" onClick={onClose}>Abbrechen</button>}
          {step === 1 ? (
            <button className="ob-btn ob-btn-danger" onClick={() => setStep(2)}>Weiter</button>
          ) : (
            <button className="ob-btn ob-btn-danger" disabled={!ok} onClick={onWiped}
              style={!ok ? { opacity: 0.4 } : null}>Endgültig löschen</button>
          )}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { Sheet, ConfirmDialog, FilePreview, NoteEditor, ImportSheet, WipeDialog });

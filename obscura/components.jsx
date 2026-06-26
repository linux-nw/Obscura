// obscura/components.jsx — shared Obscura UI. Exports to window.
const { useState, useEffect, useRef } = React;

/* ---------- Brand mark: aperture / iris diaphragm + keyhole ---------- */
function VaultMark({ size = 40, locked = true, accent, spinning }) {
  const a = accent || 'var(--ob-accent)';
  const c = 24, rOut = 24 * 0.43, rIn = 24 * 0.14;
  const blades = [];
  for (let i = 0; i < 6; i++) {
    const ang = (i * 60 + 25) * Math.PI / 180;
    const tx = c + rIn * Math.cos(ang), ty = c + rIn * Math.sin(ang);
    const L = Math.sqrt(Math.max(0, rOut * rOut - rIn * rIn));
    const dx = -Math.sin(ang), dy = Math.cos(ang);
    blades.push(
      <line key={i} x1={(tx + L * dx).toFixed(2)} y1={(ty + L * dy).toFixed(2)}
        x2={(tx - L * dx).toFixed(2)} y2={(ty - L * dy).toFixed(2)}
        stroke={a} strokeWidth={24 * 0.04} strokeLinecap="round" />
    );
  }
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" style={{ display: 'block', overflow: 'visible' }}>
      <g style={spinning ? { transformOrigin: 'center', animation: 'obApertureSpin 2.6s linear infinite' } : null}>
        {blades}
      </g>
      {locked ? (
        <>
          <circle cx={c} cy={c - 0.3} r={24 * 0.05} fill={a} />
          <path d={`M${c} ${c + 0.4} L${(c - 24 * 0.04).toFixed(2)} ${(c + 24 * 0.092).toFixed(2)} H${(c + 24 * 0.04).toFixed(2)} Z`} fill={a} />
        </>
      ) : (
        <circle cx={c} cy={c} r={24 * 0.05} fill="none" stroke={a} strokeWidth="1.3" />
      )}
    </svg>
  );
}

function Wordmark({ size = 22, sub }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <VaultMark size={size * 1.45} />
      <div>
        <div className="wordmark" style={{ fontSize: size * 0.82, color: 'var(--ob-fg)', lineHeight: 1 }}>
          Obscura
        </div>
        {sub && <div className="overline" style={{ marginTop: 7 }}>{sub}</div>}
      </div>
    </div>
  );
}

/* ---------- Passphrase field with show/hide ---------- */
function PinInput({ value, onChange, placeholder = 'Passphrase', error, onSubmit, autoFocus, big }) {
  const [show, setShow] = useState(false);
  const ref = useRef(null);
  useEffect(() => { if (autoFocus && ref.current) ref.current.focus(); }, [autoFocus]);
  return (
    <div className={'ob-field' + (error ? ' err' : '')} style={big ? { height: 60 } : null}>
      <Icon name="key" size={18} color="var(--ob-fg-3)" />
      <input
        ref={ref}
        className="ob-input"
        type={show ? 'text' : 'password'}
        value={value}
        placeholder={placeholder}
        autoCapitalize="none" autoCorrect="off" spellCheck="false"
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && onSubmit) onSubmit(); }}
      />
      <button className="ob-iconbtn" onClick={() => setShow(s => !s)} tabIndex={-1} aria-label="Anzeigen">
        <Icon name={show ? 'eye-off' : 'eye'} size={18} />
      </button>
    </div>
  );
}

/* ---------- Passphrase strength ---------- */
function scorePass(p) {
  if (!p) return { n: 0, label: '', color: 'var(--ob-border)' };
  let s = 0;
  if (p.length >= 8) s++;
  if (p.length >= 12) s++;
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
  if (/[0-9]/.test(p) || /[^A-Za-z0-9]/.test(p)) s++;
  if (p.length < 8) s = Math.min(s, 1);
  const map = [
    { label: '', color: 'var(--ob-border)' },
    { label: 'Zu kurz', color: 'var(--ob-danger)' },
    { label: 'Schwach', color: 'var(--ob-warn)' },
    { label: 'Gut', color: 'var(--ob-accent)' },
    { label: 'Stark', color: 'var(--ob-accent-bright)' },
  ];
  return { n: s, ...map[s] };
}
function StrengthMeter({ value }) {
  const { n, label, color } = scorePass(value);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div className="ob-strength">
        {[0, 1, 2, 3].map(i => (
          <div key={i} className="ob-strseg" style={{ background: i < n ? color : 'var(--ob-border)' }} />
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', minHeight: 14 }}>
        <span className="mono" style={{ fontSize: 11, color: 'var(--ob-fg-3)' }}>min. 8 Zeichen</span>
        {label && <span className="mono" style={{ fontSize: 11, color, fontWeight: 600 }}>{label}</span>}
      </div>
    </div>
  );
}

/* ---------- Biometric button (Fingerabdruck) ---------- */
function BiometricButton({ onTrigger, label = 'Mit Fingerabdruck entsperren', scanning }) {
  return (
    <button
      className="ob-btn ob-btn-ghost"
      onClick={onTrigger}
      disabled={scanning}
      style={{ borderColor: scanning ? 'var(--ob-accent)' : 'var(--ob-border-2)',
               color: scanning ? 'var(--ob-accent)' : 'var(--ob-fg)' }}
    >
      <div style={scanning ? { animation: 'obPulse 1s ease-in-out infinite' } : null}>
        <Icon name="fingerprint" size={22} color={scanning ? 'var(--ob-accent)' : 'currentColor'} />
      </div>
      {scanning ? 'Fingerabdruck wird gelesen…' : label}
    </button>
  );
}

/* ---------- File / note type tiles ---------- */
function kindIcon(kind) {
  if (kind === 'pdf' || kind === 'doc') return 'file-text';
  if (kind === 'text') return 'file-text';
  if (kind === 'image') return 'image';
  if (kind === 'video') return 'file-video';
  return 'file';
}

function FileListItem({ file, index, onOpen }) {
  const ext = (file.name.split('.').pop() || file.kind).toUpperCase();
  const isImg = file.kind === 'image';
  return (
    <div className="ob-row" onClick={() => onOpen(file)} style={{ padding: '14px 6px', gap: 14, alignItems: 'center' }}>
      <span className="ob-index">{String((index ?? 0) + 1).padStart(2, '0')}</span>
      {/* thumbnail for images, icon for others */}
      {isImg ? (
        <div style={{ width: 40, height: 40, flexShrink: 0, overflow: 'hidden', borderRadius: 3,
          background: `linear-gradient(135deg, hsl(${file.hue||0},35%,18%), hsl(${(file.hue||0)+50},25%,10%))` }}>
          <img src="obscura/assets/placeholder.png" alt=""
            style={{ width: '100%', height: '100%', objectFit: 'cover',
              filter: `hue-rotate(${file.hue||0}deg) saturate(0.8) brightness(0.75)` }}
            onError={(e) => { e.target.style.display = 'none'; }} />
        </div>
      ) : (
        <div style={{ width: 40, height: 40, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'var(--ob-surface-2)', borderRadius: 3, border: '1px solid var(--ob-border)' }}>
          <Icon name={kindIcon(file.kind)} size={20} color="var(--ob-fg-3)" stroke={1.5} />
        </div>
      )}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 15, fontWeight: 500, color: 'var(--ob-fg)', letterSpacing: '-0.01em',
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {file.name}
        </div>
        <div className="mono" style={{ fontSize: 11, color: 'var(--ob-fg-3)', marginTop: 3 }}>
          {file.size} &middot; {file.added}
        </div>
      </div>
      {/* format badge — always visible on the right */}
      <span className="mono" style={{
        fontSize: 10, fontWeight: 700, color: 'var(--ob-accent)',
        letterSpacing: '0.1em', border: '1px solid var(--ob-accent-line)',
        padding: '3px 8px', borderRadius: 2, flexShrink: 0,
      }}>{ext}</span>
    </div>
  );
}

function NoteListItem({ note, index, onOpen }) {
  const preview = note.body.replace(/\n+/g, ' ').slice(0, 54);
  return (
    <div className="ob-row" style={{ alignItems: 'flex-start', padding: '15px 6px', gap: 16 }} onClick={() => onOpen(note)}>
      <span className="ob-index" style={{ marginTop: 2 }}>{String((index ?? 0) + 1).padStart(2, '0')}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="serif" style={{ fontSize: 18, color: 'var(--ob-fg)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {note.title}
        </div>
        <div style={{ fontSize: 13.5, color: 'var(--ob-fg-3)', marginTop: 3, lineHeight: 1.45, display: '-webkit-box', WebkitLineClamp: 1, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
          {preview}…
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
          {note.category && (
            <span className="mono" style={{ fontSize: 10, color: 'var(--ob-accent)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{note.category}</span>
          )}
          {note.category && <span style={{ fontSize: 10, color: 'var(--ob-border-2)' }}>·</span>}
          <span className="mono" style={{ fontSize: 10.5, color: 'var(--ob-fg-faint)' }}>{note.date}</span>
        </div>
      </div>
    </div>
  );
}

/* ---------- Empty state: sharp keyhole mark + serif headline ---------- */
function SafeIllustration() {
  return (
    <svg width="96" height="96" viewBox="0 0 96 96" fill="none">
      <rect x="14" y="14" width="68" height="68" stroke="var(--ob-border-2)" strokeWidth="1.5" />
      <circle cx="48" cy="42" r="11" stroke="var(--ob-accent)" strokeWidth="1.8" />
      <path d="M48 51 L43 67 H53 Z" fill="var(--ob-accent)" />
    </svg>
  );
}
function EmptyState({ illustration, title, sub, cta, onCta, icon }) {
  return (
    <div className="ob-fadein" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '0 40px', gap: 0 }}>
      <div style={{ marginBottom: 26, opacity: 0.9 }}>{illustration || <SafeIllustration />}</div>
      <div className="serif" style={{ fontSize: 26, color: 'var(--ob-fg)', lineHeight: 1.1 }}>{title}</div>
      <p style={{ fontSize: 14.5, color: 'var(--ob-fg-3)', margin: '12px 0 28px', lineHeight: 1.55, maxWidth: 264 }}>{sub}</p>
      {cta && (
        <button className="ob-btn ob-btn-primary" style={{ width: 'auto', padding: '13px 22px' }} onClick={onCta}>
          {icon && <Icon name={icon} size={18} color="var(--ob-accent-fg)" />}
          {cta}
        </button>
      )}
    </div>
  );
}

/* ---------- Privacy overlay (app-switcher protection) ---------- */
function PrivacyOverlay({ onDismiss }) {
  return (
    <div onClick={onDismiss} style={{
      position: 'absolute', inset: 0, zIndex: 80,
      background: 'var(--ob-bg)',
      backdropFilter: 'blur(40px)', WebkitBackdropFilter: 'blur(40px)',
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      gap: 18, animation: 'obFade 160ms ease',
    }}>
      <VaultMark size={64} />
      <div style={{ textAlign: 'center' }}>
        <div className="wordmark" style={{ fontSize: 19, color: 'var(--ob-fg)' }}>Obscura</div>
        <div className="overline" style={{ marginTop: 8, color: 'var(--ob-fg-3)' }}>Inhalt geschützt</div>
      </div>
      <div className="mono" style={{ position: 'absolute', bottom: 56, fontSize: 11, color: 'var(--ob-fg-faint)' }}>
        Zum Fortfahren tippen
      </div>
    </div>
  );
}

Object.assign(window, {
  VaultMark, Wordmark, PinInput, StrengthMeter, scorePass,
  BiometricButton, FileTile, FileListItem, NoteListItem,
  SafeIllustration, EmptyState, PrivacyOverlay, kindIcon,
});

// obscura/screens.jsx — Setup, Auth, LoadingVault. Exports to window.
const { useState: useS3, useEffect: useE3, useRef: useR3 } = React;

const PAD_TOP = 16;   // android chrome (status bar) is drawn by the frame
const PAD_BOT = 16;   // android gesture nav is drawn by the frame

/* corner registration frame (instrument motif) */
function CornerFrame({ color = 'var(--ob-border-2)', size = 11 }) {
  const corner = (pos) => (
    <div style={{ position: 'absolute', width: size, height: size, ...pos }} />
  );
  const L = { borderColor: color, borderStyle: 'solid', position: 'absolute', width: size, height: size };
  return (
    <>
      <div style={{ ...L, top: 0, left: 0, borderWidth: '1.5px 0 0 1.5px' }} />
      <div style={{ ...L, top: 0, right: 0, borderWidth: '1.5px 1.5px 0 0' }} />
      <div style={{ ...L, bottom: 0, left: 0, borderWidth: '0 0 1.5px 1.5px' }} />
      <div style={{ ...L, bottom: 0, right: 0, borderWidth: '0 1.5px 1.5px 0' }} />
    </>
  );
}

/* ============================================================
   SETUP — first launch, choose passphrase
   ============================================================ */
function SetupScreen({ onCreate, lang }) {
  const [pass, setPass] = useS3('');
  const [confirm, setConfirm] = useS3('');
  const { n } = scorePass(pass);
  const longEnough = pass.length >= 8;
  const match = confirm.length > 0 && pass === confirm;
  const mismatch = confirm.length > 0 && pass !== confirm;
  const valid = longEnough && match;

  return (
    <div className="ob-screen">
      <div className="ob-scroll" style={{ padding: `${PAD_TOP}px 22px 0` }}>
        <Wordmark size={20} sub="Sicherer Tresor" />
        <h2 className="display" style={{ fontSize: 30, color: 'var(--ob-fg)', margin: '32px 0 10px', lineHeight: 1.08 }}>
          Tresor<br />einrichten
        </h2>
        <p style={{ fontSize: 14.5, color: 'var(--ob-fg-3)', lineHeight: 1.55, margin: '0 0 26px', maxWidth: 320 }}>
          Wähle eine Passphrase. Sie verschlüsselt alles im Tresor und wird nirgendwo gespeichert.
        </p>

        <label className="overline" style={{ display: 'block', marginBottom: 8 }}>Passphrase</label>
        <PinInput value={pass} onChange={setPass} placeholder="Mindestens 8 Zeichen" autoFocus />
        <div style={{ marginTop: 12 }}><StrengthMeter value={pass} /></div>

        <label className="overline" style={{ display: 'block', margin: '20px 0 8px' }}>Wiederholen</label>
        <PinInput value={confirm} onChange={setConfirm} placeholder="Passphrase erneut eingeben"
          error={mismatch} onSubmit={() => valid && onCreate(pass)} />
        <div style={{ minHeight: 18, marginTop: 8 }}>
          {mismatch && <span className="mono" style={{ fontSize: 11.5, color: 'var(--ob-danger)' }}>Passphrasen stimmen nicht überein</span>}
          {match && <span className="mono" style={{ fontSize: 11.5, color: 'var(--ob-accent)', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="check" size={13} color="var(--ob-accent)" /> Stimmt überein</span>}
        </div>

        <div className="ob-card" style={{ display: 'flex', gap: 11, padding: 14, marginTop: 12, borderColor: 'var(--ob-warn)', background: 'color-mix(in srgb, var(--ob-warn) 9%, var(--ob-surface))' }}>
          <Icon name="alert-triangle" size={18} color="var(--ob-warn)" style={{ marginTop: 1, flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--ob-fg-2)', lineHeight: 1.5 }}>
            Es gibt keine Wiederherstellung. Vergisst du die Passphrase, ist der Tresor unwiederbringlich verloren.
          </span>
        </div>
        <div style={{ height: 20 }} />
      </div>
      <div style={{ padding: `12px 22px ${PAD_BOT}px`, borderTop: '1px solid var(--ob-border)', background: 'var(--ob-bg)' }}>
        <button className="ob-btn ob-btn-primary" disabled={!valid} onClick={() => onCreate(pass)}>
          <Icon name="shield-check" size={19} color={valid ? 'var(--ob-accent-fg)' : 'var(--ob-fg-faint)'} /> Tresor erstellen
        </button>
      </div>
    </div>
  );
}

/* ============================================================
   AUTH — locked, enter passphrase / biometrics
   ============================================================ */
function AuthScreen({ onUnlock, onWipe, attemptsLeft, lang, biometricsOn }) {
  const [pass, setPass] = useS3('');
  const [err, setErr] = useS3(false);
  const [shake, setShake] = useS3(false);
  const [scanning, setScanning] = useS3(false);
  const wrapRef = useR3(null);

  // surface attempt drop from parent → shake + clear
  useE3(() => {
    if (attemptsLeft !== null && attemptsLeft < 5) {
      setErr(true); setPass(''); setShake(true);
      const t = setTimeout(() => setShake(false), 480);
      return () => clearTimeout(t);
    }
  }, [attemptsLeft]);

  const submit = () => {
    if (!pass) return;
    onUnlock(pass); // parent decides correct/incorrect (demo: "obscura" or any 8+)
  };
  const bio = () => {
    setScanning(true);
    setTimeout(() => { setScanning(false); onUnlock('__biometric__'); }, 1400);
  };

  const showCounter = attemptsLeft !== null && attemptsLeft < 5;

  return (
    <div className="ob-screen">
      <div className="ob-scroll" style={{ display: 'flex', flexDirection: 'column', padding: `${PAD_TOP}px 24px ${PAD_BOT}px` }}>
        {/* hero */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', minHeight: 230 }}>
          <div style={{ position: 'relative', width: 116, height: 116, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 26 }}>
            <CornerFrame />
            <VaultMark size={66} spinning={false} />
          </div>
          <div className="wordmark" style={{ fontSize: 22, color: 'var(--ob-fg)' }}>Obscura</div>
          <div className="overline" style={{ marginTop: 12, color: 'var(--ob-accent)' }}>Tresor gesperrt</div>
        </div>

        {/* form */}
        <div ref={wrapRef} className={shake ? 'ob-shake' : ''} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <PinInput value={pass} onChange={(v) => { setPass(v); setErr(false); }} placeholder="Passphrase eingeben"
            error={err} onSubmit={submit} big autoFocus />
          <div style={{ minHeight: 20, textAlign: 'center' }}>
            {showCounter && (
              <span className="mono ob-fadein" style={{ fontSize: 12, color: 'var(--ob-danger)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <Icon name="alert-triangle" size={13} color="var(--ob-danger)" />
                Falsche Passphrase · noch {attemptsLeft} {attemptsLeft === 1 ? 'Versuch' : 'Versuche'}
              </span>
            )}
          </div>
          <button className="ob-btn ob-btn-primary" disabled={!pass} onClick={submit}>
            <Icon name="unlock" size={19} color={pass ? 'var(--ob-accent-fg)' : 'var(--ob-fg-faint)'} /> Entsperren
          </button>
          {biometricsOn && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '4px 0' }}>
                <div style={{ flex: 1, height: 1, background: 'var(--ob-border)' }} />
                <span className="mono" style={{ fontSize: 11, color: 'var(--ob-fg-faint)' }}>oder</span>
                <div style={{ flex: 1, height: 1, background: 'var(--ob-border)' }} />
              </div>
              <BiometricButton onTrigger={bio} scanning={scanning} />
            </>
          )}
          <div style={{ textAlign: 'center', marginTop: 4 }}>
            <span className="mono" style={{ fontSize: 11, color: 'var(--ob-fg-faint)' }}>
              Tipp: Demo-Passphrase „obscura“ entsperrt
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================================================
   LOADING — honest decryption progress (no fake crypto theater)
   ============================================================ */
function LoadingVault({ progress, step }) {
  const pct = Math.round(progress * 100);
  return (
    <div className="ob-screen" style={{ alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', width: '100%', padding: '0 40px' }}>
        {/* decrypt visual: the aperture working — honest "busy", not fake crypto */}
        <div style={{ position: 'relative', width: 120, height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 34 }}>
          <CornerFrame />
          <VaultMark size={70} spinning locked={false} />
        </div>

        <div className="display" style={{ fontSize: 22, color: 'var(--ob-fg)' }}>
          Tresor wird entschlüsselt
        </div>
        <div className="mono" style={{ fontSize: 12, color: 'var(--ob-fg-3)', marginTop: 12, height: 18, textAlign: 'center', letterSpacing: '0.03em' }}>{step}</div>

        {/* progress */}
        <div style={{ width: '100%', maxWidth: 280, marginTop: 28 }}>
          <div style={{ height: 4, background: 'var(--ob-inset)', border: '1px solid var(--ob-border)', overflow: 'hidden' }}>
            <div style={{ height: '100%', width: pct + '%', background: 'var(--ob-accent)', transition: 'width 200ms linear' }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
            <span className="mono" style={{ fontSize: 10.5, color: 'var(--ob-fg-faint)', letterSpacing: '0.06em' }}>HKDF · XCHACHA20 · AES-256</span>
            <span className="mono" style={{ fontSize: 10.5, color: 'var(--ob-fg-3)' }}>{String(pct).padStart(3, '0')}%</span>
          </div>
        </div>
      </div>
      <div style={{ paddingBottom: PAD_BOT, display: 'flex', alignItems: 'center', gap: 7, color: 'var(--ob-fg-faint)' }}>
        <Icon name="clock" size={13} color="var(--ob-fg-faint)" />
        <span style={{ fontSize: 11.5 }}>Schlüsselableitung braucht bewusst etwas Zeit.</span>
      </div>
    </div>
  );
}

Object.assign(window, { SetupScreen, AuthScreen, LoadingVault, PAD_TOP, PAD_BOT });

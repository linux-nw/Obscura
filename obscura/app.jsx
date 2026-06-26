// obscura/app.jsx — Obscura FileVault orchestrator + Tweaks
const { useState: useSA, useEffect: useEA, useRef: useRA } = React;

const DEMO_PASS = 'obscura';

const DECRYPT_STEPS = [
  'Schlüssel wird abgeleitet (HKDF)…',
  'Tresor-Schlüssel wird entpackt…',
  'XChaCha20-Poly1305 · AES-256',
  'Integrität wird geprüft (MAC)…',
  'Index wird geladen…',
];

function ObscuraApp({ tw = {} }) {
  // phase: setup | auth | loading | main
  const [phase, setPhase] = useSA('auth');
  const [attemptsLeft, setAttemptsLeft] = useSA(null); // null = pristine
  const [lockout, setLockout] = useSA(false);
  const [progress, setProgress] = useSA(0);
  const [stepText, setStepText] = useSA(DECRYPT_STEPS[0]);
  const [privacy, setPrivacy] = useSA(false);
  const [store, setStore] = useSA(() => ({
    files: OB_DATA.files.map(f => ({ ...f })),
    notes: OB_DATA.notes.map(n => ({ ...n })),
    autoLock: 1,
    biometrics: true,
    privacyShield: true,
  }));

  const maxAttempts = tw.maxAttempts || 5;
  const unlockMs = (tw.unlockSeconds != null ? tw.unlockSeconds : 3.5) * 1000;
  const accent = tw.accent || '#2FB46F';
  const warm = tw.warmth === 'Warm';
  const emptyStart = tw.startEmpty;

  // apply empty-start tweak
  useEA(() => {
    if (emptyStart) setStore(s => ({ ...s, files: [], notes: [] }));
    else setStore(s => ({ ...s, files: OB_DATA.files.map(f => ({ ...f })), notes: OB_DATA.notes.map(n => ({ ...n })) }));
  }, [emptyStart]);

  // jump to a phase via tweak (lets reviewer inspect any screen)
  useEA(() => {
    if (!tw.jumpTo) return;
    if (tw.jumpTo === 'Ersteinrichtung') setPhase('setup');
    else if (tw.jumpTo === 'Sperrbildschirm') { setPhase('auth'); setAttemptsLeft(null); setLockout(false); }
    else if (tw.jumpTo === 'Entsperren läuft') startUnlockAnim();
    else if (tw.jumpTo === 'Tresor (entsperrt)') setPhase('main');
    else if (tw.jumpTo === 'Lockout / Wipe') { setPhase('auth'); setLockout(true); }
  }, [tw.jumpTo]);

  const accentBright = shade(accent, 12);
  const accentFg = pickFg(accent);

  const animRef = useRA(null);
  const startUnlockAnim = () => {
    setPhase('loading'); setProgress(0); setStepText(DECRYPT_STEPS[0]);
    const start = Date.now();
    if (animRef.current) clearInterval(animRef.current);
    animRef.current = setInterval(() => {
      const p = Math.min(1, (Date.now() - start) / unlockMs);
      setProgress(p);
      const idx = Math.min(DECRYPT_STEPS.length - 1, Math.floor(p * DECRYPT_STEPS.length));
      setStepText(DECRYPT_STEPS[idx]);
      if (p >= 1) {
        clearInterval(animRef.current); animRef.current = null;
        setTimeout(() => setPhase('main'), 220);
      }
    }, 90);
  };
  useEA(() => () => { if (animRef.current) clearInterval(animRef.current); }, []);

  const handleUnlock = (pass) => {
    const correct = pass === '__biometric__' || pass === DEMO_PASS;
    if (correct) { setAttemptsLeft(null); startUnlockAnim(); return; }
    const used = (attemptsLeft === null ? 0 : maxAttempts - attemptsLeft) + 1;
    const left = maxAttempts - used;
    if (left <= 0) { setLockout(true); setAttemptsLeft(0); }
    else setAttemptsLeft(left);
  };

  const handleCreate = () => { setAttemptsLeft(null); startUnlockAnim(); };
  const lockNow = () => { setPhase('auth'); setAttemptsLeft(null); setLockout(false); };
  const wipe = () => {
    setStore(s => ({ ...s, files: [], notes: [] }));
    setLockout(false); setAttemptsLeft(null); setPhase('setup');
  };

  const lang = tw.lang || 'Deutsch';

  return (
    <div className={'ob-app' + (warm ? ' warm' : '')}
      style={{ position: 'relative', flex: 1, width: '100%', height: '100%', overflow: 'hidden', background: 'var(--ob-bg)',
        '--ob-accent': accent, '--ob-accent-bright': accentBright, '--ob-accent-fg': accentFg }}>
      {phase === 'setup' && <SetupScreen onCreate={handleCreate} lang={lang} />}
      {phase === 'auth' && <AuthScreen onUnlock={handleUnlock} attemptsLeft={attemptsLeft}
        biometricsOn={store.biometrics} lang={lang} />}
      {phase === 'loading' && <LoadingVault progress={progress} step={stepText} />}
      {phase === 'main' && <MainScreen store={store} setStore={setStore} onLock={lockNow}
        onWipe={wipe} onPrivacy={() => store.privacyShield && setPrivacy(true)} lang={lang} />}

      {/* lockout wipe — forced, blocks everything */}
      {lockout && <WipeDialog forced onWiped={wipe} />}

      {/* privacy overlay */}
      {privacy && <PrivacyOverlay onDismiss={() => setPrivacy(false)} />}
    </div>
  );
}

/* --- tiny color helpers --- */
function shade(hex, amt) {
  const c = hex.replace('#', '');
  const r = Math.min(255, parseInt(c.slice(0, 2), 16) + amt);
  const g = Math.min(255, parseInt(c.slice(2, 4), 16) + amt);
  const b = Math.min(255, parseInt(c.slice(4, 6), 16) + amt);
  return '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');
}
function pickFg(hex) {
  const c = hex.replace('#', '');
  const r = parseInt(c.slice(0, 2), 16), g = parseInt(c.slice(2, 4), 16), b = parseInt(c.slice(4, 6), 16);
  const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return lum > 0.6 ? '#0A1410' : '#04140C';
}

window.ObscuraApp = ObscuraApp;

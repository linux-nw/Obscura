/**
 * Attack_App_Static — grep-style red-team assertions over src/, config and gradle.
 */
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');
const walk = (d: string, out: string[] = []): string[] => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p, out); else if (/\.(ts|tsx|js|jsx)$/.test(e.name)) out.push(p);
  }
  return out;
};
const files = [...walk(path.join(ROOT, 'src')), path.join(ROOT, 'App.tsx'), path.join(ROOT, 'index.ts')];
const read = (f: string) => fs.readFileSync(f, 'utf8').replace(/\r\n/g, '\n');
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
const rel = (f: string) => path.relative(ROOT, f);
const hits = (re: RegExp, ex: (f: string) => boolean = () => false) =>
  files.filter((f) => !ex(f)).flatMap((f) => strip(read(f)).split('\n').map((l, i) => ({ f: rel(f), i: i + 1, l })).filter((x) => re.test(x.l)).map((x) => `${x.f}:${x.i}: ${x.l.trim()}`));

describe('Attack_App_Static: source hygiene', () => {
  test('no console.* call interpolates secret-looking identifiers', () => {
    const re = /console\.(log|debug|info|warn|error)\([^)]*\b(pass(word|phrase)?|pin|secret|masterKey|kek|privateKey|plaintext|mnemonic|token|entered)\b(?!\s*:)/i;
    // allow plain string-literal-only messages containing the words (no ${} / concatenation of a variable)
    const bad = hits(re).filter((h) => /\$\{[^}]*\b(pass|pin|secret|masterKey|kek|privateKey|plaintext|entered|token)/i.test(h) || /,\s*(pass|passphrase|password|pin|secret|masterKey|kek|entered|plaintext)\b/i.test(h) || /\+\s*(pass|passphrase|password|pin|secret|masterKey|kek|entered)\b/i.test(h));
    expect(bad).toEqual([]);
  });
  test('console.log never prints key/hash material (no hex/key variables)', () => {
    expect(hits(/console\.log\([^)]*\$\{[^}]*\b(key|hash|salt|mac|iv|digest)\b[^}]*\}/i)).toEqual([]);
  });
  test('no react-native Modal import in src/ (SecureModal only)', () => {
    const bad = files.filter((f) => !f.endsWith('SecureModal.tsx')).filter((f) => {
      const s = strip(read(f));
      const m = s.match(/import\s*\{([^}]*)\}\s*from\s*['"]react-native['"]/g) || [];
      return m.some((x) => /\bModal\b/.test(x)) || /<Modal[\s>]/.test(s);
    }).map(rel);
    expect(bad).toEqual([]);
  });
  test('Math.random only in the clearly-marked fuzz helpers of PenTestService', () => {
    expect(hits(/Math\.random/, (f) => f.endsWith('PenTestService.ts'))).toEqual([]);
    const pen = strip(read(path.join(ROOT, 'src/services/PenTestService.ts')));
    // every use is inside generateRandomBuffer / generateFuzzedString
    const fn = (n: string) => { const i = pen.indexOf(`static ${n}`); return pen.slice(i, pen.indexOf('\n  }\n', i)); };
    const inFuzz = (fn('generateRandomBuffer').match(/Math\.random/g) || []).length + (fn('generateFuzzedString').match(/Math\.random/g) || []).length;
    expect(inFuzz).toBe((pen.match(/Math\.random/g) || []).length);
  });
  test('no eval / new Function / string timers / dangerouslySetInnerHTML', () => {
    expect(hits(/\beval\s*\(|new\s+Function\s*\(|\bsetTimeout\s*\(\s*['"`]|\bsetInterval\s*\(\s*['"`]|dangerouslySetInnerHTML/)).toEqual([]);
  });
  test('no cleartext http:// URLs (excluding XML/SVG namespaces)', () => {
    expect(hits(/http:\/\/(?!www\.w3\.org\/)/)).toEqual([]);
  });
  test('no hard-coded keys / secrets / bearer tokens / PEM blocks / long hex literals', () => {
    expect(hits(/(api[_-]?key|secret|passw(or)?d|private[_-]?key|auth[_-]?token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i)).toEqual([]);
    expect(hits(/-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----|AKIA[0-9A-Z]{16}|\bBearer\s+[A-Za-z0-9._-]{16,}/)).toEqual([]);
    expect(hits(/['"][0-9a-fA-F]{64}['"]/, (f) => /KAT|Argon2|fixtures/i.test(f))).toEqual([]);
  });
  test('no network egress APIs in src (fetch/XMLHttpRequest/WebSocket) — vault is offline', () => {
    expect(hits(/\bfetch\s*\(|XMLHttpRequest|new\s+WebSocket|axios/)).toEqual([]);
  });
  test('no AsyncStorage use for sensitive material (only removal of legacy keys)', () => {
    const uses = hits(/AsyncStorage\.(setItem|getItem|multiSet)/);
    expect(uses).toEqual([]);
  });
  test('Alert/UI messages never echo the entered passphrase', () => {
    expect(hits(/(Alert\.alert|showError)\([^)]*\$\{[^}]*\b(entered|pass|passphrase|pin)\b/)).toEqual([]);
  });
});

describe('Attack_App_Static: config', () => {
  const app = JSON.parse(read(path.join(ROOT, 'app.json'))).expo;
  const DANGEROUS = ['SYSTEM_ALERT_WINDOW', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE', 'RECORD_AUDIO',
    'READ_SMS', 'SEND_SMS', 'READ_CONTACTS', 'READ_PHONE_STATE', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'INTERNET',
    'REQUEST_INSTALL_PACKAGES', 'QUERY_ALL_PACKAGES', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'BIND_ACCESSIBILITY_SERVICE', 'CAMERA'];
  test('allowBackup is false', () => { expect(app.android.allowBackup).toBe(false); });
  test('no dangerous permission requested', () => {
    const req: string[] = (app.android.permissions || []).map((p: string) => p.replace('android.permission.', ''));
    expect(req.filter((p) => DANGEROUS.includes(p))).toEqual([]);
  });
  test('dangerous permissions are explicitly blocked', () => {
    const blocked: string[] = (app.android.blockedPermissions || []).map((p: string) => p.replace('android.permission.', ''));
    for (const p of ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'SYSTEM_ALERT_WINDOW', 'RECORD_AUDIO']) expect(blocked).toContain(p);
  });
  test('no usesCleartextTraffic / no plugin enabling it', () => {
    const raw = read(path.join(ROOT, 'app.json'));
    expect(raw).not.toMatch(/usesCleartextTraffic["']?\s*:\s*true/i);
    expect(raw).not.toMatch(/http:\/\//);
  });
  test('no secrets in app.json / package.json scripts', () => {
    expect(read(path.join(ROOT, 'app.json'))).not.toMatch(/(api[_-]?key|secret|token|password)["']?\s*:/i);
  });
  test('checked-in AndroidManifest (if any) is not debuggable / backup-enabled / cleartext', () => {
    const p = path.join(ROOT, 'android/app/src/main/AndroidManifest.xml');
    if (!fs.existsSync(p)) return;
    const m = read(p);
    expect(m).not.toMatch(/android:debuggable="true"/);
    expect(m).not.toMatch(/android:allowBackup="true"/);
    expect(m).not.toMatch(/usesCleartextTraffic="true"/);
    expect(m).not.toMatch(/exported="true"(?![^>]*intent-filter)/);
  });
});

describe('Attack_App_Static: android build.gradle release', () => {
  const g = read(path.join(ROOT, 'android/app/build.gradle'));
  const rel = g.slice(g.indexOf('release {', g.indexOf('buildTypes')));
  const relBlock = rel.slice(0, rel.indexOf('}'));
  test('release is minified, shrunk, not debuggable, not signed with debug key', () => {
    expect(relBlock).toMatch(/minifyEnabled\s+(true|enableMinifyInReleaseBuilds)/);
    expect(relBlock).toMatch(/shrinkResources\s+true/);
    expect(relBlock).toMatch(/debuggable\s+false/);
    expect(relBlock).not.toMatch(/signingConfigs\.debug/);
    expect(g).toMatch(/def enableMinifyInReleaseBuilds\s*=\s*true/);
  });
  test('no keystore password literals committed', () => {
    expect(g).not.toMatch(/(storePassword|keyPassword)\s*['"=]\s*['"][^'"]+['"]/);
  });
  test('gradle.properties does not disable minify or ship passwords', () => {
    const p = path.join(ROOT, 'android/gradle.properties');
    if (!fs.existsSync(p)) return;
    const s = read(p);
    expect(s).not.toMatch(/enableMinifyInReleaseBuilds\s*=\s*false/);
    expect(s).not.toMatch(/(STORE_PASSWORD|KEY_PASSWORD)\s*=\s*\S+/);
  });
});

describe('Attack_App_Static: Kotlin review invariants', () => {
  const dir = path.join(ROOT, 'android/app/src/main/java/com/filevault/app');
  const kt = (() => { const o: string[] = []; const w = (d: string) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => { const p = path.join(d, e.name); e.isDirectory() ? w(p) : p.endsWith('.kt') && o.push(p); }); w(dir); return o; })();
  test('no logging of secrets from native code', () => {
    for (const f of kt) expect(read(f)).not.toMatch(/Log\.[dviwe]\([^)]*(key|pass|secret|pin)/i);
  });
  test('no clearFlags(FLAG_SECURE), no setWebContentsDebuggingEnabled, no http:// in native code', () => {
    for (const f of kt) {
      const s = read(f);
      expect(s).not.toMatch(/clearFlags\([^)]*FLAG_SECURE/);
      expect(s).not.toMatch(/setWebContentsDebuggingEnabled\(\s*true/);
      expect(s).not.toMatch(/http:\/\/(?!www\.w3\.org)/);
    }
  });
  test('signature compare is constant-time and an empty pin is never "valid"', () => {
    const s = read(path.join(dir, 'modules/IntegrityModule.kt'));
    expect(s).toMatch(/constantTimeStringEquals/);
    expect(s).not.toMatch(/actual(Hash)?\s*==\s*expected/);
    expect(s).toMatch(/if \(expected\.isEmpty\(\)\)[\s\S]{0,200}"isValid", false/);
  });
});

// Real-disk-backed replacements for expo-file-system/legacy and expo-secure-store,
// used ONLY by the crash-kill test harness (scripts/crash-test/). Unlike the normal
// Jest mocks (__mocks__/expo-file-system.js, __mocks__/expo-secure-store.js), which
// back onto an in-memory Map that dies with the process, these read/write REAL files
// under CRASH_TEST_DIR - so state survives a real `kill -9` of the process that wrote
// it, which is the whole point of this harness (see orchestrate.js).
//
// Plain CommonJS, no TypeScript - required directly from inside a jest.mock() factory
// in the phase1/phase2 test files, so it must not need any transform.

const fs = require('fs');
const path = require('path');

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

// Module-level (not per-instance) hang-arming state. Seeding the vault (importFile,
// createNote) burns through its own moveAsync calls via writeFileAtomic before a
// rotation ever starts, so counting from process start would hit an unpredictable call
// number depending on how much was seeded. Instead, the test arms hang-mode via
// armHangAfterMoveCalls() right before starting the rotation it actually wants to
// interrupt, and only calls made from that point on are counted.
let hangArmed = false;
let hangAfterCount = 0;
let movesSinceArmed = 0;

function armHangAfterMoveCalls(n) {
  hangArmed = true;
  hangAfterCount = n;
  movesSinceArmed = 0;
}

function makeFileSystemMock(baseDir) {
  const documentsDir = path.join(baseDir, 'documents') + path.sep;
  ensureDir(documentsDir);

  const toRealPath = (p) => {
    // Mirror the shape the app uses: 'documentDirectory' is a '/'-style prefix the app
    // string-concatenates paths onto (e.g. `${documentDirectory}vault/${fileName}`).
    if (!p.startsWith(documentsDir)) {
      throw new Error(`diskMocks: path escapes sandbox: ${p}`);
    }
    return p;
  };

  return {
    documentDirectory: documentsDir,
    cacheDirectory: path.join(baseDir, 'cache') + path.sep,
    EncodingType: { UTF8: 'utf8', Base64: 'base64' },

    writeAsStringAsync: jest.fn(async (p, data) => {
      const real = toRealPath(p);
      ensureDir(path.dirname(real));
      fs.writeFileSync(real, data, 'utf8');
    }),

    readAsStringAsync: jest.fn(async (p) => {
      const real = toRealPath(p);
      if (!fs.existsSync(real)) throw new Error(`ENOENT: ${p}`);
      return fs.readFileSync(real, 'utf8');
    }),

    deleteAsync: jest.fn(async (p, opts) => {
      const real = toRealPath(p);
      try {
        const st = fs.statSync(real);
        if (st.isDirectory()) fs.rmSync(real, { recursive: true, force: true });
        else fs.unlinkSync(real);
      } catch (e) {
        if (!(opts && opts.idempotent)) throw e;
      }
    }),

    // See armHangAfterMoveCalls() above: after arming, the Nth rename FROM THAT POINT
    // writes a marker file and hangs forever, so the orchestrator's SIGKILL lands
    // exactly between two chosen renames instead of at an unpredictable point that also
    // depends on how much seeding happened first.
    moveAsync: jest.fn(async ({ from, to }) => {
      const realFrom = toRealPath(from);
      const realTo = toRealPath(to);
      ensureDir(path.dirname(realTo));
      fs.renameSync(realFrom, realTo);

      if (hangArmed) {
        movesSinceArmed += 1;
        if (process.env.CRASH_TEST_VERBOSE) {
          process.stderr.write(`[diskMocks] moveAsync (armed) #${movesSinceArmed}: ${from} -> ${to}\n`);
        }
        if (movesSinceArmed === hangAfterCount) {
          fs.writeFileSync(path.join(baseDir, 'KILL_ME_NOW'), String(process.pid));
          await new Promise(() => {}); // never resolves - orchestrator SIGKILLs us here
        }
      }
    }),

    makeDirectoryAsync: jest.fn(async (p) => {
      ensureDir(toRealPath(p));
    }),

    copyAsync: jest.fn(async ({ from, to }) => {
      const realFrom = toRealPath(from);
      const realTo = toRealPath(to);
      ensureDir(path.dirname(realTo));
      fs.copyFileSync(realFrom, realTo);
    }),

    getInfoAsync: jest.fn(async (p) => {
      const real = toRealPath(p);
      if (!fs.existsSync(real)) return { exists: false, isDirectory: false, size: 0 };
      const st = fs.statSync(real);
      return { exists: true, isDirectory: st.isDirectory(), size: st.size };
    }),

    readDirectoryAsync: jest.fn(async (p) => {
      const real = toRealPath(p);
      if (!fs.existsSync(real)) return [];
      return fs.readdirSync(real);
    }),
  };
}

function makeSecureStoreMock(baseDir) {
  const storeFile = path.join(baseDir, 'securestore.json');

  const load = () => {
    if (!fs.existsSync(storeFile)) return {};
    return JSON.parse(fs.readFileSync(storeFile, 'utf8'));
  };
  const save = (obj) => {
    ensureDir(path.dirname(storeFile));
    // Real-disk write+rename here too - a torn write of the secure-store file itself
    // is a separate, narrower concern than what this harness is proving (the
    // content/meta cross-file rotation atomicity), so keep it simple but still safe.
    const tmp = storeFile + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj), 'utf8');
    fs.renameSync(tmp, storeFile);
  };

  return {
    getItemAsync: jest.fn(async (key) => {
      const obj = load();
      return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : null;
    }),
    setItemAsync: jest.fn(async (key, value) => {
      const obj = load();
      obj[key] = value;
      save(obj);
    }),
    deleteItemAsync: jest.fn(async (key) => {
      const obj = load();
      delete obj[key];
      save(obj);
    }),
  };
}

module.exports = { makeFileSystemMock, makeSecureStoreMock, armHangAfterMoveCalls };

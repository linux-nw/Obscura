#!/usr/bin/env node
/**
 * Real kill-9 crash test for FileManager.reencryptAll's cross-file (content + meta)
 * rotation atomicity fix.
 *
 * Runs phase1 (seed + start a real rotation) as a genuinely separate child process
 * against real on-disk state, waits for it to reach the exact crash window under test,
 * sends it a real SIGKILL (uncatchable - the same signal `kill -9` sends), then runs
 * phase2 (simulating an app restart) as ANOTHER separate process against the same
 * directory and checks that every file survived in a correctly-decryptable state.
 *
 * Usage: node scripts/crash-test/orchestrate.js
 * Exit code 0 = the fix holds up under a real kill -9. Non-zero = it does not.
 */

const { spawnSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const JEST_BIN = path.join(ROOT, 'node_modules', '.bin', 'jest');
const CONFIG = path.join(ROOT, 'jest.crashtest.config.js');

function log(msg) {
  process.stdout.write(`[orchestrate] ${msg}\n`);
}

async function waitForFile(filePath, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (fs.existsSync(filePath)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

async function main() {
  const crashDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obscura-crashtest-'));
  log(`working directory: ${crashDir}`);

  // ── Phase 1: seed + rotate, run as a real child process, kill it for real ──────────
  log('starting phase1 (seed vault, begin real rotation) as a child process...');
  const phase1 = spawn(
    JEST_BIN,
    ['--config', CONFIG, 'phase1-seed-and-crash'],
    {
      cwd: ROOT,
      env: {
        ...process.env,
        CRASH_TEST_DIR: crashDir,
        CRASH_TEST_VERBOSE: '1',
        // reencryptAll makes 4 moveAsync calls per file: writeFileAtomic's own internal
        // .tmp-rename for the content stage, same for the meta stage, then the two
        // commit-renames (stage->final for content, then for meta). Calls 5-8 are file
        // #2's; call #7 is its content COMMIT rename, call #8 its meta COMMIT rename -
        // hanging after #7 lands exactly between them, the precise window under test.
        CRASH_TEST_HANG_ON_MOVE_CALL: '7',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );

  let phase1Out = '';
  phase1.stdout.on('data', (d) => { phase1Out += d; });
  phase1.stderr.on('data', (d) => { phase1Out += d; });

  const markerPath = path.join(crashDir, 'KILL_ME_NOW');
  const sawMarker = await waitForFile(markerPath, 30000);
  if (!sawMarker) {
    phase1.kill('SIGKILL');
    log('--- phase1 output ---\n' + phase1Out);
    throw new Error('phase1 never reached the crash marker within 30s - see output above');
  }

  const killedPid = fs.readFileSync(markerPath, 'utf8').trim();
  log(`crash marker seen (phase1 pid ${killedPid}, node child pid ${phase1.pid}) - sending SIGKILL now`);

  // SIGKILL the whole process tree: `jest` may run the actual test in a worker process,
  // not the `jest` CLI process itself. Kill the worker pid recorded in the marker file
  // (the process that was actually executing the mock/hang code) AND the parent jest
  // CLI process, so nothing keeps running.
  try { process.kill(parseInt(killedPid, 10), 'SIGKILL'); } catch { /* already gone */ }
  phase1.kill('SIGKILL');

  const phase1Exit = await new Promise((resolve) => {
    phase1.on('exit', (code, signal) => resolve({ code, signal }));
  });
  log(`phase1 process exited: code=${phase1Exit.code} signal=${phase1Exit.signal}`);
  if (phase1Exit.signal !== 'SIGKILL') {
    log('--- phase1 output ---\n' + phase1Out);
    throw new Error(`expected phase1 to die by SIGKILL, got signal=${phase1Exit.signal} code=${phase1Exit.code}`);
  }

  // Prove the crash really did leave the exact inconsistent intermediate state on disk
  // (belt-and-suspenders check, independent of whatever phase2 does next): file #3's
  // content should already be renamed into place while its meta '.rotnew' stage file
  // should still be sitting there, un-renamed.
  const vaultDir = path.join(crashDir, 'documents', 'vault');
  const vaultListing = fs.readdirSync(vaultDir);
  const staleMetaStage = vaultListing.filter((f) => f.endsWith('.meta.enc.rotnew'));
  if (staleMetaStage.length === 0) {
    log(`vault dir contents at crash time: ${vaultListing.join(', ')}`);
    log('--- phase1 output ---\n' + phase1Out);
    throw new Error('expected a leftover *.meta.enc.rotnew stage file after the kill - crash point missed');
  }
  log(`confirmed real on-disk crash artifact: ${staleMetaStage.join(', ')}`);

  // ── Phase 2: fresh process, simulate "app restart", verify recovery ────────────────
  log('starting phase2 (fresh process, resume + verify) as a child process...');
  const phase2 = spawnSync(
    JEST_BIN,
    ['--config', CONFIG, 'phase2-resume-and-verify'],
    {
      cwd: ROOT,
      env: { ...process.env, CRASH_TEST_DIR: crashDir },
      encoding: 'utf8',
    }
  );

  log('--- phase2 output ---\n' + (phase2.stdout || '') + (phase2.stderr || ''));

  if (phase2.status !== 0) {
    throw new Error(`phase2 (resume + verify) FAILED with exit code ${phase2.status}`);
  }

  // No leftover staging artifacts after a clean resume.
  const leftovers = fs.readdirSync(vaultDir).filter((f) => f.endsWith('.rotnew'));
  if (leftovers.length > 0) {
    throw new Error(`resume left stage files behind: ${leftovers.join(', ')}`);
  }

  log('PASS: killed the rotation process with a real SIGKILL exactly between one file\'s');
  log('content-rename and meta-rename, confirmed the resulting on-disk inconsistency,');
  log('then verified a fresh process resumes and every file (including the one caught');
  log('mid-rename and the one never touched) decrypts correctly under the new key.');

  fs.rmSync(crashDir, { recursive: true, force: true });
}

main().catch((err) => {
  console.error(`[orchestrate] FAIL: ${err.message}`);
  process.exit(1);
});

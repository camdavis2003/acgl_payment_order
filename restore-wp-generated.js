/*
  Restores generated WordPress app mirror files back to HEAD so local build/package
  workflows can produce zips without leaving the repository dirty.
*/

const { spawnSync } = require('child_process');
const path = require('path');

const ROOT = __dirname;
const TARGET = path.join('wp-plugin', 'acgl-fms', 'app');

function run(args) {
  const res = spawnSync('git', args, {
    cwd: ROOT,
    stdio: 'inherit',
    shell: false,
    windowsHide: true,
  });
  if (res.error) throw res.error;
  return typeof res.status === 'number' ? res.status : 1;
}

function main() {
  const inGit = run(['rev-parse', '--is-inside-work-tree']) === 0;
  if (!inGit) {
    console.log('Not a git work tree; skipping generated-file restore.');
    return;
  }

  const status = run(['restore', '--worktree', TARGET]);
  if (status !== 0) {
    throw new Error('Failed to restore generated WP app mirror files.');
  }

  console.log(`Restored generated files: ${TARGET}`);
}

main();

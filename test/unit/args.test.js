import test from 'node:test';
import assert from 'node:assert/strict';
import { buildArgs, tokenize, formatCommand, parseTargets } from '../../lib/args.js';

test('tokenize splits on whitespace and honors quotes', () => {
  assert.deepEqual(tokenize('--script "a b" c'), ['--script', 'a b', 'c']);
  assert.deepEqual(tokenize("--script 'a b' c"), ['--script', 'a b', 'c']);
});

test('tokenize supports backslash escapes', () => {
  assert.deepEqual(tokenize('a\\ b'), ['a b']);
  assert.deepEqual(tokenize('"quote \\" inside"'), ['quote " inside']);
});

test('tokenize rejects unterminated quotes', () => {
  assert.throws(() => tokenize('"open'), /Unterminated quote/);
});

test('parseTargets splits on whitespace and commas', () => {
  assert.deepEqual(parseTargets('192.168.1.1, example.com\n10.0.0.0/24'), [
    '192.168.1.1',
    'example.com',
    '10.0.0.0/24'
  ]);
  assert.deepEqual(parseTargets('  '), []);
});

test('buildArgs maps presets', () => {
  const { args, targets } = buildArgs({ profile: 'quick', targets: '127.0.0.1' });
  assert.deepEqual(args, ['-T4', '-F']);
  assert.deepEqual(targets, ['127.0.0.1']);
});

test('buildArgs unknown profile falls back to custom', () => {
  const { args } = buildArgs({ profile: 'does-not-exist', targets: 'h', options: { scanType: 'connect' } });
  assert.deepEqual(args, ['-sT']);
});

test('buildArgs custom options produce expected argv', () => {
  const { args } = buildArgs({
    profile: 'custom',
    targets: 'h',
    options: {
      scanType: 'udp',
      ports: 'top',
      topPorts: '50',
      ping: { skip: true, dns: 'never' },
      service: { version: true },
      scripts: { list: 'vuln' },
      timing: { template: '4' },
      extraArgs: '--spoof-mac "aa:bb:cc"'
    }
  });
  assert.deepEqual(args, [
    '-sU',
    '--top-ports', '50',
    '-Pn',
    '-n',
    '-sV',
    '--script', 'vuln',
    '-T4',
    '--spoof-mac', 'aa:bb:cc'
  ]);
});

test('buildArgs throws without targets', () => {
  assert.throws(() => buildArgs({ profile: 'regular', targets: '' }), /No targets specified/);
});

test('formatCommand quotes args containing whitespace', () => {
  assert.equal(
    formatCommand(['-p', '1-2', '--script', 'a b']),
    'nmap -p 1-2 --script "a b"'
  );
});

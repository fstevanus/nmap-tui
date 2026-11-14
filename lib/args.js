// Nmap argument builder: turns a scan request (preset + structured options)
// into an argv array for `nmap`.

export const PRESETS = [
  { id: 'regular', label: 'Regular scan', desc: 'Default: 1000 most common TCP ports, SYN stealth.' },
  { id: 'quick', label: 'Quick scan', desc: 'Top 100 ports, timing template 4. Fast first look.' },
  { id: 'quickPlus', label: 'Quick scan plus', desc: 'Quick scan + service/version and OS detection.' },
  { id: 'pingSweep', label: 'Ping sweep', desc: 'Find which hosts are online. No port scan.' },
  { id: 'quickTraceroute', label: 'Quick traceroute', desc: 'Ping sweep plus traceroute to each host.' },
  { id: 'intense', label: 'Intense scan', desc: '-T4 -A -v: OS, versions, scripts, traceroute.' },
  { id: 'intenseUdp', label: 'Intense scan + UDP', desc: 'Intense scan including common UDP ports.' },
  { id: 'intenseAllTcp', label: 'Intense scan, all TCP ports', desc: 'All 65535 TCP ports, -T4 -A -v.' },
  { id: 'intenseAllPlusUdp', label: 'Intense scan, all ports + UDP', desc: 'All TCP and UDP ports, -T4 -A -v.' },
  { id: 'intenseNoPing', label: 'Intense scan, no ping', desc: 'Skips host discovery (-Pn). For firewalled hosts.' },
  { id: 'fullPortSyn', label: 'Full port SYN scan', desc: 'All 65535 TCP ports, SYN stealth, -T4.' },
  { id: 'vuln', label: 'Vulnerability scan', desc: '-sV plus the vuln NSE script category. Use responsibly.' },
  { id: 'slowComprehensive', label: 'Slow comprehensive scan', desc: 'TCP+UDP, many ping probes, discovery+safe scripts.' },
  { id: 'custom', label: 'Custom', desc: 'Compose your own scan from the options below.' }
];

const PRESET_ARGS = {
  regular: [],
  quick: ['-T4', '-F'],
  quickPlus: ['-sV', '-T4', '-O', '-F'],
  pingSweep: ['-sn'],
  quickTraceroute: ['-sn', '--traceroute'],
  intense: ['-T4', '-A', '-v'],
  intenseUdp: ['-sS', '-sU', '-T4', '-A', '-v'],
  intenseAllTcp: ['-p', '1-65535', '-T4', '-A', '-v'],
  intenseAllPlusUdp: ['-sS', '-sU', '-T4', '-A', '-v', '-p', '1-65535'],
  intenseNoPing: ['-T4', '-A', '-v', '-Pn'],
  fullPortSyn: ['-sS', '-p-', '-T4'],
  vuln: ['-Pn', '-sV', '--script=vuln'],
  slowComprehensive: [
    '-sS', '-sU', '-T4', '-A', '-v',
    '-PE', '-PP', '-PS80,443', '-PA3389', '-PU40125', '-PY', '-g', '53',
    '--script', 'default or (discovery and safe)'
  ]
};

const SCAN_TYPES = {
  syn: ['-sS'],
  connect: ['-sT'],
  udp: ['-sU'],
  ack: ['-sA'],
  window: ['-sW'],
  maimon: ['-sM'],
  fin: ['-sF'],
  xmas: ['-sX'],
  null: ['-sN'],
  sctpInit: ['-sY'],
  sctpCookie: ['-sZ'],
  pingSweep: ['-sn'],
  list: ['-sL'],
  none: []
};

/**
 * Split an extra-args string into argv tokens, honoring single/double quotes
 * and backslash escapes (shell-like).
 */
export function tokenize(str) {
  const out = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < str.length && '\\"'.includes(str[i + 1])) { cur += str[i + 1]; i++; }
      else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '\\' && i + 1 < str.length) {
      cur += str[i + 1]; i++;
    } else if (/\s/.test(c)) {
      if (cur) { out.push(cur); cur = ''; }
    } else {
      cur += c;
    }
  }
  if (cur) out.push(cur);
  if (quote) throw new Error(`Unterminated quote in extra arguments: ${quote}`);
  return out;
}

function isBlank(v) {
  return v === undefined || v === null || String(v).trim() === '';
}

/** Parse the free-form targets field into a list of target tokens. */
const TARGET_RE = /^[A-Za-z0-9.\-:/\[\]]+$/;

/** Parse the free-form targets field into a list of target tokens. */
export function parseTargets(raw) {
  if (isBlank(raw)) return [];
  const tokens = [];
  for (const chunk of String(raw).split(/[\s,]+/)) {
    const t = chunk.trim();
    if (!t) continue;
    if (!TARGET_RE.test(t)) {
      throw new Error(`Invalid target: ${t}`);
    }
    tokens.push(t);
  }
  return tokens;
}

/**
 * Build the nmap argv for a scan request.
 * @param {{profile: string, targets: string, options: object}} req
 * @returns {{args: string[], targets: string[]}}
 */
export function buildArgs(req) {
  const profile = req.profile && PRESET_ARGS[req.profile] ? req.profile : 'custom';
  const o = req.options || {};
  const args = [];

  if (profile !== 'custom') {
    args.push(...PRESET_ARGS[profile]);
  } else {
    // --- Scan technique ---
    args.push(...(SCAN_TYPES[o.scanType] || []));

    // --- Ports ---
    const p = o.ports;
    if (p === 'all') args.push('-p-');
    else if (p === 'fast') args.push('-F');
    else if (p === 'top') args.push('--top-ports', isBlank(o.topPorts) ? '100' : String(o.topPorts));
    else if (p === 'list' && !isBlank(o.portList)) args.push('-p', String(o.portList).trim());

    // --- Host discovery ---
    const ping = o.ping || {};
    if (ping.skip) args.push('-Pn');
    if (!isBlank(ping.synPorts)) args.push(`-PS${ping.synPorts.trim()}`);
    if (!isBlank(ping.ackPorts)) args.push(`-PA${ping.ackPorts.trim()}`);
    if (!isBlank(ping.udpPorts)) args.push(`-PU${ping.udpPorts.trim()}`);
    if (ping.icmpEcho) args.push('-PE');
    if (ping.icmpTimestamp) args.push('-PP');
    if (ping.icmpNetmask) args.push('-PM');
    if (ping.disableArp) args.push('--disable-arp-ping');
    if (ping.dns === 'never') args.push('-n');
    else if (ping.dns === 'always') args.push('-R');

    // --- Service / version / OS ---
    const svc = o.service || {};
    if (svc.version) {
      args.push('-sV');
      if (svc.light) args.push('--version-light');
      else if (svc.all) args.push('--version-all');
      else if (!isBlank(svc.intensity)) args.push('--version-intensity', String(svc.intensity));
    }
    const os = o.os || {};
    if (os.detect || o.aggressive) {
      args.push('-O');
      if (os.guess) args.push('--osscan-guess');
    }
    if (o.aggressive) args.push('-A');

    // --- NSE scripts ---
    const scripts = o.scripts || {};
    if (scripts.defaults) args.push('-sC');
    if (!isBlank(scripts.list)) args.push('--script', String(scripts.list).trim());
    if (!isBlank(scripts.args)) args.push('--script-args', String(scripts.args).trim());
    if (scripts.trace) args.push('--script-trace');

    // --- Timing & performance ---
    const t = o.timing || {};
    if (!isBlank(t.template)) args.push(`-T${t.template}`);
    if (!isBlank(t.minRate)) args.push('--min-rate', String(t.minRate));
    if (!isBlank(t.maxRate)) args.push('--max-rate', String(t.maxRate));
    if (!isBlank(t.hostTimeout)) args.push('--host-timeout', String(t.hostTimeout));
    if (!isBlank(t.scanDelay)) args.push('--scan-delay', String(t.scanDelay));
    if (!isBlank(t.maxRetries)) args.push('--max-retries', String(t.maxRetries));

    // --- Firewall / IDS evasion ---
    const fw = o.firewall || {};
    if (fw.fragment) args.push('-f');
    if (!isBlank(fw.mtu)) args.push('--mtu', String(fw.mtu));
    if (!isBlank(fw.decoys)) args.push('-D', String(fw.decoys).trim());
    if (!isBlank(fw.spoofSource)) args.push('-S', String(fw.spoofSource).trim());
    if (!isBlank(fw.sourcePort)) args.push('-g', String(fw.sourcePort).trim());
    if (!isBlank(fw.dataLength)) args.push('--data-length', String(fw.dataLength));
    if (!isBlank(fw.ttl)) args.push('--ttl', String(fw.ttl));
    if (!isBlank(fw.spoofMac)) args.push('--spoof-mac', String(fw.spoofMac).trim());
    if (fw.badsum) args.push('--badsum');
    if (!isBlank(fw.interface)) args.push('-e', String(fw.interface).trim());

    // --- Output ---
    const out = o.output || {};
    if (out.verbose) args.push(...Array(Math.min(parseInt(out.verbose, 10) || 0, 3)).fill('-v'));
    if (out.reason) args.push('--reason');
    if (out.openOnly) args.push('--open');
    if (out.packetTrace) args.push('--packet-trace');
    if (out.traceroute) args.push('--traceroute');
    if (out.ipv6) args.push('-6');

    // --- Raw extra args (full nmap power) ---
    if (!isBlank(o.extraArgs)) args.push(...tokenize(String(o.extraArgs)));
  }

  const targets = parseTargets(req.targets);
  if (targets.length === 0) {
    throw new Error('No targets specified.');
  }
  return { args, targets };
}

/** Pretty command string for display (args quoted as needed). */
export function formatCommand(args) {
  return ['nmap', ...args].map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(' ');
}

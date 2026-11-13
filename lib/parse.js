// Parse nmap XML output (-oX) into a clean JSON structure for the UI.

import { XMLParser } from 'fast-xml-parser';

const ARRAY_KEYS = [
  'host', 'port', 'scaninfo', 'osmatch', 'osclass', 'hop', 'script',
  'cpe', 'hostname', 'trace', 'extraports', 'portused', 'table', 'elem'
];

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: true,
  isArray: (name) => ARRAY_KEYS.includes(name)
});

function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/** Serialize nested nmap <table>/<elem> script output into readable text lines. */
function tableToLines(t, indent = '') {
  const lines = [];
  const key = t['@_key'];
  const elems = asArray(t.elem);
  if (key) lines.push(indent + key + ':');
  for (const e of elems) {
    const k = e['@_key'] || '';
    const txt = e['#text'] != null ? String(e['#text']) : '';
    const sub = asArray(e.table);
    if (sub.length) {
      lines.push(indent + '  ' + k + (txt ? ' ' + txt : ''));
      for (const st of sub) lines.push(...tableToLines(st, indent + '    '));
    } else {
      lines.push(indent + '  ' + k + (txt ? ': ' + txt : ''));
    }
  }
  return lines;
}

function serializeTables(t) {
  const lines = [];
  for (const sub of asArray(t.table)) lines.push(...tableToLines(sub));
  return lines.join('\n');
}

function normalizeScript(s) {
  const out = { id: s['@_id'] || '', output: s['@_output'] || '' };
  const tables = serializeTables(s);
  if (tables) out.text = out.output ? `${out.output}\n${tables}` : tables;
  else out.text = out.output;
  return out;
}

function normalizeService(sv) {
  if (!sv) return null;
  return {
    name: sv['@_name'] || '',
    product: sv['@_product'] || '',
    version: sv['@_version'] || '',
    extrainfo: sv['@_extrainfo'] || '',
    ostype: sv['@_ostype'] || '',
    method: sv['@_method'] || '',
    conf: sv['@_conf'] || '',
    cpe: asArray(sv.cpe).map((c) => (typeof c === 'string' ? c : c['#text'] || '')).filter(Boolean)
  };
}

function normalizePort(p) {
  return {
    portid: p['@_portid'] || '',
    protocol: p['@_protocol'] || '',
    state: (p.state && p.state['@_state']) || 'unknown',
    reason: (p.state && p.state['@_reason']) || '',
    reason_ttl: (p.state && p.state['@_reason_ttl']) || '',
    service: normalizeService(p.service),
    scripts: asArray(p.script).map(normalizeScript),
    owner: (p.owner && p.owner['@_name']) || ''
  };
}

function normalizeOs(os) {
  if (!os) return null;
  const matches = asArray(os.osmatch).map((m) => ({
    name: m['@_name'] || '',
    accuracy: m['@_accuracy'] || '',
    line: m['@_line'] || '',
    cpe: asArray(m.cpe).map((c) => (typeof c === 'string' ? c : c['#text'] || '')).filter(Boolean),
    classes: asArray(m.osclass).map((c) => ({
      type: c['@_type'] || '',
      vendor: c['@_vendor'] || '',
      osfamily: c['@_osfamily'] || '',
      osgen: c['@_osgen'] || '',
      accuracy: c['@_accuracy'] || '',
      cpe: asArray(c.cpe).map((x) => (typeof x === 'string' ? x : x['#text'] || '')).filter(Boolean)
    }))
  }));
  return {
    portsUsed: asArray(os.portused).map((p) => ({
      state: p['@_state'] || '',
      proto: p['@_proto'] || '',
      portid: p['@_portid'] || ''
    })),
    matches
  };
}

function normalizeHost(h) {
  const addresses = asArray(h.address);
  const ip = addresses.find((a) => a['@_addrtype'] === 'ipv4') || addresses.find((a) => a['@_addrtype'] === 'ipv6');
  const mac = addresses.find((a) => a['@_addrtype'] === 'mac');
  const hostnames = asArray(h.hostnames && h.hostnames.hostname).map((x) => x['@_name']).filter(Boolean);

  const traces = asArray(h.trace);
  const traceroute = traces.length
    ? traces.map((tr) => ({
        port: tr['@_port'] || '',
        protocol: tr['@_protocol'] || tr['@_proto'] || '',
        hops: asArray(tr.hop).map((hop) => ({
          ttl: hop['@_ttl'] || '',
          ipaddr: hop['@_ipaddr'] || '',
          rtt: hop['@_rtt'] || '',
          host: hop['@_host'] || ''
        }))
      }))
    : [];

  return {
    address: ip ? ip['@_addr'] : (addresses[0] && addresses[0]['@_addr']) || '',
    type: ip ? ip['@_addrtype'] : '',
    mac: mac ? mac['@_addr'] : '',
    vendor: mac ? mac['@_vendor'] : '',
    hostnames,
    state: (h.status && h.status['@_state']) || '',
    status: h.status
      ? { state: h.status['@_state'] || '', reason: h.status['@_reason'] || '', reason_ttl: h.status['@_reason_ttl'] || '' }
      : null,
    ports: asArray(h.ports && h.ports.port).map(normalizePort),
    extraPorts: asArray(h.ports && h.ports.extraports).map((ep) => ({
      state: ep['@_state'] || '',
      count: parseInt(ep['@_count'] || '0', 10) || 0
    })),
    os: normalizeOs(h.os),
    traceroute,
    hostScripts: asArray(h.hostscript && h.hostscript.script).map(normalizeScript),
    uptime: h.uptime ? { seconds: h.uptime['@_seconds'] || '', lastboot: h.uptime['@_lastboot'] || '' } : null,
    distance: h.distance ? { value: h.distance['@_value'] || '' } : null,
    times: h.times
      ? { srtt: h.times['@_srtt'] || '', rttvar: h.times['@_rttvar'] || '', to: h.times['@_to'] || '' }
      : null
  };
}

function summarize(hosts, runStats) {
  let open = 0, closed = 0, filtered = 0;
  const services = {};
  for (const h of hosts) {
    for (const p of h.ports || []) {
      if (p.state === 'open') open++;
      else if (p.state === 'closed') closed++;
      else if (p.state === 'filtered') filtered++;
      if (p.state === 'open' && p.service && p.service.name) {
        services[p.service.name] = (services[p.service.name] || 0) + 1;
      }
    }
    // <extraports state="closed" count="995"> summarizes the ports nmap did
    // not enumerate individually; count them or closed/filtered are wildly
    // under-reported on default scans.
    for (const ep of h.extraPorts || []) {
      if (ep.state === 'closed') closed += ep.count;
      else if (ep.state === 'filtered') filtered += ep.count;
    }
  }
  const rs = runStats || {};
  return {
    hostsUp: hosts.filter((h) => h.state === 'up').length,
    hostsDown: hosts.filter((h) => h.state === 'down').length,
    openPorts: open,
    closedPorts: closed,
    filteredPorts: filtered,
    services,
    elapsed: (rs.finished && rs.finished['@_elapsed']) || '',
    exit: (rs.finished && rs.finished['@_exit']) || '',
    errormsg: (rs.finished && rs.finished['@_errormsg']) || ''
  };
}

/**
 * Parse nmap XML output into a normalized result object.
 * @param {string} xml
 */
export function parseNmapXml(xml) {
  const doc = parser.parse(xml);
  const run = doc.nmaprun;
  if (!run) throw new Error('Not a valid nmap XML document.');

  const hosts = asArray(run.host).map(normalizeHost);

  return {
    scanner: {
      name: run['@_scanner'] || 'nmap',
      version: run['@_version'] || '',
      args: run['@_args'] || '',
      startstr: run['@_startstr'] || ''
    },
    scanInfo: asArray(run.scaninfo).map((s) => ({
      type: s['@_type'] || '',
      protocol: s['@_protocol'] || '',
      numservices: s['@_numservices'] || '',
      services: s['@_services'] || ''
    })),
    verbose: run.verbose ? run.verbose['@_level'] || '0' : '0',
    debugging: run.debugging ? run.debugging['@_level'] || '0' : '0',
    hosts,
    runStats: {
      finished: run.runstats && run.runstats.finished
        ? {
            time: run.runstats.finished['@_time'] || '',
            timestr: run.runstats.finished['@_timestr'] || '',
            summary: run.runstats.finished['@_summary'] || '',
            elapsed: run.runstats.finished['@_elapsed'] || '',
            exit: run.runstats.finished['@_exit'] || '',
            errormsg: run.runstats.finished['@_errormsg'] || ''
          }
        : null,
      hosts: run.runstats && run.runstats.hosts
        ? {
            up: run.runstats.hosts['@_up'] || '',
            down: run.runstats.hosts['@_down'] || '',
            total: run.runstats.hosts['@_total'] || ''
          }
        : null
    },
    summary: summarize(hosts, run.runstats)
  };
}

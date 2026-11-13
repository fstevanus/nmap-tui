import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapXml } from '../../lib/parse.js';

const SAMPLE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.93" args="nmap -F 127.0.0.1" startstr="test">
<host><status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="QEMU"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports><extraports state="closed" count="993"><extrareasons reason="reset" count="993"/></extraports>
<port protocol="tcp" portid="8787"><state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="nmap-web" version="1.0" extrainfo="node" method="probed" conf="10"/>
<script id="http-title" output="NMAP&#183;WEB"/>
</port>
<port protocol="tcp" portid="22"><state state="closed" reason="reset" reason_ttl="0"/></port>
</ports>
<os><portused state="open" proto="tcp" portid="8787"/>
<osmatch name="Linux 5.x" accuracy="98"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="98"/></osmatch>
</os>
<trace port="8787" proto="tcp"><hop ttl="1" ipaddr="10.0.0.1" rtt="0.40" host="gw"/></trace>
<hostscript><script id="uptime" output="1.2 days"/></hostscript>
<uptime seconds="105000" lastboot="mock"/>
<distance value="0"/>
</host>
<runstats><finished time="1" timestr="t" elapsed="1.23" exit="success" summary="Nmap done"/>
<hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`;

test('parses hosts, ports, services, scripts, os and traceroute', () => {
  const r = parseNmapXml(SAMPLE_XML);
  assert.equal(r.scanner.version, '7.93');
  assert.equal(r.hosts.length, 1);
  const h = r.hosts[0];
  assert.equal(h.address, '127.0.0.1');
  assert.equal(h.mac, '00:11:22:33:44:55');
  assert.equal(h.vendor, 'QEMU');
  assert.deepEqual(h.hostnames, ['localhost']);
  assert.equal(h.ports.length, 2);
  const p = h.ports[0];
  assert.equal(p.portid, '8787');
  assert.equal(p.state, 'open');
  assert.equal(p.service.product, 'nmap-web');
  assert.equal(p.scripts[0].id, 'http-title');
  assert.equal(h.os.matches[0].name, 'Linux 5.x');
  assert.equal(h.traceroute[0].hops[0].ipaddr, '10.0.0.1');
  assert.equal(h.hostScripts[0].id, 'uptime');
});

test('counts <extraports> in summary (regression: closed/filtered under-count)', () => {
  const r = parseNmapXml(SAMPLE_XML);
  // 993 extraports closed + 1 enumerated closed port = 994
  assert.equal(r.summary.closedPorts, 994);
  assert.equal(r.summary.openPorts, 1);
  assert.equal(r.summary.hostsUp, 1);
  assert.deepEqual(r.hosts[0].extraPorts, [{ state: 'closed', count: 993 }]);
});

test('rejects non-nmap XML', () => {
  assert.throws(() => parseNmapXml('<html><body>nope</body></html>'), /Not a valid nmap XML/);
});

test('empty run (host down) yields zeroed summary without throwing', () => {
  const r = parseNmapXml(`<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.93"><runstats><finished elapsed="0.1" exit="success" errormsg=""/>
<hosts up="0" down="1" total="1"/></runstats></nmaprun>`);
  assert.equal(r.hosts.length, 0);
  assert.equal(r.summary.openPorts, 0);
  assert.equal(r.summary.errormsg, '');
});

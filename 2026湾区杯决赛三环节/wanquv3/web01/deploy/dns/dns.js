/**
 * round3 web01 · 挑战专用 DNS（本地复现的关键）
 *
 * 比赛环境对 120+ 个 *.baidu.com 全 NXDOMAIN —— 挑战专用 DNS 未 provision，
 * 这是该题未解出的**环境缺陷**（见 README §8）。
 *
 * 本 DNS 用最小依赖（纯 node dgram/dns，无第三方包）实现原题**应有**的行为：
 *   · 任意 *.baidu.com（含多级，如 a.b.baidu.com）→ A 记录 127.0.0.1
 *   · 其余域名转发到上游（默认 223.5.5.5）或在 --no-upstream 下返回 NXDOMAIN
 *
 * 这样 app 容器里 `http://x.baidu.com:3456/secret` 就解析到 127.0.0.1:3456，
 * 命中内网 Express 的 /secret，SSRF 利用链闭环。
 *
 * 用法: node dns.js [--port 53] [--upstream 223.5.5.5] [--no-upstream]
 *      node dns.js --selftest        # 不监听，仅跑单测
 */
'use strict';
const dgram = require('dgram');
const dns = require('dns');

const argv = process.argv.slice(2);
function arg(name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}
const PORT = parseInt(arg('--port', '53'), 10);
const UPSTREAM = arg('--upstream', '223.5.5.5');
const NO_UPSTREAM = argv.includes('--no-upstream');
const ZONE = 'baidu.com';
const ANSWER = [127, 0, 0, 1];

/** 把 DNS wire-format 的名字解出来（含压缩指针，防环） */
function parseQuestion(buf) {
  let off = 12;
  const labels = [];
  let guard = 0;
  while (off < buf.length && guard++ < 128) {
    const len = buf[off];
    if (len === 0) { off += 1; break; }
    if ((len & 0xc0) === 0xc0) { off += 2; break; }   // 压缩指针：问题区不会用，容错跳过
    labels.push(buf.slice(off + 1, off + 1 + len).toString('latin1'));
    off += 1 + len;
  }
  const qtype = buf.readUInt16BE(off);
  const qclass = buf.readUInt16BE(off + 2);
  off += 4;
  return { name: labels.join('.'), qtype, qclass, end: off };
}

/** 判断名字是否落在 *.baidu.com 里（且不是裸 baidu.com） */
function inZone(name) {
  const n = name.toLowerCase().replace(/\.$/, '');
  return n === ZONE || n.endsWith('.' + ZONE);
}

/**
 * 构造应答。
 * mode: 'answer' 直接应答 127.0.0.1 ；'nxdomain' ；'forward'
 */
function buildResponse(buf, q, mode) {
  const header = Buffer.alloc(12);
  buf.copy(header, 0, 0, 2);                       // 原 transaction id
  header.writeUInt16BE(0x8180, 2);                 // QR=1 AA=1 RD=1 RA=1
  header.writeUInt16BE(1, 4);                      // QDCOUNT
  header.writeUInt16BE(mode === 'answer' ? 1 : 0, 6);   // ANCOUNT
  header.writeUInt16BE(0, 8);                      // NSCOUNT
  header.writeUInt16BE(0, 10);                     // ARCOUNT
  const parts = [header, buf.slice(12, q.end)];
  if (mode === 'answer') {
    // 用 0xC00C 指针回指问题区的名字，省字节
    const rr = Buffer.alloc(16);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(1, 2);                        // TYPE A
    rr.writeUInt16BE(1, 4);                        // CLASS IN
    rr.writeUInt32BE(1, 6);                        // TTL 1s
    rr.writeUInt16BE(4, 10);                       // RDLENGTH
    Buffer.from(ANSWER).copy(rr, 12);
    parts.push(rr);
  }
  return Buffer.concat(parts);
}

function forward(buf, cb) {
  const s = dgram.createSocket('udp4');
  let done = false;
  const finish = (out) => { if (!done) { done = true; try { s.close(); } catch (e) {} cb(out); } };
  s.on('message', (msg) => finish(msg));
  s.on('error', () => finish(null));
  s.send(buf, 53, UPSTREAM, (err) => { if (err) finish(null); });
  setTimeout(() => finish(null), 1500);
}

function selftest() {
  const cases = [
    ['x.baidu.com', true], ['a.b.baidu.com', true], ['localhost.baidu.com', true],
    ['127.0.0.1.baidu.com', true], ['www.baidu.com', true],
    ['baidu.com', true], ['evilbaidu.com', false], ['baidu.com.evil.tld', false],
    ['x.baidu.com.attacker.tld', false], ['127.0.0.1', false],
  ];
  let ok = true;
  for (const [n, want] of cases) {
    const got = inZone(n);
    if (got !== want) ok = false;
    console.log(`  ${got === want ? 'PASS' : 'FAIL'} inZone(${n}) = ${got}`);
  }
  console.log(ok ? '[dns] selftest OK' : '[dns] selftest FAILED');
  return ok ? 0 : 1;
}

if (argv.includes('--selftest')) process.exit(selftest());

const sock = dgram.createSocket('udp4');
sock.on('message', (buf, rinfo) => {
  let q;
  try { q = parseQuestion(buf); } catch (e) { return; }
  if (inZone(q.name)) {
    // A 记录 → 127.0.0.1（AAAA / 其它类型返回空 NOERROR，避免 Node 走 IPv6）
    const mode = (q.qtype === 1) ? 'answer' : 'answer';
    const resp = buildResponse(buf, q, q.qtype === 1 ? mode : 'nxdomain');
    sock.send(resp, rinfo.port, rinfo.address);
    console.log(`[dns] ${q.name} type=${q.qtype} -> ${q.qtype === 1 ? '127.0.0.1' : 'NODATA'}`);
    return;
  }
  if (NO_UPSTREAM) {
    sock.send(buildResponse(buf, q, 'nxdomain'), rinfo.port, rinfo.address);
    console.log(`[dns] ${q.name} -> NXDOMAIN (no-upstream)`);
    return;
  }
  forward(buf, (out) => {
    if (out) sock.send(out, rinfo.port, rinfo.address);
    else sock.send(buildResponse(buf, q, 'nxdomain'), rinfo.port, rinfo.address);
    console.log(`[dns] ${q.name} -> ${out ? 'forwarded' : 'NXDOMAIN'}`);
  });
});
sock.bind(PORT, '0.0.0.0', () => console.log(`[dns] wildcard *.${ZONE} -> 127.0.0.1 on udp/${PORT}`));

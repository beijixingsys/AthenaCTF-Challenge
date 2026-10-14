// 用 node 实测 WHATWG URL 对这些"解析器差异族"候选的解析结果，
// 为 README §4 的"数学上不可能"论证提供实证数据。
const tests = [
  'http://127.0.0.1.baidu.com:3456/secret',
  'http://x.baidu.com@127.0.0.1:3456/secret',
  'http://x.baidu.com%2f@127.0.0.1:3456/secret',
  'http://x.baidu.com\\@127.0.0.1:3456/secret',
  'http://x.baidu.com#@127.0.0.1:3456/secret',
  'http://x.baidu.com?.baidu.com:3456/secret',
  'http://x.baidu.com:3456/secret',
  'http://127.0.0.1:3456/secret',
  'http://localhost:3456/secret',
  'http://x.baidu.com\\.attacker.tld:3456/secret',
  'http://x.baidu.com%00.attacker.tld:3456/secret',
  'http://127.1:3456/secret',
  'http://0x7f.0.0.1:3456/secret',
  'http://2130706433:3456/secret',
  'http://[::1]:3456/secret',
];
for (const t of tests) {
  try {
    const u = new URL(t);
    console.log(JSON.stringify({
      input: t, href: u.href, hostname: u.hostname, port: u.port,
      pathname: u.pathname, whitelist_pass: u.hostname.endsWith('.baidu.com'),
    }));
  } catch (e) {
    console.log(JSON.stringify({ input: t, error: e.message }));
  }
}

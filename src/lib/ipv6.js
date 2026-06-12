// ipv6.js — minimal IPv6 validators for threat-feed ingest.
//
// Augur stores indicators as text then the materializer casts them to
// `inet` (`a.source_ip::inet <<= o.entity_value::inet`), so a malformed v6
// value would break that join. Everything stored as a v6 ip/cidr passes
// through here first. Mirrors the parser in tunnelmind-data-api
// api/utils/ip.js / scry-server src/lib/ip.js (zero-dep, one copy per repo).

function parseIpv4(raw) {
  if (typeof raw !== "string") return null;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(raw.trim());
  if (!m) return null;
  const o = m.slice(1, 5).map(Number);
  for (let i = 0; i < 4; i++) {
    if (o[i] > 255) return null;
    if (m[i + 1].length > 1 && m[i + 1][0] === "0") return null;
  }
  return o;
}

/** Parse an IPv6 string into eight groups, or null. */
export function parseIpv6(raw) {
  if (typeof raw !== "string") return null;
  let s = raw.trim().toLowerCase();
  if (!s || s.indexOf(":") === -1) return null;
  if (/[^0-9a-f:.]/.test(s)) return null;
  if ((s.match(/::/g) || []).length > 1) return null;
  if (/:::/.test(s)) return null;

  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  let tailGroups = [];
  if (tail.indexOf(".") !== -1) {
    const v4 = parseIpv4(tail);
    if (!v4) return null;
    tailGroups = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1);
  }

  const hasCompression = s.indexOf("::") !== -1;
  let head, tailPart;
  if (hasCompression) {
    const [h, t] = s.split("::");
    head = h ? h.split(":") : [];
    tailPart = t ? t.split(":").filter((x) => x !== "") : [];
  } else {
    head = s.replace(/:$/, "").split(":");
    tailPart = [];
  }

  const hexGroups = [];
  for (const part of [...head, ...tailPart]) {
    if (part === "") return null;
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    hexGroups.push(parseInt(part, 16));
  }

  const explicit = hexGroups.length + tailGroups.length;
  let groups;
  if (hasCompression) {
    const headLen = head.filter((x) => x !== "").length;
    const fill = 8 - explicit;
    if (fill < 1) return null;
    groups = [
      ...hexGroups.slice(0, headLen),
      ...new Array(fill).fill(0),
      ...hexGroups.slice(headLen),
      ...tailGroups,
    ];
  } else {
    if (explicit !== 8) return null;
    groups = [...hexGroups, ...tailGroups];
  }
  return groups.length === 8 ? groups : null;
}

/** True if `s` is a syntactically valid bare IPv6 address. */
export function isV6(s) {
  return parseIpv6(s) !== null;
}

/** True if `s` is a valid IPv6 CIDR (`addr/len`, 0 ≤ len ≤ 128). */
export function isV6Cidr(s) {
  if (typeof s !== "string" || s.indexOf("/") === -1) return false;
  const [addr, lenStr] = s.split("/");
  const len = Number(lenStr);
  if (!Number.isInteger(len) || len < 0 || len > 128) return false;
  return parseIpv6(addr) !== null;
}

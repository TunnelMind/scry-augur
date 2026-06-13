// node --test src/sources/ipv6.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { isV6, isV6Cidr } from "../lib/ipv6.js";
import { parseDropList } from "./spamhaus_drop.js";
import { mapIoc } from "./threatfox.js";

test("ipv6 validators", () => {
  assert.equal(isV6("2001:db8::1"), true);
  assert.equal(isV6("::1"), true);
  assert.equal(isV6(":::"), false);
  assert.equal(isV6("1.2.3.4"), false);
  assert.equal(isV6Cidr("2a0e:b107::/32"), true);
  assert.equal(isV6Cidr("2001:db8::/200"), false);
  assert.equal(isV6Cidr("10.0.0.0/8"), false);
});

test("parseDropList accepts v4 and v6 CIDRs, rejects junk", () => {
  const list = [
    "; comment",
    "5.42.184.0/22 ; SBL537404",
    "2a06:e480::/29 ; SBL999001",
    "not-a-cidr ; SBL000",
    "2001:db8::/200 ; SBL111", // bad prefix len → dropped
  ].join("\n");
  const out = parseDropList(list);
  const cidrs = out.map((e) => e.cidr);
  assert.deepEqual(cidrs, ["5.42.184.0/22", "2a06:e480::/29"]);
  assert.deepEqual(parseDropList(""), []);
});

test("threatfox mapIoc handles v6 ip:port forms", () => {
  assert.deepEqual(mapIoc("ip:port", "1.2.3.4:443"),
    { entity_type: "ip", entity_value: "1.2.3.4", port: 443 });
  assert.deepEqual(mapIoc("ip:port", "[2001:db8::1]:8080"),
    { entity_type: "ip", entity_value: "2001:db8::1", port: 8080 });
  assert.deepEqual(mapIoc("ip:port", "2001:db8::1"),
    { entity_type: "ip", entity_value: "2001:db8::1", port: null });
  assert.equal(mapIoc("ip:port", "not-an-ip:1"), null);
});

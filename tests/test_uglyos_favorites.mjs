// SPDX-License-Identifier: MIT
// Node regression tests execute exact JS imported by Qt Quick. No watch access.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const file = new URL("../meta-noblesse/recipes-asteroid/uglyos-launchers/uglyos-launchers/uglyos-favorites.js", import.meta.url);
const js = readFileSync(file, "utf8");
const ctx = Object.create(null);
runInNewContext(js, ctx, {timeout: 1000});
const values = x => Array.from(x);
const id = "org.asteroid.agenda.desktop";
const valid = ["org.asteroid.agenda.desktop", "org.asteroid.timer.desktop",
               "org.asteroid.settings.desktop", "org.asteroid.clock.desktop",
               "org.asteroid.music.desktop"];
assert.equal(ctx.MAX_PINS, 4);
assert.deepEqual(values(ctx.normalize("not json")), []);
assert.deepEqual(values(ctx.normalize("{}")), []);
assert.deepEqual(values(ctx.normalize(JSON.stringify([id, id, null, 43, "wrong;rm -rf", "a.desktop"]))),
                 [id, "a.desktop"]);
assert.equal(ctx.toggle("[]", {fileID: "../private.desktop"}), "[]");
let data = "[]";
for (const value of valid) data = ctx.toggle(data, {fileID: value});
assert.deepEqual(JSON.parse(data), valid.slice(1).reverse());
data = ctx.toggle(data, {fileID: valid[2]});
assert(!JSON.parse(data).includes(valid[2]));
data = ctx.toggle(data, {fileID: valid[2]});
assert.equal(JSON.parse(data)[0], valid[2]);

const items = valid.map(fileID => ({
    fileID, title: fileID.split(".").at(-2), launches: 0,
    launchApplication() { this.launches++; }
}));
const model = {itemCount: items.length, get(i) { return items[i]; }};
let resolved = values(ctx.resolve(model, JSON.stringify([valid[1], valid[3], "ghost.desktop"])));
assert.deepEqual(resolved.map(x => x.fileID), [valid[1], valid[3]]);
assert.equal(items.reduce((sum, x) => sum + x.launches, 0), 0);
assert.deepEqual(values(ctx.resolve({itemCount: 5}, data)), []);
assert.deepEqual(values(ctx.resolve(null, data)), []);
assert.equal(ctx.appID({object: items[0]}), id);
assert.equal(ctx.appID({object: {fileID: "wrong ;!"}}), "");
const oversized = JSON.stringify(Array.from({length: 500}, (_, i) => "org.test." + i + ".desktop"));
assert.equal(ctx.normalize(oversized).length, 4);
console.log("PASS[uglyos-favorites]: deterministic IDs, stale filtering, cap, no accidental launches");

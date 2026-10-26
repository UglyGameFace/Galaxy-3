// SPDX-License-Identifier: MIT
// Pure, local UgLy|OS launcher pinning helpers. No network, polling or sorting.
// Upstream AsteroidOS LauncherItem.fileID is stable across UI translations.
// The stock launcherModel stays authoritative: uninstalled apps never launch.
var MAX_PINS = 4
var MAX_SCANNED_APPS = 160

function validID(value) {
    return typeof value === "string" &&
           /^[A-Za-z0-9._-]{1,96}$/.test(value) &&
           value.endsWith(".desktop")
}

function normalize(raw) {
    var parsed
    try {
        parsed = JSON.parse(raw)
    } catch (err) {
        return []
    }
    if (!Array.isArray(parsed))
        return []
    var clean = []
    for (var i = 0; i < parsed.length && i < 32; i++) {
        var id = parsed[i]
        if (validID(id) && clean.indexOf(id) === -1)
            clean.push(id)
        if (clean.length === MAX_PINS)
            break
    }
    return clean
}

function app(itemOrRoles) {
    if (!itemOrRoles)
        return null
    return itemOrRoles.object ? itemOrRoles.object : itemOrRoles
}

function appID(itemOrRoles) {
    var value = app(itemOrRoles)
    if (!value || !validID(value.fileID))
        return ""
    return value.fileID
}

function toggle(raw, itemOrRoles) {
    var id = appID(itemOrRoles)
    var favorites = normalize(raw)
    if (!id)
        return JSON.stringify(favorites)
    var existing = favorites.indexOf(id)
    if (existing !== -1) {
        favorites.splice(existing, 1)
    } else {
        // New favorite goes first, and the oldest falls off after four.
        favorites.unshift(id)
        favorites = favorites.slice(0, MAX_PINS)
    }
    return JSON.stringify(favorites)
}

function resolve(launcher, raw) {
    var ids = normalize(raw)
    var found = []
    if (!launcher || typeof launcher.get !== "function")
        return found
    var count = Math.min(MAX_SCANNED_APPS, Number(launcher.itemCount) || 0)
    if (count < 0)
        return found
    // Each pinned ID is resolved against CURRENT installed entries. No title
    // matching, synthetic launch entries, shell input or permission widening.
    for (var j = 0; j < ids.length; j++) {
        for (var i = 0; i < count; i++) {
            var item = app(launcher.get(i))
            if (appID(item) === ids[j]) {
                found.push(item)
                break
            }
        }
    }
    return found
}

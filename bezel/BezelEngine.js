// SPDX-License-Identifier: MIT
// UgLy|OS Bezel Engine: pure, bounded interaction logic for Qt QML and host tests.
// OFF-DEVICE: the Watch3 evdev -> Qt wheel adapter is not yet proven on hardware.
// No device access, network transport, subscriptions, timers or privileged calls.
.pragma library

var PAGES = ["ring", "precision", "keyboard", "timeline", "game", "gestures", "features"];
var CHARACTERS = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-";
var CONTEXTS = ["everyday", "gaming", "work", "accessibility"];
var LOCAL_ACTIONS = ["ring", "precision", "keyboard", "timeline", "game", "gestures", "features"];
var REMOTE_ACTIONS = ["phone-media", "phone-camera", "phone-navigation", "phone-game",
                      "phone-automation", "phone-audio", "phone-notifications"];
var MAX_GESTURES = 6;

function clamp(value, lo, hi) { return Math.max(lo, Math.min(hi, value)); }
function circular(index, delta, length) { return (index + ((delta % length) + length)) % length; }
function safeTime(v) { return typeof v === "number" && isFinite(v) && v >= 0 ? v : -1; }
function makeState() {
    return {
        page: "ring", context: "everyday", focus: 0, dial: 50, timelineSeconds: 0,
        gameSlot: 0, keyboardIndex: 0, keyboardText: "", lastTurnMs: -1,
        totalTurns: 0, gestureArmed: false, gestureRecord: false,
        gestureSteps: [], gestureStartedMs: -1, gestures: [],
        notifications: [], selectedNotification: 0,
        modifier: false, lastResult: "Normal navigation", assistive: false,
        // No action executes off-device; remote and haptic transports are absent.
        intents: []
    };
}
// Samsung pinned tizen_bezel.c reports +1=CW, -1=CCW as EV_REL/REL_WHEEL.
// It also reports EV_REL/REL_X (hall diagnostics), which MUST be ignored.
// Device path is never assumed based on a stable event number in production.
function normalizeEvdev(type, code, value, ms) {
    if (type !== 2 || code !== 8 || !Number.isInteger(value) ||
        value === 0 || Math.abs(value) > 8 || safeTime(ms) < 0) return null;
    return {kind: "rotate", steps: value, ms: ms};
}
function validPattern(steps) {
    return Array.isArray(steps) && steps.length >= 2 && steps.length <= 8 &&
        steps.every(function(x) { return x === 1 || x === -1; });
}
function patternKey(steps) {
    return steps.map(function(n) { return n === 1 ? "R" : "L"; }).join("");
}
function registerGesture(state, pattern, target) {
    var next = JSON.parse(JSON.stringify(state));
    if (!validPattern(pattern) || LOCAL_ACTIONS.indexOf(target) < 0) {
        next.lastResult = "Invalid local gesture";
        return next;
    }
    var key = patternKey(pattern);
    var prior = next.gestures.filter(function(x) { return x.key !== key; });
    if (prior.length >= MAX_GESTURES) {
        next.lastResult = "Gesture limit reached";
        return next;
    }
    prior.push({key:key, target:target});
    next.gestures = prior;
    next.lastResult = "Local gesture saved";
    return next;
}
function clearGesture(state, key) {
    var next = JSON.parse(JSON.stringify(state));
    next.gestures = next.gestures.filter(function(x) { return x.key !== key; });
    return next;
}
function selectLocal(s, page) {
    if (LOCAL_ACTIONS.indexOf(page) < 0) return;
    s.page = page;
    s.lastResult = "Local " + page;
    s.gestureArmed = false;
    s.gestureRecord = false;
    s.gestureSteps = [];
}
function remoteIntent(state, action, payload) {
    // Intent is **never sent** from the engine. A future authenticated Android
    // companion may register permissions, acknowledgments and transports.
    var next = JSON.parse(JSON.stringify(state));
    if (REMOTE_ACTIONS.indexOf(action) < 0) {
        next.lastResult = "Unknown action";
        return next;
    }
    next.lastResult = action + ": Android companion not connected";
    next.intents = []; // fail closed, no queued data or offline replay
    return next;
}
function apply(state, event) {
    var s = JSON.parse(JSON.stringify(state));
    s.intents = [];
    if (!event || typeof event.kind !== "string") return s;
    if (event.kind === "context") {
        if (CONTEXTS.indexOf(event.value) >= 0) {
            s.context = event.value;
            s.lastResult = "Context: " + event.value;
        }
        return s;
    }
    if (event.kind === "arm") {
        s.gestureArmed = true;
        s.gestureRecord = event.record === true;
        s.gestureSteps = [];
        s.gestureStartedMs = -1;
        s.lastResult = s.gestureRecord ? "Recording local pattern" : "Enter pattern, confirm";
        return s;
    }
    if (event.kind === "cancel") {
        s.gestureArmed = false;
        s.gestureRecord = false;
        s.gestureSteps = [];
        s.lastResult = "Cancelled";
        return s;
    }
    if (event.kind === "back") {
        if (s.gestureArmed) return apply(s, {kind:"cancel"});
        selectLocal(s, "ring");
        return s;
    }
    if (event.kind === "modifier") {
        s.modifier = event.held === true; // a logical adapter state, NOT KEY_POWER
        return s;
    }
    if (event.kind === "choose") {
        if (s.gestureArmed) {
            if (!validPattern(s.gestureSteps)) {
                s.lastResult = "Use 2–8 detents";
            } else if (s.gestureRecord) {
                s = registerGesture(s, s.gestureSteps, "ring");
            } else {
                var key = patternKey(s.gestureSteps);
                var match = s.gestures.filter(function(x) { return x.key === key; })[0];
                if (match) selectLocal(s, match.target);
                else s.lastResult = "Pattern not assigned";
            }
            s.gestureArmed = false;
            s.gestureRecord = false;
            s.gestureSteps = [];
            return s;
        }
        if (s.page === "ring") selectLocal(s, LOCAL_ACTIONS[s.focus]);
        else if (s.page === "keyboard" && s.keyboardText.length < 48)
            s.keyboardText += CHARACTERS[s.keyboardIndex];
        else if (s.page === "gestures") return apply(s, {kind:"arm",record:true});
        else s.lastResult = "Selected " + s.page;
        return s;
    }
    if (event.kind === "rotate") {
        if (!Number.isInteger(event.steps) || !event.steps ||
            Math.abs(event.steps) > 8 || safeTime(event.ms) < 0) return s;
        var direction = event.steps > 0 ? 1 : -1;
        var steps = Math.abs(event.steps);
        if (s.gestureArmed) {
            if (s.gestureStartedMs >= 0 && (event.ms < s.gestureStartedMs ||
                event.ms - s.gestureStartedMs > 2000)) {
                s.gestureSteps = [];
                s.gestureStartedMs = -1;
            }
            if (s.gestureStartedMs < 0) s.gestureStartedMs = event.ms;
            for (var gi = 0; gi < steps && s.gestureSteps.length < 8; ++gi)
                s.gestureSteps.push(direction);
            s.lastResult = "Pattern: " + patternKey(s.gestureSteps);
            return s;
        }
        var rapid = s.lastTurnMs >= 0 && event.ms >= s.lastTurnMs &&
                    event.ms - s.lastTurnMs <= 95;
        // Acceleration is opt-in for value adjustment, never menu navigation.
        var precisionMultiplier = rapid ? 3 : 1;
        s.lastTurnMs = event.ms;
        s.totalTurns = clamp(s.totalTurns + event.steps, -100000, 100000);
        if (s.page === "ring") {
            s.focus = circular(s.focus, event.steps, LOCAL_ACTIONS.length);
        } else if (s.page === "precision") {
            s.dial = clamp(s.dial + event.steps * precisionMultiplier, 0, 100);
        } else if (s.page === "keyboard") {
            s.keyboardIndex = circular(s.keyboardIndex, event.steps, CHARACTERS.length);
        } else if (s.page === "timeline") {
            s.timelineSeconds = clamp(s.timelineSeconds + event.steps * 5, 0, 86400);
        } else if (s.page === "game") {
            s.gameSlot = circular(s.gameSlot, event.steps, 24);
        } else if (s.page === "features") {
            s.focus = circular(s.focus, event.steps, LOCAL_ACTIONS.length);
        } else {
            // Default gesture page scroll is harmless and does not record.
            s.focus = circular(s.focus, event.steps, LOCAL_ACTIONS.length);
        }
        s.lastResult = "Detent " + (direction > 0 ? "CW" : "CCW");
        return s;
    }
    return s;
}

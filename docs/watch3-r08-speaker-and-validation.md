# Watch3 R08 speaker capability and validator incident

Only the metadata flag was corrected: SM-R840X has a physical speaker.
AsteroidOS playback has not been verified and the output may need codec, amplifier,
ALSA mixer, userspace routing, and panel-independent device tests.
Upstream build #1: https://github.com/UglyGameFace/Galaxy-3/actions/runs/39516972444
Completed 950 of 950 BitBake tasks; final checker incorrectly used WLAN/SPEAKER
instead of HAS_WLAN/HAS_SPEAKER. Its generated config contained false speaker
because old machine metadata was false. The new fast test uses the exact
historical generated values plus a SYNTHETIC true-speaker variant, not a fresh
AsteroidOS-generated package. Recompile only when the actual package is needed.

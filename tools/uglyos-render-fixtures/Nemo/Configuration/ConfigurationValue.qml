// Host-only fixture: no persistent device settings are read or written.
import QtQml
QtObject {
    property string key: ""
    property string defaultValue: "original"
    property string value: key === "/desktop/uglyos/launcher/favorites" ? "[]"
        : key === "/desktop/uglyos/appearance/effects"
          ? (typeof mockEffectsPreset === "undefined" ? defaultValue : mockEffectsPreset)
          : (typeof mockAccentPreset === "undefined" ? defaultValue : mockAccentPreset)
}

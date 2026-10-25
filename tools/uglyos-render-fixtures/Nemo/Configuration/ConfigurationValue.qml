// Host-only fake for Nemo.Configuration. No persistent settings are written.
import QtQml
QtObject {
    property string key: ""
    property string defaultValue: "original"
    property string value: typeof mockAccentPreset === "undefined" ? defaultValue : mockAccentPreset
}

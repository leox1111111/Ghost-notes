[app]
title = Ghost Notes
package.name = ghostnotes
package.domain = org.leox
source.dir = .
source.include_exts = py,png,ttf
source.exclude_dirs = .ci,.github,bin,.buildozer
version = 1.0
requirements = python3,kivy==2.3.1
orientation = portrait
fullscreen = 0
icon.filename = %(source.dir)s/assets/icon.png
presplash.filename = %(source.dir)s/assets/presplash.png
android.presplash_color = #0E0F14
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE
android.api = 34
android.minapi = 24
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
android.allow_backup = False
android.window_softinput_mode = adjustResize

[buildozer]
log_level = 2
warn_on_root = 0

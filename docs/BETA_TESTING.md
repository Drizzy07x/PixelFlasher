# PixelFlasher beta testing plan

This document defines the minimum testing gate before a beta build is shared with users.

## Beta channels

| Channel | Audience | Purpose |
| --- | --- | --- |
| `dev` | maintainers | daily development; can break |
| `beta` | trusted testers | feature validation before stable |
| `stable` | normal users | known-safe public release |

Use GitHub pre-releases for beta builds.

## Required artifacts per beta

- Windows x64 build
- Linux x86_64 build or AppImage
- `checksums.sha256`
- short changelog
- known risks
- tester checklist

## Pre-release gate

Run this before publishing a beta:

```bash
python PixelFlasher.py --self-test
python PixelFlasher.py --diagnostics --output PixelFlasher-diagnostics.zip
```

A beta should not be published when `--self-test` has required failures.
Warnings are acceptable for optional tools such as `adb` or `fastboot` when CI does not provide them.

## Smoke checklist

### App startup

- [ ] App opens without crash
- [ ] App closes without traceback
- [ ] Theme loads correctly
- [ ] Icons load correctly
- [ ] Settings can be saved and reopened
- [ ] Logs can be opened/copied

### Windows

- [ ] Windows 10 or 11 opens the packaged `.exe`
- [ ] Python is not required on the tester machine
- [ ] Paths with spaces work
- [ ] ADB device detection works
- [ ] Fastboot device detection works
- [ ] Open-folder actions use Explorer correctly

### Linux

- [ ] AppImage or binary starts after executable permission is set
- [ ] Works on Ubuntu 22.04 or 24.04
- [ ] Works on X11
- [ ] Works on Wayland when available
- [ ] ADB device detection works
- [ ] Fastboot device detection works
- [ ] Open-folder actions use the correct file manager

### Device checks

- [ ] Device detected in ADB mode
- [ ] Device detected in bootloader mode
- [ ] Active slot is displayed correctly
- [ ] Android version/build is displayed correctly
- [ ] Root/Magisk status is displayed correctly when available

### Firmware checks

- [ ] Valid ZIP is accepted
- [ ] Invalid ZIP is rejected with a clear error
- [ ] Build/device info is parsed correctly
- [ ] `boot.img` or `init_boot.img` is detected correctly
- [ ] Hashes are calculated correctly
- [ ] Large ZIP does not freeze the UI indefinitely

### High-risk checks

Only advanced testers should run these, and never on a daily-driver phone.

- [ ] Dry run works
- [ ] Pre-flash checks are shown before flashing
- [ ] Final confirmation appears before destructive actions
- [ ] Patch boot works on a secondary test device
- [ ] Real flash works on a secondary test device
- [ ] Final log can be exported

## Stable promotion rules

Promote beta to stable only when:

- zero known critical bugs
- zero known data-loss bugs
- zero known new startup crashes
- Windows and Linux smoke tests pass
- at least one successful patch boot test exists
- at least one successful real flash test exists on a secondary device

## Bug report requirements

Every useful beta report should include:

- beta version
- OS and version
- device model/codename
- Android version/build
- exact action performed
- expected result
- actual result
- diagnostics ZIP generated with `--diagnostics`

## Added beta-safe commands

These commands do not import the full wxPython UI and can run in CI/headless environments:

```bash
python PixelFlasher.py --version
python PixelFlasher.py --self-test
python PixelFlasher.py --doctor
python PixelFlasher.py --diagnostics --output PixelFlasher-diagnostics.zip
```

## Automated checks now covered

- Python/runtime check
- required project files
- JSON validity for Android metadata
- config write check
- platform compatibility layer check
- modern UI theme token check
- modern SVG icon registry check
- optional adb/fastboot discovery
- optional packaged binary discovery
- redacted diagnostics bundle generation

## New source bundle helper

For beta source artifacts:

```bash
python tools/create_beta_bundle.py --label 9.2.0-beta.1
```

This creates:

```text
PixelFlasher-9.2.0-beta.1-source.zip
PixelFlasher-9.2.0-beta.1-source.zip.sha256
```

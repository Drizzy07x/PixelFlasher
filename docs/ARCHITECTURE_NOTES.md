# Architecture notes for the modernization work

## Current risk

`Main.py` owns too much UI state and behavior. Large edits there are risky
because UI changes can accidentally affect flashing behavior.

## New direction

Move new low-risk code into small modules first:

```text
platform_utils.py
self_test.py
diagnostics.py
ui/theme.py
ui/icons.py
ui/components/models.py
```

These modules are safe to test in CI without a display server or a connected
phone.

## Migration strategy

1. New code uses `platform_utils.py` for OS behavior.
2. New UI screens use `ui/theme.py` and `ui/icons.py`.
3. Existing flashing functions remain untouched until tests cover them.
4. Extract one component at a time from `Main.py`.
5. Keep the legacy UI fallback until beta testers validate the new flow.

## High-risk areas

Do not refactor these casually:

- adb/fastboot command generation
- firmware ZIP parsing
- boot/init_boot patching
- slot switching
- wipe/downgrade handling
- generated flash scripts

These need targeted tests and device validation before large changes.

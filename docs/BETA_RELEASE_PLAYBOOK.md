# PixelFlasher beta release playbook

Use this document every time a beta is prepared.

## Branching

Recommended branches:

- `main`: stable only
- `beta-modern-ui`: integration branch for beta builds
- `feature/<name>`: focused PR branches

## Versioning

The current project version is `9.1.1.1`. Use beta labels on top of the existing
line instead of resetting to `2.0.0`.

Recommended next beta:

```text
9.2.0-beta.1
```

## Pre-beta gate

Run locally before tagging:

```bash
python PixelFlasher.py --self-test
python PixelFlasher.py --diagnostics --output PixelFlasher-diagnostics.zip
python -m unittest discover -s tests -v
```

## GitHub release checklist

- [ ] Open PR from feature branch into `beta-modern-ui`
- [ ] `beta-smoke.yml` passes on Windows and Ubuntu
- [ ] Build artifacts generated for Windows and Linux
- [ ] SHA256 checksums generated
- [ ] Changelog includes new features, fixed bugs, and known risks
- [ ] Beta issue template is available
- [ ] Diagnostics ZIP creation confirmed
- [ ] At least one tester confirms app launch on Windows
- [ ] At least one tester confirms app launch on Linux

## Tester rules

- No daily-driver phones for destructive flash tests.
- Start with `Dry Run`.
- Attach diagnostics ZIP to every crash or unclear failure.
- Report exact OS, device codename, Android build, and PixelFlasher version.

## Stable promotion gate

Do not promote beta to stable unless all are true:

- [ ] Zero known critical bugs
- [ ] Zero known data-loss bugs
- [ ] Zero known startup crashes
- [ ] Windows smoke test passes
- [ ] Linux smoke test passes
- [ ] Patch boot tested successfully on secondary device
- [ ] Real flash tested successfully on secondary device
- [ ] Known issues documented

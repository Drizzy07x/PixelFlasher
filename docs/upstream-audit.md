# PixelFlasher 10 upstream audit log

PixelFlasher 10 ports upstream behavior deliberately. It does not merge wx UI,
release-version changes, or superseded build experiments into the modern branch.
Each milestone close and the release code freeze must add a dated audit entry.

## 2026-07-18 — foundation checkpoint

- Modern branch: `modernization/10.0`
- Modern baseline: `6203cab` (`Checkpoint modern React WebView baseline`)
- Upstream remote: `https://github.com/badabing2005/PixelFlasher.git`
- Audited upstream tip: `d85019245f3da403fb165bfc6561242e6c914e9e`
- New commits after the previously audited tip: none
- Integration decision: no additional upstream commit is required

The local behavior port `624006d` already contains the useful changes from the
audited range:

- KernelSU and derivatives no longer receive incompatible `--magiskboot`
  arguments for LKM patching (`33c40fe7`).
- LSPosed's current `modules_state` schema is supported (`7f2c2522`).
- reboot-to-system timeout is configurable (`d8501924`).
- the applicable macOS runner and Homebrew fixes are retained (`4c4243ac`,
  `623286c7`).

Version bumps, reverted Windows signing experiments, obsolete wx build changes,
and intermediate macOS workflow attempts remain intentionally excluded. Their
behavior is either superseded or belongs to the legacy release pipeline that
PixelFlasher 10 replaces.

## Audit procedure

1. Fetch `upstream/main` without merging it.
2. Record the exact upstream SHA and list commits after the previous audited
   SHA.
3. Review code, tests, security implications, and all supported platforms for
   each new behavior.
4. Port only the minimal behavior and characterization tests into the current
   milestone branch.
5. Never copy an upstream version bump, wx UI change, or release workflow
   wholesale.
6. Run the complete Python/frontend baseline and packaged smoke gates before
   recording the audit as closed.

The next mandatory audits are at the close of the next implementation milestone
and at release code freeze.

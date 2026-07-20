# PixelFlasher 10 upstream audit log

PixelFlasher 10 ports upstream behavior deliberately. It does not merge wx UI,
release-version changes, or superseded build experiments into the modern branch.
Each milestone close and the release code freeze must add a dated audit entry.

## 2026-07-20 — packaged personal-tools checkpoint

- Modern branch: `modernization/10.0`
- Modern checkpoint: `9241179` (`Prove packaged personal tool execution`)
- Upstream remote: `https://github.com/badabing2005/PixelFlasher.git`
- Audited upstream tip: `d85019245f3da403fb165bfc6561242e6c914e9e`
- New commits after the previously audited tip: none
- Integration decision: no upstream commit is required

The fresh fetch confirmed that `upstream/main` still points to the same audited
release tip. The behavior port in `624006d` remains complete; version bumps,
wx UI changes and superseded release-workflow experiments remain excluded.

Checkpoint evidence: 1,361 Python tests passed with seven platform skips and
16,680 subtests; Ruff and strict Pyright passed; all 33 frontend files and 209
tests passed; gettext verification, TypeScript and both production Vite bundles
passed. A rebuilt Windows x86_64 executable completed the schema-v2 personal
tools smoke: a purpose-bound, hash-pinned safe argv profile survived repository
reload and executed directly, then the isolated Legacy Raw boundary proved
persistent permission, exact per-run confirmation and native-shell execution.
The same executable also reran the packaged firmware smoke successfully.

## 2026-07-20 — packaged bridge smoke checkpoint

- Modern branch: `modernization/10.0`
- Modern checkpoint: `757eb20` (`Prove packaged React bridge startup`)
- Upstream remote: `https://github.com/badabing2005/PixelFlasher.git`
- Audited upstream tip: `d85019245f3da403fb165bfc6561242e6c914e9e`
- New commits after the previously audited tip: none
- Integration decision: no upstream commit is required

The fetch confirmed that upstream remains on the same audited release tip. The
selected behavior port `624006d` therefore remains complete for this range;
there is no new kernel patching, LSPosed, timeout, platform, or safety behavior
to extract. Version and wx UI history remain excluded as documented below.

Checkpoint evidence: 1,238 Python tests passed with seven platform skips and
16,127 subtests; Ruff and strict core Pyright passed; 196 frontend tests,
gettext verification, TypeScript checks and the production Vite build passed;
the Windows x86_64 default entrypoint completed a real React `app.ready`
bridge-v2 handshake and emitted a clean-shutdown receipt. Native CI workflows
now require the same closed receipt for every release architecture and Linux
display backend.

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

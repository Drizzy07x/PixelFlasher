# Release rollback playbook

GitHub release artifacts and tags are immutable. A rollback never replaces an
existing binary.

1. Mark the affected release as withdrawn and prerelease; retain its artifacts
   and evidence for investigation.
2. Publish a security advisory when confidentiality permits.
3. Identify the last signed release whose device-safety behavior is valid and
   link it prominently from the withdrawn release.
4. Fix forward from the withdrawn tag's source. Run the complete parity,
   package, hardware and signing matrix under a new RC tag.
5. Publish a new patch release only after all normal gates pass. Never retag or
   upload replacement assets to the withdrawn release.
6. If firmware or artifact manifests are affected, revoke the manifest key or
   entry, publish a signed replacement and invalidate the affected cache item.

For a suspected destructive-operation defect, immediately disable publication
and signed update manifests until SafetyPolicy, planner and postcondition tests
prove the correction.

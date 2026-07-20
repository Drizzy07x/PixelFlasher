## Summary

Describe what changed and why.

## Type of change

- [ ] UI/UX only
- [ ] Beta infrastructure
- [ ] Platform compatibility
- [ ] Bug fix
- [ ] Flashing/ADB/Fastboot behavior
- [ ] Documentation

## Risk level

- [ ] Low: no flashing behavior changed
- [ ] Medium: UI flow or parsing changed
- [ ] High: ADB/Fastboot/flashing behavior changed

## Validation

- [ ] `python PixelFlasher.py --self-test`
- [ ] `python -m unittest discover -s tests -v`
- [ ] Packaged `--ui-smoke-report` receipt verified on affected platforms
- [ ] Functional fake ADB/Fastboot smoke completed where applicable
- [ ] Device detection tested
- [ ] Dry Run tested
- [ ] Real flash tested on secondary device only

## Notes for testers

List anything beta testers should focus on.

import { describe, expect, it } from 'vitest';
import { rootAppSupportsDeviceArchitecture } from '../pages/root/RootPage';

describe('root app architecture compatibility', () => {
  it('accepts universal apps and canonical architecture aliases', () => {
    expect(rootAppSupportsDeviceArchitecture('universal', '')).toBe(true);
    expect(rootAppSupportsDeviceArchitecture('arm64-v8a', 'arm64')).toBe(true);
    expect(rootAppSupportsDeviceArchitecture('x86-64', 'x86_64')).toBe(true);
  });

  it('fails closed for missing, unsupported, or mismatched architecture evidence', () => {
    expect(rootAppSupportsDeviceArchitecture('arm64-v8a', '')).toBe(false);
    expect(rootAppSupportsDeviceArchitecture('arm64-v8a', 'x86_64')).toBe(false);
    expect(rootAppSupportsDeviceArchitecture('mips', 'mips')).toBe(false);
  });
});

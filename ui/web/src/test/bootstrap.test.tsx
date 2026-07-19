import { beforeEach, describe, expect, it, vi } from 'vitest';

const renderRoot = vi.hoisted(() => vi.fn());
const createRoot = vi.hoisted(() => vi.fn(() => ({ render: renderRoot })));

vi.mock('react-dom/client', () => ({ createRoot }));

describe('production bootstrap', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    createRoot.mockClear();
    renderRoot.mockClear();
  });

  it('fails clearly when the persistent WebView shell has no root', async () => {
    const { mountPixelFlasher } = await import('../bootstrap');
    expect(() => mountPixelFlasher()).toThrow('root element is unavailable');
    expect(createRoot).not.toHaveBeenCalled();
  });

  it('mounts the app into the shell root', async () => {
    const root = document.createElement('div');
    root.id = 'root';
    document.body.append(root);
    const { mountPixelFlasher } = await import('../bootstrap');
    mountPixelFlasher();
    expect(createRoot).toHaveBeenCalledWith(root);
    expect(renderRoot).toHaveBeenCalledOnce();
  });

  it('production entrypoint invokes the shared bootstrap', async () => {
    const root = document.createElement('div');
    root.id = 'root';
    document.body.append(root);
    vi.resetModules();
    await import('../main');
    expect(createRoot).toHaveBeenCalledWith(root);
  });
});

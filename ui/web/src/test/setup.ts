import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';
import { installDevelopmentBridge } from '../mockBridge';

installDevelopmentBridge();
const developmentBridge = window.pixelflasher;

beforeEach(() => {
  window.pixelflasher = developmentBridge;
  developmentBridge?.__reset?.();
  window.localStorage.clear();
  window.location.hash = '';
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-contrast');
  document.documentElement.removeAttribute('data-motion');
  document.documentElement.style.fontSize = '';
  if (!window.requestAnimationFrame) {
    window.requestAnimationFrame = (callback: FrameRequestCallback) => window.setTimeout(() => callback(performance.now()), 0);
  }
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.pixelflasher = developmentBridge;
});

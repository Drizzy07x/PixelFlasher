import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';

export function mountPixelFlasher() {
  const root = document.getElementById('root');
  if (!root) throw new Error('PixelFlasher root element is unavailable.');

  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

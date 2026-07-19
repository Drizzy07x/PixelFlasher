import { mountPixelFlasher } from './bootstrap';
import { installDevelopmentBridge } from './mockBridge';

// The local Vite entrypoint owns the demo bridge. Production starts from
// main.tsx and therefore cannot install or bundle this implementation.
installDevelopmentBridge();
mountPixelFlasher();

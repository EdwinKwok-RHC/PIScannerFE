import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { installCspStyleAdapter } from './utils/cspStyleAdapter';
import './index.css';

// Must run before any Fluent UI component renders (see cspStyleAdapter.ts).
installCspStyleAdapter();

const container = document.getElementById('root');
if (!container) throw new Error('Root element #root not found');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

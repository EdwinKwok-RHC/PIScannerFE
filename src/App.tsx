import {
  FluentProvider,
  makeStyles,
  tokens,
  webDarkTheme,
  webLightTheme,
} from '@fluentui/react-components';
import { useState } from 'react';
import { AppHeader } from './components/AppHeader';
import { ScannerPage } from './features/scanner/ScannerPage';

const useStyles = makeStyles({
  root: {
    minHeight: '100vh',
    backgroundColor: tokens.colorNeutralBackground2,
    color: tokens.colorNeutralForeground1,
  },
});

/** Initial theme follows the OS preference. The choice is not persisted. */
function prefersDark(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

export function App() {
  const styles = useStyles();
  const [isDark, setIsDark] = useState(prefersDark);
  return (
    // Layout styles live on an inner element: Fluent copies the provider's
    // className onto portal mount nodes (tooltips), so page-level background
    // or sizing on the provider itself would cover the page.
    <FluentProvider theme={isDark ? webDarkTheme : webLightTheme}>
      <div className={styles.root}>
        <AppHeader isDark={isDark} onThemeChange={setIsDark} />
        <ScannerPage />
      </div>
    </FluentProvider>
  );
}

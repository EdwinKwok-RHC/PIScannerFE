import { Caption1, Switch, Title3, makeStyles, tokens } from '@fluentui/react-components';
import {
  ShieldKeyholeRegular,
  WeatherMoonRegular,
  WeatherSunnyRegular,
} from '@fluentui/react-icons';
import { PrivacyBadge } from './PrivacyBadge';

const useStyles = makeStyles({
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalL,
    padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalXXL}`,
    borderBottom: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    backgroundColor: tokens.colorNeutralBackground1,
    '@media (max-width: 640px)': {
      padding: `${tokens.spacingVerticalM} ${tokens.spacingHorizontalL}`,
    },
  },
  brand: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalM,
  },
  logo: {
    fontSize: '32px',
    color: tokens.colorBrandForeground1,
    flexShrink: 0,
  },
  titles: {
    display: 'flex',
    flexDirection: 'column',
  },
  title: {
    margin: 0,
  },
  subtitle: {
    color: tokens.colorNeutralForeground3,
  },
  tools: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalL,
    flexWrap: 'wrap',
  },
  theme: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalXS,
    color: tokens.colorNeutralForeground2,
  },
});

interface AppHeaderProps {
  isDark: boolean;
  onThemeChange: (dark: boolean) => void;
}

export function AppHeader({ isDark, onThemeChange }: AppHeaderProps) {
  const styles = useStyles();
  return (
    <header className={styles.header}>
      <div className={styles.brand}>
        <ShieldKeyholeRegular className={styles.logo} aria-hidden="true" />
        <div className={styles.titles}>
          <Title3 as="h1" className={styles.title}>
            Prompt Security Scanner
          </Title3>
          <Caption1 className={styles.subtitle}>Local deterministic analysis</Caption1>
        </div>
      </div>
      <div className={styles.tools}>
        <PrivacyBadge />
        <div className={styles.theme}>
          {isDark ? (
            <WeatherMoonRegular aria-hidden="true" />
          ) : (
            <WeatherSunnyRegular aria-hidden="true" />
          )}
          <Switch
            label="Dark theme"
            checked={isDark}
            onChange={(_, data) => {
              onThemeChange(data.checked);
            }}
          />
        </div>
      </div>
    </header>
  );
}

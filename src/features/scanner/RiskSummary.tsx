import { Caption1, Text, makeStyles, mergeClasses, tokens } from '@fluentui/react-components';
import { RiskIcon } from '../../components/RiskBadge';
import type { RiskLevel } from '../../security/types';
import { LEVEL_LABEL } from '../../utils/severity';

const useStyles = makeStyles({
  root: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalL,
  },
  icon: {
    fontSize: '56px',
    flexShrink: 0,
    display: 'flex',
  },
  body: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXXS,
    flexGrow: 1,
    minWidth: 0,
  },
  level: {
    fontSize: tokens.fontSizeHero800,
    lineHeight: tokens.lineHeightHero800,
    fontWeight: tokens.fontWeightBold,
    letterSpacing: '0.02em',
  },
  score: {
    fontSize: tokens.fontSizeBase500,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground2,
  },
  track: {
    height: '8px',
    borderRadius: tokens.borderRadiusCircular,
    backgroundColor: tokens.colorNeutralBackground5,
    overflow: 'hidden',
    marginTop: tokens.spacingVerticalS,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
  },
  bar: {
    height: '100%',
    borderRadius: tokens.borderRadiusCircular,
  },
  SAFE: { color: tokens.colorPaletteGreenForeground1 },
  LOW: { color: tokens.colorPaletteBlueForeground2 },
  MEDIUM: { color: tokens.colorPaletteMarigoldForeground1 },
  HIGH: { color: tokens.colorPaletteDarkOrangeForeground1 },
  CRITICAL: { color: tokens.colorPaletteRedForeground1 },
  barSAFE: { backgroundColor: tokens.colorPaletteGreenBorderActive },
  barLOW: { backgroundColor: tokens.colorPaletteBlueBorderActive },
  barMEDIUM: { backgroundColor: tokens.colorPaletteMarigoldBorderActive },
  barHIGH: { backgroundColor: tokens.colorPaletteDarkOrangeBorderActive },
  barCRITICAL: { backgroundColor: tokens.colorPaletteRedBorderActive },
  note: {
    color: tokens.colorNeutralForeground3,
  },
});

interface RiskSummaryProps {
  level: RiskLevel;
  score: number;
}

export function RiskSummary({ level, score }: RiskSummaryProps) {
  const styles = useStyles();
  const label = LEVEL_LABEL[level];
  return (
    <div className={styles.root}>
      <span className={mergeClasses(styles.icon, styles[level])} aria-hidden="true">
        <RiskIcon level={level} />
      </span>
      <div className={styles.body}>
        <Text className={mergeClasses(styles.level, styles[level])} data-testid="overall-level">
          {label.toUpperCase()}
        </Text>
        <Text className={styles.score} data-testid="overall-score">
          {score} / 100
        </Text>
        <div
          className={styles.track}
          role="meter"
          aria-label="Overall risk score"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={score}
          aria-valuetext={`${score} out of 100, ${label}`}
        >
          {/* Width is applied via the CSSOM (React style prop), which CSP allows. */}
          <div
            className={mergeClasses(styles.bar, styles[`bar${level}`])}
            style={{ width: `${Math.max(score, 2)}%` }}
          />
        </div>
        <Caption1 className={styles.note}>
          Deterministic quick assessment based on known patterns, not a guarantee of safety.
        </Caption1>
      </div>
    </div>
  );
}

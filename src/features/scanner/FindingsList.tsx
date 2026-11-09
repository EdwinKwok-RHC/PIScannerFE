import {
  Badge,
  Body1,
  Caption1,
  Card,
  Subtitle2,
  Text,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import { useId } from 'react';
import { RiskBadge } from '../../components/RiskBadge';
import type { Correlation, Finding } from '../../security/types';
import { CATEGORY_LABEL, LEVEL_RANK } from '../../utils/severity';

const useStyles = makeStyles({
  list: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
  },
  card: {
    padding: tokens.spacingHorizontalL,
    gap: tokens.spacingVerticalS,
  },
  head: {
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalS,
  },
  title: {
    margin: 0,
    flexBasis: '100%',
  },
  ruleId: {
    fontFamily: tokens.fontFamilyMonospace,
    color: tokens.colorNeutralForeground3,
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'max-content minmax(0, 1fr)',
    columnGap: tokens.spacingHorizontalM,
    rowGap: tokens.spacingVerticalS,
    margin: 0,
    '@media (max-width: 480px)': {
      gridTemplateColumns: 'minmax(0, 1fr)',
    },
  },
  term: {
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground2,
  },
  detail: {
    margin: 0,
    minWidth: 0,
  },
  evidence: {
    display: 'block',
    margin: 0,
    padding: `${tokens.spacingVerticalXS} ${tokens.spacingHorizontalS}`,
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    backgroundColor: tokens.colorNeutralBackground3,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
  },
  correlations: {
    margin: 0,
    paddingLeft: tokens.spacingHorizontalXL,
    color: tokens.colorNeutralForeground2,
  },
  empty: {
    color: tokens.colorNeutralForeground2,
  },
});

function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => LEVEL_RANK[b.severity] - LEVEL_RANK[a.severity] || b.contribution - a.contribution,
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const styles = useStyles();
  const titleId = useId();
  return (
    <Card className={styles.card} aria-labelledby={titleId} role="article">
      <div className={styles.head}>
        <RiskBadge level={finding.severity} context="Severity" />
        <Badge appearance="outline" color="informative">
          {CATEGORY_LABEL[finding.category]}
        </Badge>
        <Caption1 className={styles.ruleId}>{finding.ruleId}</Caption1>
        <Caption1>Confidence: {finding.confidenceLabel}</Caption1>
        <Subtitle2 as="h3" id={titleId} className={styles.title}>
          {finding.title}
        </Subtitle2>
      </div>
      <dl className={styles.grid}>
        <dt className={styles.term}>Severity</dt>
        <dd className={styles.detail}>
          <Text>
            {finding.severity.charAt(0) + finding.severity.slice(1).toLowerCase()} (contributes{' '}
            {finding.contribution} pts)
          </Text>
        </dd>
        <dt className={styles.term}>Category</dt>
        <dd className={styles.detail}>{CATEGORY_LABEL[finding.category]}</dd>
        <dt className={styles.term}>Rule</dt>
        <dd className={styles.detail}>
          {finding.ruleId}: {finding.title}
        </dd>
        <dt className={styles.term}>Evidence</dt>
        <dd className={styles.detail}>
          {/* Rendered strictly as a text node: never parsed as HTML, never linkified. */}
          <code className={styles.evidence}>{finding.evidence || '(no text span)'}</code>
        </dd>
        <dt className={styles.term}>Explanation</dt>
        <dd className={styles.detail}>
          <Body1>{finding.explanation}</Body1>
        </dd>
        <dt className={styles.term}>Remediation</dt>
        <dd className={styles.detail}>
          <Body1>{finding.remediation}</Body1>
        </dd>
      </dl>
    </Card>
  );
}

interface FindingsListProps {
  findings: readonly Finding[];
  correlations: readonly Correlation[];
}

export function FindingsList({ findings, correlations }: FindingsListProps) {
  const styles = useStyles();
  if (findings.length === 0) {
    return (
      <Body1 className={styles.empty}>
        No known risky patterns were detected. This is a pattern-based check and does not prove the
        prompt is safe.
      </Body1>
    );
  }
  return (
    <>
      {correlations.length > 0 && (
        <div>
          <Text weight="semibold">Context correlations applied</Text>
          <ul className={styles.correlations}>
            {correlations.map((c) => (
              <li key={c.id}>
                {c.description}
                {c.floor > 0 ? ` (minimum score ${c.floor})` : ''}
                {c.bonus > 0 ? ` (+${c.bonus})` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}
      <ul className={styles.list} aria-label="Findings">
        {sortFindings(findings).map((f) => (
          <li key={f.id}>
            <FindingCard finding={f} />
          </li>
        ))}
      </ul>
    </>
  );
}

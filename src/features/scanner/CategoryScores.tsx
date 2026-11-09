import { Caption1, Text, makeStyles, tokens } from '@fluentui/react-components';
import { RiskBadge } from '../../components/RiskBadge';
import { CATEGORIES, type Category, type CategoryResult } from '../../security/types';
import { CATEGORY_LABEL } from '../../utils/severity';

const useStyles = makeStyles({
  list: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
    display: 'flex',
    flexDirection: 'column',
  },
  row: {
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1fr) auto auto',
    alignItems: 'center',
    gap: tokens.spacingHorizontalM,
    padding: `${tokens.spacingVerticalS} 0`,
    borderBottom: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    ':last-child': {
      borderBottom: 'none',
    },
  },
  score: {
    color: tokens.colorNeutralForeground3,
    fontVariantNumeric: 'tabular-nums',
    minWidth: '4.5em',
    textAlign: 'right',
  },
});

export function CategoryScores({ categories }: { categories: Record<Category, CategoryResult> }) {
  const styles = useStyles();
  return (
    <ul className={styles.list} aria-label="Category ratings">
      {CATEGORIES.map((c) => {
        const r = categories[c];
        return (
          <li key={c} className={styles.row}>
            <Text weight="semibold">{CATEGORY_LABEL[c]}</Text>
            <Caption1 className={styles.score}>
              {r.score}/100 · {r.findingCount} {r.findingCount === 1 ? 'finding' : 'findings'}
            </Caption1>
            <RiskBadge level={r.level} context={`${CATEGORY_LABEL[c]} rating`} />
          </li>
        );
      })}
    </ul>
  );
}

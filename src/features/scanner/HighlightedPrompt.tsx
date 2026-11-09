import { Caption1, Tooltip, makeStyles, mergeClasses, tokens } from '@fluentui/react-components';
import type { HighlightKind, HighlightRun } from '../../security/types';
import { HIGHLIGHT_LABEL } from '../../utils/severity';

/**
 * Highlight styles differ in background AND underline pattern so they are
 * distinguishable without relying on color alone.
 */
const useStyles = makeStyles({
  pre: {
    margin: 0,
    padding: tokens.spacingHorizontalM,
    maxHeight: '360px',
    overflow: 'auto',
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase300,
    lineHeight: tokens.lineHeightBase400,
    backgroundColor: tokens.colorNeutralBackground2,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    color: tokens.colorNeutralForeground1,
  },
  mark: {
    color: tokens.colorNeutralForeground1,
    borderRadius: tokens.borderRadiusSmall,
    padding: '0 1px',
    cursor: 'help',
    ':focus-visible': {
      outline: `${tokens.strokeWidthThick} solid ${tokens.colorStrokeFocus2}`,
      outlineOffset: '1px',
    },
  },
  injection: {
    backgroundColor: tokens.colorPaletteRedBackground2,
    borderBottom: `2px solid ${tokens.colorPaletteRedBorderActive}`,
  },
  outbound: {
    backgroundColor: tokens.colorPaletteDarkOrangeBackground2,
    borderBottom: `2px dashed ${tokens.colorPaletteDarkOrangeBorderActive}`,
  },
  sensitive: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    borderBottom: `2px dotted ${tokens.colorPaletteMarigoldBorderActive}`,
  },
  destination: {
    backgroundColor: tokens.colorPalettePurpleBackground2,
    borderBottom: `3px double ${tokens.colorPalettePurpleBorderActive}`,
  },
  obfuscation: {
    backgroundColor: tokens.colorPaletteTealBackground2,
    textDecorationLine: 'underline',
    textDecorationStyle: 'wavy',
    textDecorationColor: tokens.colorPaletteTealBorderActive,
  },
  secret: {
    backgroundColor: tokens.colorNeutralBackground5,
    outline: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke1}`,
    fontWeight: tokens.fontWeightSemibold,
  },
  legend: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: `${tokens.spacingVerticalXS} ${tokens.spacingHorizontalM}`,
    listStyle: 'none',
    margin: `${tokens.spacingVerticalS} 0 0`,
    padding: 0,
  },
  swatch: {
    display: 'inline-block',
    marginRight: tokens.spacingHorizontalXS,
    padding: '0 4px',
  },
});

const LEGEND: readonly HighlightKind[] = [
  'injection',
  'outbound',
  'sensitive',
  'destination',
  'obfuscation',
  'secret',
];

export function HighlightedPrompt({ runs }: { runs: readonly HighlightRun[] }) {
  const styles = useStyles();
  return (
    <div>
      {/*
        Every run is rendered as a React text node. No HTML parsing, no
        dangerouslySetInnerHTML, and URLs are never turned into links.
      */}
      <pre
        className={styles.pre}
        data-testid="highlighted-prompt"
        tabIndex={0}
        aria-label="Scanned prompt with highlighted evidence"
      >
        {runs.map((run) => {
          if (!run.kind) return <span key={run.start}>{run.text}</span>;
          const kindLabel = HIGHLIGHT_LABEL[run.kind];
          const description = `${kindLabel}: ${run.labels.join('; ')}`;
          return (
            <Tooltip key={run.start} content={description} relationship="description" withArrow>
              <mark
                className={mergeClasses(styles.mark, styles[run.kind])}
                tabIndex={0}
                data-kind={run.kind}
              >
                {run.text}
              </mark>
            </Tooltip>
          );
        })}
      </pre>
      <ul className={styles.legend} aria-label="Highlight legend">
        {LEGEND.map((k) => (
          <li key={k}>
            <Caption1>
              <span className={mergeClasses(styles.swatch, styles[k])} aria-hidden="true">
                Aa
              </span>
              {HIGHLIGHT_LABEL[k]}
            </Caption1>
          </li>
        ))}
      </ul>
    </div>
  );
}

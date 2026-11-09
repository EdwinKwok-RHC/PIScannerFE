import {
  Body1,
  Card,
  MessageBar,
  MessageBarBody,
  Subtitle1,
  Text,
  makeStyles,
  mergeClasses,
  tokens,
} from '@fluentui/react-components';
import { LockClosedRegular } from '@fluentui/react-icons';
import { useRef, useState } from 'react';
import { scanPrompt } from '../../security/scanner';
import type { ScanResult } from '../../security/types';
import { LEVEL_LABEL } from '../../utils/severity';
import { CategoryScores } from './CategoryScores';
import { FindingsList } from './FindingsList';
import { HighlightedPrompt } from './HighlightedPrompt';
import { PromptEditor } from './PromptEditor';
import { DEFAULT_MAX_LENGTH } from './promptLimits';
import { RiskSummary } from './RiskSummary';

const useStyles = makeStyles({
  main: {
    maxWidth: '1440px',
    margin: '0 auto',
    padding: `${tokens.spacingVerticalXL} ${tokens.spacingHorizontalXXL}`,
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
    '@media (max-width: 640px)': {
      padding: `${tokens.spacingVerticalL} ${tokens.spacingHorizontalM}`,
    },
  },
  notice: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalS,
    padding: `${tokens.spacingVerticalS} ${tokens.spacingHorizontalM}`,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorPaletteGreenBackground1,
    border: `${tokens.strokeWidthThin} solid ${tokens.colorPaletteGreenBorder1}`,
    color: tokens.colorNeutralForeground1,
  },
  noticeIcon: {
    color: tokens.colorPaletteGreenForeground1,
    fontSize: '20px',
    flexShrink: 0,
  },
  layout: {
    display: 'grid',
    gap: tokens.spacingHorizontalXL,
    gridTemplateColumns: 'minmax(0, 7fr) minmax(0, 5fr)',
    alignItems: 'start',
    '@media (max-width: 1023px)': {
      gridTemplateColumns: 'minmax(0, 1fr)',
    },
  },
  column: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
    minWidth: 0,
    // When stacked, flatten both columns into one grid so results can be
    // ordered: editor, overall risk, categories, evidence, findings.
    '@media (max-width: 1023px)': {
      display: 'contents',
    },
  },
  editor: { '@media (max-width: 1023px)': { order: 0 } },
  overall: { '@media (max-width: 1023px)': { order: 1 } },
  categories: { '@media (max-width: 1023px)': { order: 2 } },
  evidence: { '@media (max-width: 1023px)': { order: 3 } },
  findings: { '@media (max-width: 1023px)': { order: 4 } },
  card: {
    padding: tokens.spacingHorizontalXL,
    gap: tokens.spacingVerticalM,
    '@media (max-width: 640px)': {
      padding: tokens.spacingHorizontalL,
    },
  },
  sectionTitle: {
    margin: 0,
  },
  eyebrow: {
    margin: 0,
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground3,
  },
  muted: {
    color: tokens.colorNeutralForeground3,
  },
});

export function ScannerPage() {
  const styles = useStyles();
  const [prompt, setPrompt] = useState('');
  const [maxLength, setMaxLength] = useState(DEFAULT_MAX_LENGTH);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scannedPrompt, setScannedPrompt] = useState('');
  const [announcement, setAnnouncement] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // Prompt text lives only in React state (memory). It is never written to
  // localStorage, sessionStorage, IndexedDB, cookies, the URL or the network.

  const handleScan = () => {
    if (prompt.trim().length === 0 || prompt.length > maxLength) return;
    const r = scanPrompt(prompt, { maxLength });
    setResult(r);
    setScannedPrompt(prompt);
    const n = r.findings.length;
    setAnnouncement(
      `Scan complete. Overall risk ${LEVEL_LABEL[r.level]}, score ${r.score} out of 100. ${n} ${n === 1 ? 'finding' : 'findings'}.`,
    );
  };

  const handleClear = () => {
    setPrompt('');
    setResult(null);
    setScannedPrompt('');
    setAnnouncement('Prompt and results cleared.');
    textareaRef.current?.focus();
  };

  const stale = result !== null && prompt !== scannedPrompt;

  return (
    <main className={styles.main} id="main">
      <div className={styles.notice} role="note">
        <LockClosedRegular className={styles.noticeIcon} aria-hidden="true" />
        <Text weight="semibold">Analysis runs locally. Your prompt is not sent anywhere.</Text>
      </div>

      <div className={styles.layout}>
        <div className={styles.column}>
          <Card
            className={mergeClasses(styles.card, styles.editor)}
            role="region"
            aria-labelledby="editor-title"
          >
            <Subtitle1 as="h2" id="editor-title" className={styles.sectionTitle}>
              Prompt Editor
            </Subtitle1>
            <PromptEditor
              value={prompt}
              maxLength={maxLength}
              hasResult={result !== null}
              textareaRef={textareaRef}
              onChange={setPrompt}
              onMaxLengthChange={setMaxLength}
              onScan={handleScan}
              onClear={handleClear}
            />
          </Card>

          {result && (
            <Card
              className={mergeClasses(styles.card, styles.evidence)}
              role="region"
              aria-labelledby="evidence-title"
            >
              <Subtitle1 as="h2" id="evidence-title" className={styles.sectionTitle}>
                Highlighted Evidence
              </Subtitle1>
              <Body1 className={styles.muted}>
                Suspicious text from the scanned prompt. Focus or hover a highlight to see why it
                was flagged. Credential-like values are redacted.
              </Body1>
              <HighlightedPrompt runs={result.highlights} />
            </Card>
          )}
        </div>

        <div className={styles.column}>
          <Card
            className={mergeClasses(styles.card, styles.overall)}
            role="region"
            aria-labelledby="overall-title"
          >
            <h2 id="overall-title" className={styles.eyebrow}>
              Overall Risk
            </h2>
            {result ? (
              <RiskSummary level={result.level} score={result.score} />
            ) : (
              <Body1 className={styles.muted}>
                No scan yet. Paste a prompt and select <strong>Scan Prompt</strong>.
              </Body1>
            )}
            {stale && (
              <MessageBar intent="warning">
                <MessageBarBody>
                  The prompt has changed since the last scan. Results reflect the previous text.
                </MessageBarBody>
              </MessageBar>
            )}
            {result?.truncated && (
              <MessageBar intent="warning">
                <MessageBarBody>
                  Input exceeded the analysis limit and was truncated.
                </MessageBarBody>
              </MessageBar>
            )}
          </Card>

          {result && (
            <Card
              className={mergeClasses(styles.card, styles.categories)}
              role="region"
              aria-labelledby="categories-title"
            >
              <Subtitle1 as="h2" id="categories-title" className={styles.sectionTitle}>
                Category Scores
              </Subtitle1>
              <CategoryScores categories={result.categories} />
            </Card>
          )}

          {result && (
            <Card
              className={mergeClasses(styles.card, styles.findings)}
              role="region"
              aria-labelledby="findings-title"
            >
              <Subtitle1 as="h2" id="findings-title" className={styles.sectionTitle}>
                Findings ({result.findings.length})
              </Subtitle1>
              <FindingsList findings={result.findings} correlations={result.correlations} />
            </Card>
          )}
        </div>
      </div>

      <div role="status" aria-live="polite" aria-atomic="true" className="visually-hidden">
        {announcement}
      </div>
    </main>
  );
}

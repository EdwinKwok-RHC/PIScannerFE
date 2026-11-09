import {
  Button,
  Caption1,
  Field,
  Select,
  Textarea,
  makeStyles,
  tokens,
} from '@fluentui/react-components';
import { EraserRegular, ShieldTaskRegular } from '@fluentui/react-icons';
import { useId, type KeyboardEvent, type RefObject } from 'react';
import { EXAMPLE_PROMPTS, type ExampleGroup } from '../../data/examples';
import { MAX_LENGTH_OPTIONS } from './promptLimits';

const GROUPS: readonly ExampleGroup[] = ['Benign', 'Suspicious', 'Critical'];
const fmt = new Intl.NumberFormat('en-US');

const useStyles = makeStyles({
  root: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
  },
  controls: {
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)',
    gap: tokens.spacingHorizontalM,
    '@media (max-width: 640px)': {
      gridTemplateColumns: 'minmax(0, 1fr)',
    },
  },
  textarea: {
    width: '100%',
    '& textarea': {
      minHeight: '320px',
      maxHeight: '70vh',
      fontFamily: tokens.fontFamilyMonospace,
      fontSize: tokens.fontSizeBase300,
      lineHeight: tokens.lineHeightBase300,
    },
  },
  meta: {
    display: 'flex',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalS,
    color: tokens.colorNeutralForeground3,
  },
  over: {
    color: tokens.colorPaletteRedForeground1,
    fontWeight: tokens.fontWeightSemibold,
  },
  actions: {
    display: 'flex',
    gap: tokens.spacingHorizontalM,
    flexWrap: 'wrap',
    alignItems: 'center',
  },
});

interface PromptEditorProps {
  value: string;
  maxLength: number;
  hasResult: boolean;
  textareaRef: RefObject<HTMLTextAreaElement | null>;
  onChange: (value: string) => void;
  onMaxLengthChange: (value: number) => void;
  onScan: () => void;
  onClear: () => void;
}

export function PromptEditor({
  value,
  maxLength,
  hasResult,
  textareaRef,
  onChange,
  onMaxLengthChange,
  onScan,
  onClear,
}: PromptEditorProps) {
  const styles = useStyles();
  const counterId = useId();
  const hintId = useId();
  const length = value.length;
  const isEmpty = value.trim().length === 0;
  const isOver = length > maxLength;
  const canScan = !isEmpty && !isOver;

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      if (canScan) onScan();
    }
  };

  return (
    <div className={styles.root}>
      <div className={styles.controls}>
        <Field label="Load an example prompt">
          <Select
            value=""
            onChange={(_, data) => {
              const example = EXAMPLE_PROMPTS.find((x) => x.id === data.value);
              if (example) onChange(example.prompt);
            }}
          >
            <option value="" disabled>
              Choose an example…
            </option>
            {GROUPS.map((group) => (
              <optgroup key={group} label={group}>
                {EXAMPLE_PROMPTS.filter((x) => x.group === group).map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.label}
                  </option>
                ))}
              </optgroup>
            ))}
          </Select>
        </Field>
        <Field label="Maximum length">
          <Select
            value={String(maxLength)}
            onChange={(_, data) => {
              onMaxLengthChange(Number(data.value));
            }}
          >
            {MAX_LENGTH_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {fmt.format(n)} characters
              </option>
            ))}
          </Select>
        </Field>
      </div>

      <Field
        label="Prompt to scan"
        validationState={isOver ? 'error' : 'none'}
        validationMessage={
          isOver
            ? `The prompt is ${fmt.format(length - maxLength)} characters over the ${fmt.format(maxLength)} character limit.`
            : null
        }
      >
        <Textarea
          textarea={{ ref: textareaRef }}
          className={styles.textarea}
          value={value}
          resize="vertical"
          placeholder="Paste an AI prompt here. It is treated as untrusted plain text and never leaves this browser."
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          aria-describedby={`${counterId} ${hintId}`}
          onChange={(_, data) => {
            onChange(data.value);
          }}
          onKeyDown={handleKeyDown}
        />
      </Field>

      <div className={styles.meta}>
        <Caption1 id={hintId}>Press Ctrl+Enter to scan. Scanning only runs when you ask.</Caption1>
        <Caption1 id={counterId} className={isOver ? styles.over : undefined}>
          {fmt.format(length)} / {fmt.format(maxLength)} characters
        </Caption1>
      </div>

      <div className={styles.actions}>
        <Button
          appearance="primary"
          icon={<ShieldTaskRegular />}
          disabled={!canScan}
          onClick={onScan}
        >
          Scan Prompt
        </Button>
        <Button
          appearance="secondary"
          icon={<EraserRegular />}
          disabled={length === 0 && !hasResult}
          onClick={onClear}
        >
          Clear
        </Button>
      </div>
    </div>
  );
}

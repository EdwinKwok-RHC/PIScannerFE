import { Badge, Button, Text, Tooltip, makeStyles, tokens } from '@fluentui/react-components';
import { InfoRegular, LockClosedFilled } from '@fluentui/react-icons';

const useStyles = makeStyles({
  root: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalS,
    flexWrap: 'wrap',
  },
  text: {
    color: tokens.colorNeutralForeground2,
  },
});

export const PRIVACY_TOOLTIP =
  'Prompt analysis uses deterministic rules running locally in your browser. No AI service or backend API is used.';

export function PrivacyBadge() {
  const styles = useStyles();
  return (
    <div className={styles.root}>
      <Badge
        appearance="tint"
        color="success"
        size="large"
        shape="rounded"
        icon={<LockClosedFilled />}
      >
        Local Analysis
      </Badge>
      <Text size={200} className={styles.text}>
        Your prompt stays in this browser.
      </Text>
      <Tooltip content={PRIVACY_TOOLTIP} relationship="description" withArrow>
        <Button
          appearance="transparent"
          size="small"
          icon={<InfoRegular />}
          aria-label="About local analysis"
        />
      </Tooltip>
    </div>
  );
}

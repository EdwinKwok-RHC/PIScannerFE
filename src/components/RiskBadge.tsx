import { Badge, type BadgeProps } from '@fluentui/react-components';
import {
  CheckmarkCircleFilled,
  ErrorCircleFilled,
  InfoFilled,
  ShieldErrorFilled,
  WarningFilled,
} from '@fluentui/react-icons';
import type { ReactElement } from 'react';
import type { RiskLevel } from '../security/types';
import { LEVEL_BADGE_COLOR, LEVEL_LABEL } from '../utils/severity';

/** Each level has a distinct icon so severity is never conveyed by color alone. */
const ICONS: Record<RiskLevel, ReactElement> = {
  SAFE: <CheckmarkCircleFilled />,
  LOW: <InfoFilled />,
  MEDIUM: <WarningFilled />,
  HIGH: <ErrorCircleFilled />,
  CRITICAL: <ShieldErrorFilled />,
};

export function RiskIcon({ level }: { level: RiskLevel }) {
  return ICONS[level];
}

interface RiskBadgeProps {
  level: RiskLevel;
  /** Prefix for the accessible name, e.g. "Severity" or "Prompt Injection rating". */
  context?: string;
  size?: BadgeProps['size'];
  appearance?: BadgeProps['appearance'];
}

export function RiskBadge({
  level,
  context,
  size = 'medium',
  appearance = 'tint',
}: RiskBadgeProps) {
  const label = LEVEL_LABEL[level];
  return (
    <Badge
      appearance={appearance}
      color={LEVEL_BADGE_COLOR[level]}
      size={size}
      icon={ICONS[level]}
      aria-label={context ? `${context}: ${label}` : label}
      role="img"
    >
      {label.toUpperCase()}
    </Badge>
  );
}

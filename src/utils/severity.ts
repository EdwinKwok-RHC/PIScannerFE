import type { BadgeProps } from '@fluentui/react-components';
import type { Category, HighlightKind, RiskLevel } from '../security/types';

export const LEVEL_LABEL: Record<RiskLevel, string> = {
  SAFE: 'Safe',
  LOW: 'Low',
  MEDIUM: 'Medium',
  HIGH: 'High',
  CRITICAL: 'Critical',
};

/** Fluent badge colors: green / blue / amber / orange / red. */
export const LEVEL_BADGE_COLOR: Record<RiskLevel, NonNullable<BadgeProps['color']>> = {
  SAFE: 'success',
  LOW: 'brand',
  MEDIUM: 'warning',
  HIGH: 'severe',
  CRITICAL: 'danger',
};

export const LEVEL_RANK: Record<RiskLevel, number> = {
  SAFE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export const CATEGORY_LABEL: Record<Category, string> = {
  PROMPT_INJECTION: 'Prompt Injection',
  DATA_EXFILTRATION: 'Data Exfiltration',
  SENSITIVE_DATA: 'Sensitive Data',
  OBFUSCATION: 'Obfuscation',
};

export const HIGHLIGHT_LABEL: Record<HighlightKind, string> = {
  injection: 'Prompt injection',
  outbound: 'Outbound action',
  sensitive: 'Sensitive data',
  destination: 'Destination',
  obfuscation: 'Obfuscation / concealment',
  secret: 'Redacted credential',
};

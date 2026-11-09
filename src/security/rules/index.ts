import type { Rule } from '../types';
import { dataExfiltrationRules } from './dataExfiltration';
import { obfuscationRules } from './obfuscation';
import { promptInjectionRules } from './promptInjection';
import { sensitiveDataRules } from './sensitiveData';

/**
 * Registry of all detection rules. To add a rule, create a `Rule` object in
 * the appropriate category module (or a new module) and include it here.
 */
export const RULES: readonly Rule[] = [
  ...promptInjectionRules,
  ...dataExfiltrationRules,
  ...sensitiveDataRules,
  ...obfuscationRules,
];

export { dataExfiltrationRules, obfuscationRules, promptInjectionRules, sensitiveDataRules };

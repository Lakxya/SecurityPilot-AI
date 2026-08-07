export type IntentType =
  | 'GREETING'
  | 'CASUAL_CONVERSATION'
  | 'GENERAL_CYBERSECURITY'
  | 'PROGRAMMING'
  | 'SECURITY_AUDIT'
  | 'STRIDE_REVIEW'
  | 'OWASP_AUDIT'
  | 'ARCHITECTURE_GEN'
  | 'README_GEN'
  | 'SRS_GEN'
  | 'TERRAFORM_GEN'
  | 'DOCUMENT_EDITING';

export function classifyUserIntent(text: string): IntentType {
  const clean = text.trim().toLowerCase();

  // 1. Greetings
  if (
    /^(hi|hello|hey|greetings|good morning|good afternoon|good evening|yo|sup)$/i.test(clean) ||
    clean.startsWith('hi ') ||
    clean.startsWith('hello ') ||
    clean.startsWith('hey ')
  ) {
    return 'GREETING';
  }

  // 2. Casual Conversation
  if (
    clean.includes('how are you') ||
    clean.includes('who are you') ||
    clean.includes('what can you do') ||
    clean.includes('help me') ||
    clean.includes('thank')
  ) {
    return 'CASUAL_CONVERSATION';
  }

  // 3. STRIDE Review
  if (clean.includes('stride') || clean.includes('spoofing') || clean.includes('tampering') || clean.includes('repudiation')) {
    return 'STRIDE_REVIEW';
  }

  // 4. OWASP Audit
  if (clean.includes('owasp') || clean.includes('top 10') || clean.includes('xss') || clean.includes('sqli') || clean.includes('injection vulnerability')) {
    return 'OWASP_AUDIT';
  }

  // 5. Security Audit
  if (
    clean.includes('audit') ||
    clean.includes('vulnerability') ||
    clean.includes('threat model') ||
    clean.includes('security review') ||
    clean.includes('cvss') ||
    clean.includes('risk assessment')
  ) {
    return 'SECURITY_AUDIT';
  }

  // 6. Architecture Generation
  if (clean.includes('architecture') || clean.includes('system design') || clean.includes('diagram') || clean.includes('blueprint')) {
    return 'ARCHITECTURE_GEN';
  }

  // 7. Specific Artifact Generators
  if (clean.includes('terraform') || clean.includes('hcl') || clean.includes('iac')) {
    return 'TERRAFORM_GEN';
  }
  if (clean.includes('readme')) {
    return 'README_GEN';
  }
  if (clean.includes('srs') || clean.includes('specification')) {
    return 'SRS_GEN';
  }

  // 8. General Cybersecurity Question
  if (
    clean.includes('explain') ||
    clean.includes('what is') ||
    clean.includes('jwt') ||
    clean.includes('oauth') ||
    clean.includes('tls') ||
    clean.includes('aes') ||
    clean.includes('rsa') ||
    clean.includes('cipher')
  ) {
    return 'GENERAL_CYBERSECURITY';
  }

  // 9. Programming Question
  if (clean.includes('function') || clean.includes('code') || clean.includes('json') || clean.includes('python') || clean.includes('react')) {
    return 'PROGRAMMING';
  }

  // Default fallback
  return 'GENERAL_CYBERSECURITY';
}

/**
  Returns true ONLY if the intent requires rendering the Executive Security Report UI & Modal.
 */
export function isReportIntent(intent: IntentType): boolean {
  return (
    intent === 'SECURITY_AUDIT' ||
    intent === 'OWASP_AUDIT' ||
    intent === 'STRIDE_REVIEW' ||
    intent === 'ARCHITECTURE_GEN'
  );
}

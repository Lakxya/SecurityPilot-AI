from typing import List, Dict
from app.engine.finding import Finding

class ComplianceEngine:
    """
    Compliance Framework Mapping Engine.
    Maps security findings to major enterprise frameworks (OWASP, CIS, NIST, SOC2, ISO27001, MITRE ATT&CK).
    """

    FRAMEWORK_RULES: Dict[str, List[str]] = {
        "mfa": ["OWASP A07", "CIS AWS 1.2", "NIST SP 800-53 IA-2", "SOC2 CC6.1", "ISO27001 A.9.4.2"],
        "iam": ["OWASP A01", "CIS AWS 1.16", "NIST SP 800-53 AC-6", "SOC2 CC6.3", "MITRE T1078"],
        "s3": ["OWASP A01", "CIS AWS 2.1.1", "NIST SP 800-53 SC-28", "SOC2 CC6.6", "ISO27001 A.8.2.3"],
        "encryption": ["OWASP A02", "CIS AWS 2.2.1", "NIST SP 800-53 SC-13", "SOC2 CC6.7", "ISO27001 A.10.1.1"],
        "cloudtrail": ["OWASP A09", "CIS AWS 3.1", "NIST SP 800-53 AU-2", "SOC2 CC7.2", "ISO27001 A.12.4.1"],
        "public": ["OWASP A05", "CIS AWS 1.20", "NIST SP 800-53 AC-4", "SOC2 CC6.6", "MITRE T1190"],
    }

    @classmethod
    def enrich_finding(cls, finding: Finding) -> Finding:
        """Enrich finding with relevant compliance framework tags based on keywords."""
        text = f"{finding.title} {finding.description} {finding.service}".lower()
        enriched_frameworks = set(finding.frameworks)

        for keyword, tags in cls.FRAMEWORK_RULES.items():
            if keyword in text:
                enriched_frameworks.update(tags)

        finding.frameworks = sorted(list(enriched_frameworks))
        return finding

    @classmethod
    def map_findings(cls, findings: List[Finding]) -> List[Finding]:
        """Map and enrich a list of findings."""
        return [cls.enrich_finding(f) for f in findings]

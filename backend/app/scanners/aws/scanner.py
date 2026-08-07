from typing import List, Dict, Any
from app.engine.scanner_base import BaseScanner
from app.engine.finding import Finding
from app.scanners.aws.iam import AWSIAMScanner
from app.scanners.aws.s3 import AWSS3Scanner
from app.scanners.aws.ec2 import AWSEC2Scanner
from app.scanners.aws.cloudtrail import AWSCloudTrailScanner
from app.scanners.aws.kms import AWSKMSScanner

class AWSScanner(BaseScanner):
    """AWS Master Security Scanner."""

    def __init__(self):
        self.sub_scanners: List[BaseScanner] = [
            AWSIAMScanner(),
            AWSS3Scanner(),
            AWSEC2Scanner(),
            AWSCloudTrailScanner(),
            AWSKMSScanner(),
        ]

    async def scan(self) -> List[Finding]:
        findings = []
        for sub in self.sub_scanners:
            sub_findings = await sub.scan()
            findings.extend(sub_findings)
        return findings

    async def health_check(self) -> bool:
        checks = [await sub.health_check() for sub in self.sub_scanners]
        return all(checks)

    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "aws_master_scanner",
            "name": "AWS Cloud Security Suite",
            "provider": "AWS",
            "service": "All AWS Services",
            "version": "1.0.0",
        }

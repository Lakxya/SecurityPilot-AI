from typing import List, Dict, Any
from app.engine.scanner_base import BaseScanner
from app.engine.finding import Finding
from app.engine.severity import Severity

class AWSEC2Scanner(BaseScanner):
    """AWS EC2 Placeholder Security Scanner."""

    async def scan(self) -> List[Finding]:
        return [
            Finding(
                id="AWS-EC2-001",
                provider="AWS",
                service="EC2",
                resource="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f",
                title="Security Group Open Inbound SSH Port 22",
                description="Security group rule allows inbound SSH connections on port 22 from 0.0.0.0/0 unrestricted ingress.",
                severity=Severity.HIGH,
                cvss=7.5,
                recommendation="Restrict SSH access to trusted CIDR blocks or VPN gateway.",
                remediation="aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f --protocol tcp --port 22 --cidr 0.0.0.0/0",
                references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"],
                frameworks=["OWASP A05", "CIS AWS 5.2", "NIST SP 800-53 AC-4", "SOC2 CC6.6"],
            )
        ]

    async def health_check(self) -> bool:
        return True

    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "aws_ec2_scanner",
            "name": "AWS EC2 & Security Group Auditor",
            "provider": "AWS",
            "service": "EC2",
            "version": "1.0.0",
        }

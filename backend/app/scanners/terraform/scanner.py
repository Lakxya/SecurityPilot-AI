from typing import List, Dict, Any
from app.engine.scanner_base import BaseScanner
from app.engine.finding import Finding
from app.engine.severity import Severity

class TerraformScanner(BaseScanner):
    """Terraform IaC HCL Blueprint Security Scanner Placeholder."""

    async def scan(self) -> List[Finding]:
        return [
            Finding(
                id="TF-AWS-001",
                provider="Terraform",
                service="HCL Blueprint",
                resource="main.tf:aws_db_instance.default",
                title="RDS Instance Storage Encrypted Disabled",
                description="Terraform HCL resource aws_db_instance does not set storage_encrypted = true.",
                severity=Severity.HIGH,
                cvss=7.7,
                recommendation="Enable storage encryption for RDS database instances in HCL code.",
                remediation="resource \"aws_db_instance\" \"default\" {\n  storage_encrypted = true\n}",
                references=["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance"],
                frameworks=["CIS AWS 2.3.1", "NIST SP 800-53 SC-28", "SOC2 CC6.6"],
            )
        ]

    async def health_check(self) -> bool:
        return True

    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "terraform_scanner",
            "name": "Terraform IaC Static Auditor",
            "provider": "Terraform",
            "service": "HCL Modules",
            "version": "1.0.0",
        }

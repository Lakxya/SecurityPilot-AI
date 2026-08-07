from app.engine.scanner_registry import scanner_registry
from app.scanners.aws import AWSScanner, AWSIAMScanner, AWSS3Scanner, AWSEC2Scanner, AWSCloudTrailScanner, AWSKMSScanner
from app.scanners.azure import AzureScanner
from app.scanners.gcp import GCPScanner
from app.scanners.docker import DockerScanner
from app.scanners.kubernetes import KubernetesScanner
from app.scanners.terraform import TerraformScanner
from app.scanners.github import GitHubScanner

def init_scanners():
    """Register all available scanners into the global ScannerRegistry singleton."""
    scanner_registry.clear()
    
    # Register Master & Service Scanners
    scanner_registry.register("aws_master", AWSScanner())
    scanner_registry.register("aws_iam", AWSIAMScanner())
    scanner_registry.register("aws_s3", AWSS3Scanner())
    scanner_registry.register("aws_ec2", AWSEC2Scanner())
    scanner_registry.register("aws_cloudtrail", AWSCloudTrailScanner())
    scanner_registry.register("aws_kms", AWSKMSScanner())
    scanner_registry.register("azure_master", AzureScanner())
    scanner_registry.register("gcp_master", GCPScanner())
    scanner_registry.register("docker_master", DockerScanner())
    scanner_registry.register("kubernetes_master", KubernetesScanner())
    scanner_registry.register("terraform_master", TerraformScanner())
    scanner_registry.register("github_master", GitHubScanner())

# Initialize on module import
init_scanners()

__all__ = [
    "AWSScanner",
    "AzureScanner",
    "GCPScanner",
    "DockerScanner",
    "KubernetesScanner",
    "TerraformScanner",
    "GitHubScanner",
    "init_scanners",
]

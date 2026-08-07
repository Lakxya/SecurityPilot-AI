from abc import ABC, abstractmethod
from typing import List, Dict, Any
from app.engine.finding import Finding

class BaseScanner(ABC):
    """
    Abstract Security Scanner Interface.
    All scanners (AWS, Azure, GCP, Docker, K8s, Terraform, GitHub) must implement this interface.
    """

    @abstractmethod
    async def scan(self) -> List[Finding]:
        """Execute security scan and return list of standard findings."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check scanner connectivity and credentials health."""
        pass

    @abstractmethod
    def metadata(self) -> Dict[str, Any]:
        """Return scanner metadata (name, provider, service, version, framework support)."""
        pass

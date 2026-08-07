from typing import Dict, List, Optional
from app.engine.scanner_base import BaseScanner

class ScannerRegistry:
    """
    Dynamic Security Scanner Registry.
    Allows scanners to be registered and queried dynamically by provider/service.
    """

    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {}

    def register(self, key: str, scanner: BaseScanner) -> None:
        """Register a scanner instance with a unique key."""
        self._scanners[key.lower()] = scanner

    def unregister(self, key: str) -> Optional[BaseScanner]:
        """Unregister a scanner instance by key."""
        return self._scanners.pop(key.lower(), None)

    def get(self, key: str) -> Optional[BaseScanner]:
        """Get scanner by key."""
        return self._scanners.get(key.lower())

    def get_by_provider(self, provider: str) -> List[BaseScanner]:
        """Get all scanners matching a cloud or platform provider."""
        provider_lower = provider.lower()
        return [
            scanner for scanner in self._scanners.values()
            if scanner.metadata().get("provider", "").lower() == provider_lower
        ]

    def list_scanners(self) -> List[Dict]:
        """List metadata for all registered scanners."""
        return [scanner.metadata() for scanner in self._scanners.values()]

    def list_providers(self) -> List[str]:
        """List unique providers registered."""
        providers = {scanner.metadata().get("provider") for scanner in self._scanners.values() if scanner.metadata().get("provider")}
        return sorted(list(providers))

    def clear(self) -> None:
        """Clear all registered scanners."""
        self._scanners.clear()

# Global default scanner registry singleton
scanner_registry = ScannerRegistry()

"""Module registry - bundled, trusted modules only (PRD 9.3).

There is no directory scan and no dynamic import of user-supplied files here,
deliberately: importing a Python file executes it, so "drop a plugin in this
folder" is an arbitrary-code-execution feature. Third-party modules will arrive
later behind an explicit install-and-trust step; the architecture below stays
plugin-shaped so that is purely additive.
"""

from __future__ import annotations

from typing import Iterable

from ..modules.osint.ct_subdomains import CtSubdomainsModule
from ..modules.osint.dns_records import DnsRecordsModule
from ..modules.osint.reverse_dns import ReverseDnsModule
from ..modules.osint.tls_cert import TlsCertificateModule
from ..modules.osint.whois_rdap import WhoisRdapModule
from ..modules.web.hints import HintsModule
from ..modules.web.http_headers import HttpHeadersModule
from ..modules.web.published_files import PublishedFilesModule
from ..modules.web.tech_fingerprint import TechFingerprintModule
from .module_base import ModuleBase

#: Instantiated once, in the order the guided recipe walks them.
BUNDLED_MODULES: tuple[ModuleBase, ...] = (
    WhoisRdapModule(),
    DnsRecordsModule(),
    ReverseDnsModule(),
    CtSubdomainsModule(),
    TlsCertificateModule(),
    HttpHeadersModule(),
    TechFingerprintModule(),
    PublishedFilesModule(),
    HintsModule(),
)

#: The order the guided ``rhp recon`` recipe runs modules in (PRD 10).
RECIPE_ORDER: tuple[str, ...] = (
    "whois",
    "dns",
    "revdns",
    "subdomains",
    "cert",
    "headers",
    "fingerprint",
    "published-files",
    "hints",
)


class Registry:
    """Lookup for the bundled modules."""

    def __init__(self, modules: Iterable[ModuleBase] | None = None) -> None:
        self._modules: dict[str, ModuleBase] = {}
        for module in modules if modules is not None else BUNDLED_MODULES:
            self._modules[module.id] = module

    def all(self) -> list[ModuleBase]:
        return list(self._modules.values())

    def ids(self) -> list[str]:
        return list(self._modules)

    def get(self, module_id: str) -> ModuleBase | None:
        return self._modules.get(module_id)

    def require(self, module_id: str) -> ModuleBase:
        module = self.get(module_id)
        if module is None:
            available = ", ".join(sorted(self._modules))
            raise KeyError(f"No module called {module_id!r}. Available modules: {available}.")
        return module

    def recipe(self) -> list[ModuleBase]:
        return [self._modules[name] for name in RECIPE_ORDER if name in self._modules]


def default_registry() -> Registry:
    return Registry()

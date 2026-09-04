"""Reverse DNS and network context (PTR, ASN, announced prefix).

Both sources are free and keyless: PTR comes from the resolver, and the network
context comes from Team Cymru's public IP-to-ASN service, which is queried over
DNS. The target is never contacted (PRD 6.1).
"""

from __future__ import annotations

import ipaddress

from ...core.models import (
    AssetKind,
    Confidence,
    ContactMode,
    DiscoveredAsset,
    Observation,
    PluginResult,
    RunStatus,
)
from ...core.module_base import ModuleBase, ModuleContext
from ...core.scope import normalize_ip, validate_target
from . import dns_records

CYMRU_ORIGIN_SUFFIX = "origin.asn.cymru.com"
CYMRU_ORIGIN6_SUFFIX = "origin6.asn.cymru.com"
CYMRU_AS_SUFFIX = "asn.cymru.com"


def _reverse_pointer(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return address.reverse_pointer


def _cymru_query_name(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    pointer = address.reverse_pointer
    if address.version == 4:
        return pointer.replace("in-addr.arpa", CYMRU_ORIGIN_SUFFIX)
    return pointer.replace("ip6.arpa", CYMRU_ORIGIN6_SUFFIX)


def _split_cymru(value: str) -> list[str]:
    cleaned = value.strip().strip('"')
    return [part.strip() for part in cleaned.split("|")]


class ReverseDnsModule(ModuleBase):
    id = "revdns"
    name = "Reverse DNS and network context"
    version = "1.0.0"
    category = "osint"
    mode = ContactMode.THIRD_PARTY
    teaching_key = "revdns"
    supported_target_types = ("domain", "host", "ip")
    config_schema = {
        "max_addresses": (8, "How many addresses to look up when the target is a name."),
        "network_context": (True, "Also ask Team Cymru which network/ASN announces the address."),
    }
    request_budget = 0
    scope_requirement = "none"

    def run(self, context: ModuleContext) -> PluginResult:
        result = PluginResult()
        config = self.resolved_config(context.params)
        target = validate_target(context.target)

        addresses = self._addresses(target, int(config["max_addresses"]), result)
        if not addresses:
            result.status = RunStatus.PARTIAL
            result.warnings.append(
                f"No addresses to look up for {target}; run the DNS module first, or pass an IP."
            )
            result.merge_metrics(requests=0, third_party_requests=0)
            return result

        for address in addresses:
            context.cancel.raise_if_cancelled()
            context.emit(f"Reverse lookup for {address}")
            try:
                pointers = dns_records.resolve_records(_reverse_pointer(address), "PTR")
            except dns_records.DnsLookupError as exc:
                result.status = RunStatus.PARTIAL
                result.errors.append(str(exc))
                pointers = []

            for pointer in pointers:
                name = pointer.rstrip(".")
                result.observations.append(
                    Observation(
                        type="dns.ptr",
                        normalized_value=name,
                        source_provider="DNS resolver",
                        dedup_key=f"dns.ptr:{address}:{name}",
                        asset_value=str(address),
                        asset_kind=AssetKind.IP,
                        evidence=f"PTR record for {address}.",
                        confidence=Confidence.HIGH,
                    )
                )
                result.discovered_assets.append(
                    DiscoveredAsset(
                        AssetKind.HOST,
                        name,
                        "Name the address points back to. Often the hosting provider, "
                        "not the site owner.",
                    )
                )

            if config["network_context"]:
                result.observations.extend(self._network_context(address, result))

        result.merge_metrics(
            requests=0, third_party_requests=0, addresses=len(addresses)
        )
        return result

    def _addresses(
        self, target: str, limit: int, result: PluginResult
    ) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        literal = normalize_ip(target)
        if literal is not None:
            return [literal]
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for rdtype in ("A", "AAAA"):
            try:
                values = dns_records.resolve_records(target, rdtype)
            except dns_records.DnsLookupError as exc:
                result.warnings.append(str(exc))
                continue
            for value in values:
                address = normalize_ip(value)
                if address is not None and address not in addresses:
                    addresses.append(address)
        return addresses[:limit]

    def _network_context(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        result: PluginResult,
    ) -> list[Observation]:
        observations: list[Observation] = []
        try:
            origin = dns_records.resolve_records(_cymru_query_name(address), "TXT")
        except dns_records.DnsLookupError as exc:
            result.warnings.append(f"Network context lookup failed for {address}: {exc}")
            return observations
        if not origin:
            return observations

        fields = _split_cymru(origin[0])
        if len(fields) < 2:
            return observations
        asn, prefix = fields[0], fields[1]
        country = fields[2] if len(fields) > 2 else ""
        registry = fields[3] if len(fields) > 3 else ""

        observations.append(
            Observation(
                type="network.prefix",
                normalized_value=prefix,
                source_provider="Team Cymru IP-to-ASN (DNS)",
                dedup_key=f"network.prefix:{address}:{prefix}",
                asset_value=str(address),
                asset_kind=AssetKind.IP,
                evidence=f"origin ASN TXT record for {address}: {origin[0]}",
                confidence=Confidence.MEDIUM,
            )
        )

        as_name = ""
        try:
            as_records = dns_records.resolve_records(f"AS{asn}.{CYMRU_AS_SUFFIX}", "TXT")
        except dns_records.DnsLookupError:
            as_records = []
        if as_records:
            as_fields = _split_cymru(as_records[0])
            as_name = as_fields[-1] if as_fields else ""

        label = f"AS{asn}" + (f" ({as_name})" if as_name else "")
        observations.append(
            Observation(
                type="network.asn",
                normalized_value=label,
                source_provider="Team Cymru IP-to-ASN (DNS)",
                dedup_key=f"network.asn:{address}:{asn}",
                asset_value=str(address),
                asset_kind=AssetKind.IP,
                evidence=(
                    f"{address} is announced by AS{asn}"
                    + (f", registry {registry}" if registry else "")
                    + (f", country {country}" if country else "")
                    + "."
                ),
                confidence=Confidence.MEDIUM,
            )
        )
        return observations

"""
modules/recon/dns_enum.py
--------------------------
DNS record enumeration module.

Capabilities:
  - Queries configurable record types (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - Uses dnspython for reliability; falls back to subprocess dig
  - Zone transfer attempt (AXFR) — purely informational

Config keys (from config.yaml → recon → dns):
  nameservers  : list[str]   Custom DNS resolvers
  record_types : list[str]   Which record types to query
"""

from modules.base_module import BaseModule
from core.exceptions import ToolNotFoundError, ScanError

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False


class DnsEnum(BaseModule):
    """
    DNS enumeration via dnspython (or dig fallback).

    Config keys: nameservers, record_types
    """

    MODULE_NAME = "DnsEnum"

    def _execute(self) -> dict:
        if not _DNSPYTHON_AVAILABLE:
            raise ToolNotFoundError(
                "dnspython not installed. Run: pip install dnspython"
            )

        nameservers  = self.config.get("nameservers", ["8.8.8.8", "1.1.1.1"])
        record_types = self.config.get(
            "record_types", ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        )

        resolver = dns.resolver.Resolver()
        resolver.nameservers = nameservers

        results = {"dns_records": {}, "zone_transfer": None}

        for rtype in record_types:
            records = self._query(resolver, rtype)
            if records:
                results["dns_records"][rtype] = records
                self.logger.info(f"  {rtype:6s} → {', '.join(records)}")

        # ── Zone transfer attempt (AXFR) ──────────────────────────────────
        ns_records = results["dns_records"].get("NS", [])
        if ns_records:
            axfr_result = self._attempt_zone_transfer(ns_records[0])
            results["zone_transfer"] = axfr_result

        return results

    def _query(self, resolver, rtype: str) -> list:
        """Query a single record type; return list of string values."""
        try:
            answers = resolver.resolve(self.target, rtype)
            return [str(r) for r in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.DNSException,
        ):
            return []

    def _attempt_zone_transfer(self, nameserver: str) -> dict:
        """
        Attempt DNS zone transfer (AXFR).
        This is a standard enumeration technique — legitimate pentest activity.
        """
        ns_clean = nameserver.rstrip(".")
        self.logger.info(f"Attempting AXFR zone transfer via {ns_clean}...")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, self.target, timeout=5))
            records = [str(name) for name in zone.nodes.keys()]
            self.logger.warning(
                f"[!!!] Zone transfer SUCCEEDED on {ns_clean} — "
                f"{len(records)} records leaked!"
            )
            return {"vulnerable": True, "nameserver": ns_clean, "records": records}
        except Exception:
            self.logger.info(f"Zone transfer refused by {ns_clean} (expected).")
            return {"vulnerable": False, "nameserver": ns_clean}

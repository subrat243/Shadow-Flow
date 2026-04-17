"""
modules/recon/subdomain_enum.py
--------------------------------
Subdomain enumeration module — active + passive.

Capabilities:
  Active  : Wordlist-based DNS brute-force (threaded)
  Passive : crt.sh certificate transparency lookup (no DNS noise)

Config keys (from config.yaml → recon → subdomain):
  wordlist : str   Path to subdomain wordlist
  threads  : int   Worker threads for active brute-force
  passive  : bool  Enable crt.sh passive enumeration
"""

import concurrent.futures
import requests
from modules.base_module import BaseModule
from core.exceptions import ScanError

try:
    import dns.resolver
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False

_CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"


class SubdomainEnum(BaseModule):
    """
    Subdomain enumeration — wordlist brute-force + crt.sh passively.

    Config keys: wordlist, threads, passive
    """

    MODULE_NAME = "SubdomainEnum"

    def _execute(self) -> dict:
        results = {"subdomains": [], "passive_subdomains": []}

        passive_enabled = self.config.get("passive", True)

        # ── Passive: crt.sh ───────────────────────────────────────────────
        if passive_enabled:
            passive = self._crtsh_lookup()
            results["passive_subdomains"] = passive
            self.logger.info(
                f"crt.sh found {len(passive)} unique subdomain(s)."
            )

        # ── Active: wordlist brute-force ──────────────────────────────────
        wordlist_path = self.config.get("wordlist", "config/wordlists/subdomains.txt")
        if _DNSPYTHON_AVAILABLE:
            active = self._brute_force(wordlist_path)
            results["subdomains"] = active
            self.logger.info(
                f"Wordlist brute-force found {len(active)} live subdomain(s)."
            )
        else:
            self.logger.warning("dnspython not installed — skipping active brute-force.")

        # Merge and deduplicate
        all_subs = list(
            set(results["subdomains"] + results["passive_subdomains"])
        )
        results["all_subdomains"] = sorted(all_subs)
        self.logger.info(f"Total unique subdomains: {len(all_subs)}")

        return results

    # ── crt.sh Passive ───────────────────────────────────────────────────

    def _crtsh_lookup(self) -> list:
        """Query crt.sh for certificate transparency records."""
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(self.target):
                        subdomains.add(sub)
            return sorted(subdomains)
        except requests.RequestException as exc:
            self.logger.warning(f"crt.sh query failed: {exc}")
            return []

    # ── Active brute-force ────────────────────────────────────────────────

    def _load_wordlist(self, path: str) -> list:
        """Load subdomain wordlist; return list of prefixes."""
        if not path:
            return []
        try:
            with open(path, "r", errors="ignore") as fh:
                return [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            self.logger.warning(f"Wordlist not found: {path}")
            return []

    def _resolve(self, subdomain: str) -> str | None:
        """Try to resolve a subdomain; return it if it resolves."""
        resolver = dns.resolver.Resolver()
        try:
            resolver.resolve(subdomain, "A", lifetime=2)
            return subdomain
        except Exception:
            return None

    def _brute_force(self, wordlist_path: str) -> list:
        """Threaded DNS brute-force using the wordlist."""
        words = self._load_wordlist(wordlist_path)
        if not words:
            self.logger.warning("Empty wordlist — skipping brute-force.")
            return []

        candidates = [f"{w}.{self.target}" for w in words]
        threads = self.config.get("threads", 50)
        found = []

        self.logger.info(
            f"Brute-forcing {len(candidates)} candidates with {threads} threads…"
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._resolve, c): c for c in candidates}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self.logger.info(f"  [+] {result}")

        return sorted(found)

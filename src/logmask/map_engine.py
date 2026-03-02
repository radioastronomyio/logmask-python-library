"""
Map engine for CSV translation map management.

This module handles loading, merging, writing, and fake value generation
for the global and project translation maps.

# [Agent context: This is the single source of truth for fake value generation.
# Parsers must NOT generate fake values — only detect identifiers. All generation
# routes through generate_fake_value() which dispatches by identifier_type.
# Key invariant: MapEntry.__post_init__ enforces original_value != anonymized_value.
# The collision-check logic in _generate_fake_ipv4 has known bugs — see BUG
# comments inline. DOMAIN_NAMES list is used for UPN domain generation but FQDN
# hostname generation leaks the real domain suffix — see BUG in _generate_fake_hostname.]
"""

import random
import uuid
from pathlib import Path
from typing import Literal

import pandas as pd

from logmask.models import Config, MapEntry


# Word list for hostname generation
HOSTNAME_WORDS = [
    "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF", "HOTEL",
    "INDIA", "JULIET", "KILO", "LIMA", "MIKE", "NOVEMBER", "OSCAR", "PAPA",
    "QUEBEC", "ROMEO", "SIERRA", "TANGO", "UNIFORM", "VICTOR", "WHISKEY",
    "XRAY", "YANKEE", "ZULU", "APOLLO", "ATHENA", "ATLAS", "AURORA", "BOLT",
    "COMET", "CORONA", "COSMOS", "CYGNUS", "DRACO", "ECLIPSE", "FLARE",
    "GALAXY", "GEMINI", "HALO", "ION", "JUPITER", "LUNA", "MARS", "MERCURY",
    "METEOR", "NEBULA", "NEPTUNE", "NOVA", "ORBIT", "PHOENIX", "PLUTO",
    "PULSAR", "QUASAR", "SATURN", "SOLAR", "STAR", "TITAN", "URANUS", "VENUS",
    "VOID", "ZENITH", "ZERO", "AZURE", "CRIMSON", "EMERALD", "GOLDEN",
    "INDIGO", "JADE", "LAVENDER", "MAGENTA", "OBSIDIAN", "PLATINUM", "RUBY",
    "SAPPHIRE", "TOPAZ", "VIOLET", "ZIRCON",
]

# Word list for UPN local-part generation
USER_NAMES = [
    "user001", "user002", "user003", "user004", "user005", "user006", "user007",
    "user008", "user009", "user010", "admin01", "admin02", "admin03", "svc01",
    "svc02", "svc03", "test01", "test02", "dev01", "dev02", "ops01", "ops02",
    "ops03", "db01", "db02", "db03", "web01", "web02", "web03", "app01", "app02",
    "api01", "api02", "bot01", "bot02", "bot03", "sys01", "sys02", "sys03",
    "net01", "net02", "sec01", "sec02", "mon01", "mon02", "log01", "log02",
]

# Word list for domain generation
DOMAIN_NAMES = [
    "contoso.local", "fabrikam.local", "woodgrove.local", "adatum.local",
    "fabrikam.com", "contoso.com", "lucernepublishing.com", "northwindtraders.com",
    "tailspintoys.com", "wingtiptoys.com", "proseware.com", "wide-world-importers.com",
]


class MapEngine:
    """
    Engine for managing translation maps and generating fake values.
    """

    def __init__(self, config: Config) -> None:
        """
        Initialize the map engine with configuration.

        Args:
            config: Runtime configuration including map paths.
        """
        self.config = config

    def load_global_map(self) -> dict[str, MapEntry]:
        """
        Load the global translation map from CSV.

        Returns:
            Dictionary mapping original values to MapEntry objects.
        """
        return self._load_map_from_csv(self.config.global_map_path)

    def load_project_map(self) -> dict[str, MapEntry]:
        """
        Load the project translation map from CSV.

        Returns:
            Dictionary mapping original values to MapEntry objects.
        """
        return self._load_map_from_csv(self.config.project_map_path)

    def _load_map_from_csv(self, path: Path) -> dict[str, MapEntry]:
        """
        Load a map from a CSV file.

        Args:
            path: Path to the CSV file.

        Returns:
            Dictionary mapping original values to MapEntry objects.
        """
        if not path.exists():
            return {}

        try:
            df = pd.read_csv(path, dtype=str)
            result = {}
            for _, row in df.iterrows():
                row_dict = row.to_dict()
                # Strip whitespace from string values
                for key in row_dict:
                    if isinstance(row_dict[key], str):
                        row_dict[key] = row_dict[key].strip()
                entry = MapEntry.from_csv_row(row_dict)
                result[entry.original_value] = entry
            return result
        except Exception as e:
            # If file exists but is invalid, return empty dict
            print(f"Error loading CSV from {path}: {e}")
            return {}

    def merge_maps(self) -> dict[str, MapEntry]:
        """
        Merge global and project maps with project taking precedence.

        Returns:
            Merged dictionary where project entries override global entries
            on original_value key collision.
        """
        global_map = self.load_global_map()
        project_map = self.load_project_map()

        # Start with global map
        merged = global_map.copy()

        # Project map overrides global map
        merged.update(project_map)

        return merged

    def write_project_map(self, entries: list[MapEntry]) -> None:
        """
        Write entries to the project map CSV file.

        Args:
            entries: List of MapEntry objects to write.
        """
        # Ensure directory exists
        self.config.project_map_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert entries to rows
        rows = [entry.to_csv_row() for entry in entries]

        # Write to CSV
        df = pd.DataFrame(rows)
        df.to_csv(self.config.project_map_path, index=False)

    def generate_fake_value(
        self,
        identifier_type: str,
        original_value: str,
        preserve_format: bool = True,
        scope: Literal["global", "project"] = "project",
    ) -> str:
        """
        Generate a fake value for the given identifier type.

        Args:
            identifier_type: The type of identifier (ipv4, cidr, hostname, etc.).
            original_value: The original value to base generation on.
            preserve_format: Whether to apply structural rules during generation.
            scope: The scope for the generated value (global or project).

        Returns:
            A generated fake value.
        """
        # TODO: `scope` parameter is accepted but never used in any generation
        # method. Either thread it through to generation logic or remove it from
        # the signature (callers pass it but it has no effect).
        if identifier_type == "ipv4":
            return self._generate_fake_ipv4(original_value, preserve_format)
        elif identifier_type == "cidr":
            return self._generate_fake_cidr(original_value, preserve_format)
        elif identifier_type == "hostname":
            return self._generate_fake_hostname(original_value, preserve_format)
        elif identifier_type == "upn":
            return self._generate_fake_upn(original_value, preserve_format)
        elif identifier_type == "guid":
            return self._generate_fake_guid(original_value, preserve_format)
        elif identifier_type == "sid":
            return self._generate_fake_sid(original_value, preserve_format)
        elif identifier_type == "mac":
            return self._generate_fake_mac(original_value, preserve_format)
        elif identifier_type == "unc":
            return self._generate_fake_unc(original_value, preserve_format)
        else:
            raise ValueError(f"Unknown identifier type: {identifier_type}")

    def _generate_fake_ipv4(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake IPv4 address.

        Preserves first two octets (A+B) and randomizes C+D (1-254).
        Checks for collision with existing map entries.

        Args:
            original: Original IPv4 address.
            preserve_format: Whether to preserve first two octets.

        Returns:
            Fake IPv4 address.
        """
        if not preserve_format:
            # Generate completely random RFC1918 address
            classes = [
                ("10", random.randint(0, 255), random.randint(1, 254), random.randint(1, 254)),
                ("192", "168", random.randint(0, 255), random.randint(1, 254)),
                ("172", random.choice([str(i) for i in range(16, 32)]), random.randint(0, 255), random.randint(1, 254)),
            ]
            octets = random.choice(classes)
            return ".".join(str(o) for o in octets)

        # Parse original IP
        octets = original.split(".")
        if len(octets) != 4:
            raise ValueError(f"Invalid IPv4 address: {original}")

        # Preserve first two octets, randomize last two
        fake_octets = octets[:2] + [str(random.randint(1, 254)), str(random.randint(1, 254))]
        fake_ip = ".".join(fake_octets)

        # BUG: Collision check compares `fake_ip` against `merged_map` keys, which are
        # *original* values — not anonymized values. To detect collisions, it should check
        # against the set of existing *anonymized* values. Also, the condition `fake_ip != original`
        # allows the loop to exit when fake equals original, but MapEntry.__post_init__
        # raises ValueError when original_value == anonymized_value.
        # HACK: merge_maps() reads CSV from disk on every call. When generating multiple
        # IPs, this causes redundant disk I/O. Cache the merged map or pass it in.
        merged_map = self.merge_maps()
        max_attempts = 100
        attempts = 0

        while fake_ip in merged_map and fake_ip != original and attempts < max_attempts:
            fake_octets = octets[:2] + [str(random.randint(1, 254)), str(random.randint(1, 254))]
            fake_ip = ".".join(fake_octets)
            attempts += 1

        return fake_ip

    def _generate_fake_cidr(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake CIDR notation.

        Anonymizes IP portion using IPv4 rules, preserves /prefix.

        Args:
            original: Original CIDR notation.
            preserve_format: Whether to preserve IP class.

        Returns:
            Fake CIDR notation.
        """
        # Split IP and prefix
        parts = original.split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid CIDR notation: {original}")

        ip_part, prefix = parts
        fake_ip = self._generate_fake_ipv4(ip_part, preserve_format)
        return f"{fake_ip}/{prefix}"

    def _generate_fake_hostname(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake hostname.

        Generates from pattern SRV-{WORD}-{NN}. Matches flat vs FQDN structure.

        Args:
            original: Original hostname.
            preserve_format: Whether to preserve structure (flat vs FQDN).

        Returns:
            Fake hostname.
        """
        if not preserve_format:
            # Generate simple random hostname
            word = random.choice(HOSTNAME_WORDS)
            num = random.randint(1, 99)
            return f"SRV-{word}-{num:02d}"

        # Check if it's an FQDN (contains dots)
        if "." in original:
            # BUG: Domain suffix leakage — only the first label is anonymized, but
            # the real domain suffix (e.g., "contoso.local") is passed through unchanged.
            # This leaks the real domain name into anonymized output.
            # Fix: anonymize the domain suffix too (e.g., replace with a fake domain
            # from DOMAIN_NAMES, or generate a deterministic fake suffix).
            parts = original.split(".")
            # Generate fake for first part
            word = random.choice(HOSTNAME_WORDS)
            num = random.randint(1, 99)
            fake_parts = [f"SRV-{word}-{num:02d}"] + parts[1:]
            return ".".join(fake_parts)
        else:
            # Flat hostname
            word = random.choice(HOSTNAME_WORDS)
            num = random.randint(1, 99)
            return f"SRV-{word}-{num:02d}"

    def _generate_fake_upn(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake UPN (User Principal Name).

        Anonymizes local-part with random name. Anonymizes domain via hostname rules.

        Args:
            original: Original UPN.
            preserve_format: Whether to preserve domain structure.

        Returns:
            Fake UPN.
        """
        # Split local-part and domain
        parts = original.split("@")
        if len(parts) != 2:
            raise ValueError(f"Invalid UPN: {original}")

        local_part, domain = parts

        # Generate fake local-part
        fake_local = random.choice(USER_NAMES)

        # Generate fake domain
        if preserve_format and "." in domain:
            # Preserve FQDN structure
            domain_parts = domain.split(".")
            fake_domain = f"fabrikam.{domain_parts[1]}" if len(domain_parts) > 1 else "fabrikam.com"
        else:
            fake_domain = random.choice(DOMAIN_NAMES)

        return f"{fake_local}@{fake_domain}"

    def _generate_fake_guid(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake GUID.

        Uses uuid.uuid5(NAMESPACE_URL, original) for deterministic generation.

        Args:
            original: Original GUID.
            preserve_format: Not used (always deterministic).

        Returns:
            Fake GUID.
        """
        # Use uuid5 with NAMESPACE_URL for deterministic generation
        fake_guid = uuid.uuid5(uuid.NAMESPACE_URL, original)
        return str(fake_guid)

    def _generate_fake_sid(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake SID (Security Identifier).

        Preserves S-1-5-21 prefix. Randomizes sub-authorities (same count).

        Args:
            original: Original SID.
            preserve_format: Whether to preserve prefix structure.

        Returns:
            Fake SID.
        """
        # Parse SID
        parts = original.split("-")
        if len(parts) < 4 or not original.startswith("S-1-5-21-"):
            raise ValueError(f"Invalid SID: {original}")

        # Preserve S-1-5-21- prefix
        prefix = "S-1-5-21-"

        # Count sub-authorities after prefix
        sub_authorities = parts[4:]  # Everything after S-1-5-21-

        # Generate random sub-authorities with same count
        fake_sub_auths = [str(random.randint(1000000000, 4294967295)) for _ in sub_authorities]

        return prefix + "-".join(fake_sub_auths)

    def _generate_fake_mac(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake MAC address.

        Preserves first 3 octets (OUI). Randomizes last 3. Preserves delimiter style.

        Args:
            original: Original MAC address.
            preserve_format: Whether to preserve OUI.

        Returns:
            Fake MAC address.
        """
        # Detect delimiter style
        if ":" in original:
            delimiter = ":"
        elif "-" in original:
            delimiter = "-"
        else:
            delimiter = ":"

        # Parse octets
        octets = original.replace("-", ":").split(":")
        if len(octets) != 6:
            raise ValueError(f"Invalid MAC address: {original}")

        if preserve_format:
            # Preserve first 3 octets (OUI) with their original case
            # For colon delimiter, convert to lowercase (standard convention)
            # For dash delimiter, preserve original case
            if delimiter == ":":
                preserved_oui = [oct.lower() for oct in octets[:3]]
            else:
                preserved_oui = octets[:3]
            # Randomize last 3 octets
            fake_octets = preserved_oui + [
                f"{random.randint(0, 255):02x}",
                f"{random.randint(0, 255):02x}",
                f"{random.randint(0, 255):02x}",
            ]
        else:
            # Generate completely random MAC
            fake_octets = [f"{random.randint(0, 255):02x}" for _ in range(6)]

        return delimiter.join(fake_octets)

    def _generate_fake_unc(self, original: str, preserve_format: bool) -> str:
        """
        Generate a fake UNC path.

        Decomposes, anonymizes server+share via hostname rules, reassembles.

        Args:
            original: Original UNC path.
            preserve_format: Whether to preserve path structure.

        Returns:
            Fake UNC path.
        """
        # Parse UNC path: \\server\share\path...
        if not original.startswith("\\\\"):
            raise ValueError(f"Invalid UNC path: {original}")

        # Remove leading \\ and split
        parts = original[2:].split("\\")

        if len(parts) < 2:
            raise ValueError(f"Invalid UNC path: {original}")

        server = parts[0]
        share = parts[1] if len(parts) > 1 else ""

        # Generate fake server name
        fake_server = self._generate_fake_hostname(server, preserve_format)

        # Generate fake share name (preserve structure if possible)
        if preserve_format and share:
            # Share names often end with $ for hidden shares
            if share.endswith("$"):
                fake_share = f"Share{random.randint(1, 99)}$"
            else:
                fake_share = f"Share{random.randint(1, 99)}"
        else:
            fake_share = share if share else ""

        # Reassemble UNC path
        fake_parts = [fake_server, fake_share] + parts[2:]
        return "\\\\" + "\\".join(fake_parts)

    def add_entry(self, entry: MapEntry) -> None:
        """
        Add a single entry to the project map.

        Args:
            entry: The MapEntry to add.
        """
        # Load existing project map
        project_map = self.load_project_map()

        # Add or update entry
        project_map[entry.original_value] = entry

        # Write back to CSV
        self.write_project_map(list(project_map.values()))

    def show_map(self, scope: Literal["global", "project", "merged"] = "merged") -> list[MapEntry]:
        """
        Get map entries for display.

        Args:
            scope: Which map to retrieve (global, project, or merged).

        Returns:
            List of MapEntry objects from the specified scope.
        """
        if scope == "global":
            return list(self.load_global_map().values())
        elif scope == "project":
            return list(self.load_project_map().values())
        elif scope == "merged":
            return list(self.merge_maps().values())
        else:
            raise ValueError(f"Invalid scope: {scope}")


def load_merged_map(config: Config) -> dict[str, str]:
    """
    Convenience function to load merged map as simple dictionary.

    Args:
        config: Runtime configuration.

    Returns:
        Dictionary mapping original values to anonymized values.
    """
    engine = MapEngine(config)
    merged = engine.merge_maps()
    return {original: entry.anonymized_value for original, entry in merged.items()}

"""
Parser registry for infrastructure identifier detection.

This module maintains the registry of all parsers that can detect
infrastructure identifiers in text. Each parser is a callable that
takes text and config and returns a list of DetectedIdentifier objects.
"""

from typing import Callable

from logmask.models import Config, DetectedIdentifier

# Import parser functions (will be implemented in Phase 3)
from logmask.parsers import cidr, hostname, identity, ipv4, network

# Parser function signature
ParserFunction = Callable[[str, Config], list[DetectedIdentifier]]

# Registry of all available parsers
PARSER_REGISTRY: dict[str, ParserFunction] = {
    "ipv4": ipv4.parse,
    "cidr": cidr.parse,
    "hostname": hostname.parse,
    "identity": identity.parse,
    "network": network.parse,
}


def get_parser(name: str) -> ParserFunction:
    """
    Get a parser by name.
    
    Args:
        name: The name of the parser (e.g., "ipv4", "hostname").
        
    Returns:
        The parser function.
        
    Raises:
        KeyError: If the parser name is not registered.
    """
    if name not in PARSER_REGISTRY:
        raise KeyError(f"Unknown parser: {name}. Available parsers: {list(PARSER_REGISTRY.keys())}")
    return PARSER_REGISTRY[name]


def list_parsers() -> list[str]:
    """
    Get a list of all registered parser names.
    
    Returns:
        List of parser names.
    """
    return list(PARSER_REGISTRY.keys())


def run_all_parsers(text: str, config: Config) -> list[DetectedIdentifier]:
    """
    Run all registered parsers against the given text.
    
    Args:
        text: The text to parse.
        config: Runtime configuration.
        
    Returns:
        Combined list of detected identifiers from all parsers.
    """
    all_identifiers: list[DetectedIdentifier] = []
    for parser_name, parser_func in PARSER_REGISTRY.items():
        try:
            identifiers = parser_func(text, config)
            all_identifiers.extend(identifiers)
        except Exception as e:
            # Log error but continue with other parsers
            print(f"Warning: Parser {parser_name} failed: {e}")
    return all_identifiers

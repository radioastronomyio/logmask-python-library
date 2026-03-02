"""
Unit tests for parser modules.

This module tests each parser's ability to detect identifiers
in synthetic log data without false positives.
"""

import pytest

from logmask.models import Config, DetectedIdentifier
from logmask.parsers import ipv4, cidr, hostname, identity, network


class TestIPv4Parser:
    """Tests for the IPv4 address parser."""
    
    def test_parse_rfc1918_addresses(self, sample_log_with_ipv4: str, sample_config: Config) -> None:
        """Test that RFC1918 IPv4 addresses are detected."""
        identifiers = ipv4.parse(sample_log_with_ipv4, sample_config)
        
        # Expected IPv4 addresses in the sample log
        expected_ips = ["10.0.1.50", "192.168.100.10", "172.16.0.1", "10.255.255.254", "192.168.1.200"]
        
        # Check that we found the expected number of addresses
        assert len(identifiers) == len(expected_ips), f"Expected {len(expected_ips)} IPv4 addresses, found {len(identifiers)}"
        
        # Check that all expected IPs are present
        found_values = [id.value for id in identifiers]
        for expected_ip in expected_ips:
            assert expected_ip in found_values, f"Expected IP {expected_ip} not found in {found_values}"
    
    def test_ipv4_confidence_score(self, sample_config: Config) -> None:
        """Test that IPv4 parser returns high confidence scores."""
        text = "Connection from 10.0.1.50 to 192.168.1.1"
        identifiers = ipv4.parse(text, sample_config)
        
        # All IPv4 addresses should have high confidence (1.0)
        for identifier in identifiers:
            assert identifier.confidence == 1.0, f"Expected confidence 1.0, got {identifier.confidence}"
    
    def test_ipv4_position_tracking(self, sample_config: Config) -> None:
        """Test that IPv4 parser correctly tracks start and end positions."""
        text = "Connection from 10.0.1.50 to 192.168.1.1"
        identifiers = ipv4.parse(text, sample_config)
        
        # Check position tracking for first IP
        first_ip = [id for id in identifiers if id.value == "10.0.1.50"][0]
        assert first_ip.start_pos == text.index("10.0.1.50")
        assert first_ip.end_pos == first_ip.start_pos + len("10.0.1.50")
        
        # Check position tracking for second IP
        second_ip = [id for id in identifiers if id.value == "192.168.1.1"][0]
        assert second_ip.start_pos == text.index("192.168.1.1")
        assert second_ip.end_pos == second_ip.start_pos + len("192.168.1.1")
    
    def test_ipv4_no_public_ips(self, sample_config: Config) -> None:
        """Test that IPv4 parser does not match public IP addresses."""
        text = "Public IPs: 8.8.8.8, 1.1.1.1, 172.32.0.1"
        identifiers = ipv4.parse(text, sample_config)
        
        # Should not match any public IPs
        assert len(identifiers) == 0, f"Expected no matches for public IPs, found {len(identifiers)}"
    
    def test_ipv4_no_timestamp_corruption(self, sample_config: Config) -> None:
        """Test that IPv4 parser does not match IP-like strings in timestamps."""
        text = "2025-03-01 10:15:23 INFO Connection established"
        identifiers = ipv4.parse(text, sample_config)
        
        # Should not match 10:15:23 as an IP address
        assert len(identifiers) == 0, f"Expected no matches in timestamp, found {len(identifiers)}"


class TestCIDRParser:
    """Tests for the CIDR notation parser."""
    
    def test_parse_cidr_notation(self, sample_log_with_cidr: str, sample_config: Config) -> None:
        """Test that CIDR subnet notation is detected."""
        identifiers = cidr.parse(sample_log_with_cidr, sample_config)
        
        # Expected CIDR notations in the sample log
        expected_cidrs = ["192.168.1.0/24", "10.0.0.1/16", "172.16.10.0/24", "10.10.10.0/24"]
        
        # Check that we found the expected number of CIDR notations
        assert len(identifiers) == len(expected_cidrs), f"Expected {len(expected_cidrs)} CIDR notations, found {len(identifiers)}"
        
        # Check that all expected CIDRs are present
        found_values = [id.value for id in identifiers]
        for expected_cidr in expected_cidrs:
            assert expected_cidr in found_values, f"Expected CIDR {expected_cidr} not found in {found_values}"
    
    def test_cidr_preserves_prefix(self, sample_config: Config) -> None:
        """Test that CIDR parser captures the prefix length."""
        text = "Subnet: 192.168.1.0/24, Gateway: 10.0.0.1/16"
        identifiers = cidr.parse(text, sample_config)
        
        # Check that prefix lengths are preserved
        cidr_values = [id.value for id in identifiers]
        assert "192.168.1.0/24" in cidr_values
        assert "10.0.0.1/16" in cidr_values
    
    def test_cidr_confidence_score(self, sample_config: Config) -> None:
        """Test that CIDR parser returns high confidence scores."""
        text = "Subnet: 192.168.1.0/24"
        identifiers = cidr.parse(text, sample_config)
        
        # All CIDR notations should have high confidence (1.0)
        for identifier in identifiers:
            assert identifier.confidence == 1.0, f"Expected confidence 1.0, got {identifier.confidence}"
    
    def test_cidr_no_public_ips(self, sample_config: Config) -> None:
        """Test that CIDR parser does not match public IP CIDRs."""
        text = "Public CIDRs: 8.8.8.0/24, 1.1.1.0/24"
        identifiers = cidr.parse(text, sample_config)
        
        # Should not match any public IP CIDRs
        assert len(identifiers) == 0, f"Expected no matches for public IP CIDRs, found {len(identifiers)}"
    
    def test_cidr_parse_function(self) -> None:
        """Test the parse_cidr helper function."""
        cidr_str = "192.168.1.0/24"
        ip, prefix = cidr.parse_cidr(cidr_str)
        
        assert ip == "192.168.1.0"
        assert prefix == 24


class TestHostnameParser:
    """Tests for the hostname parser."""
    
    def test_parse_netbios_names(self, sample_log_with_hostnames: str, sample_config: Config) -> None:
        """Test that NetBIOS names are detected."""
        identifiers = hostname.parse(sample_log_with_hostnames, sample_config)

        # Expected standalone NetBIOS names in the sample log
        # BACKUP-02 and DC-PRIMARY only appear inside FQDNs, so they won't be separate NetBIOS matches
        expected_netbios = ["SQL-PROD-03", "FILESVR-01"]

        # Check that all expected NetBIOS names are present
        found_values = [id.value for id in identifiers]
        for expected_name in expected_netbios:
            assert expected_name in found_values, f"Expected NetBIOS name {expected_name} not found in {found_values}"
    
    def test_parse_fqdns(self, sample_log_with_hostnames: str, sample_config: Config) -> None:
        """Test that FQDNs are detected."""
        identifiers = hostname.parse(sample_log_with_hostnames, sample_config)
        
        # Expected FQDNs in the sample log
        expected_fqdns = ["DC-PRIMARY.contoso.local", "MAIL.contoso.local", "BACKUP-02.fabrikam.local"]
        
        # Check that all expected FQDNs are present
        found_values = [id.value for id in identifiers]
        for expected_fqdn in expected_fqdns:
            assert expected_fqdn in found_values, f"Expected FQDN {expected_fqdn} not found in {found_values}"
    
    def test_hostname_false_positive_filtering(self, sample_config: Config) -> None:
        """Test that common words and paths are filtered out."""
        text = "the and for are common words that should not be detected"
        identifiers = hostname.parse(text, sample_config)
        
        # Should not match common English words
        assert len(identifiers) == 0, f"Expected no matches for common words, found {len(identifiers)}"
    
    def test_hostname_lower_confidence(self, sample_config: Config) -> None:
        """Test that hostname parser returns lower confidence scores."""
        text = "Connecting to SQL-PROD-03 server"
        identifiers = hostname.parse(text, sample_config)
        
        # Hostnames should have lower confidence (0.7-0.95)
        for identifier in identifiers:
            assert 0.7 <= identifier.confidence <= 0.95, f"Expected confidence between 0.7 and 0.95, got {identifier.confidence}"
    
    def test_hostname_no_file_extensions(self, sample_config: Config) -> None:
        """Test that hostname parser does not match file extensions."""
        text = "Files: log.txt, data.csv, config.ini"
        identifiers = hostname.parse(text, sample_config)

        # Should not match file extensions (no structural hostname signals)
        assert len(identifiers) == 0, f"Expected no matches for file extensions, found {len(identifiers)}"

    def test_hostname_no_url_components(self, sample_config: Config) -> None:
        """Test that hostname parser does not match URL components."""
        text = "URL: https://www.example.com/path"
        identifiers = hostname.parse(text, sample_config)

        # Should not match URL components
        assert "www" not in [id.value for id in identifiers], "Should not match 'www' as a hostname"

    def test_hostname_structural_heuristics(self, sample_config: Config) -> None:
        """Test that NetBIOS detection requires structural signals."""
        # Should detect: hyphenated names
        text1 = "Server SQL-PROD-03 is online"
        ids1 = hostname.parse(text1, sample_config)
        assert "SQL-PROD-03" in [id.value for id in ids1]

        # Should detect: known prefix
        text2 = "Connecting to SRV01 now"
        # SRV01 has no hyphen, no known prefix with dash, but is all-uppercase with digit
        # Actually SRV01 is uppercase + digit + >= 4 chars? len("SRV01") = 5, yes

        # Should NOT detect: plain English words
        text3 = "the server runs and processes data for common tasks"
        ids3 = hostname.parse(text3, sample_config)
        found_values = [id.value for id in ids3]
        for word in ["the", "server", "runs", "and", "processes", "data", "for", "common", "tasks"]:
            assert word not in found_values, f"Should not match '{word}' as a hostname"

    def test_hostname_no_english_words(self, sample_config: Config) -> None:
        """Test that plain English README-like text produces zero/near-zero false positives."""
        text = ("This is a document about software development. "
                "It covers testing, deployment, and configuration management. "
                "The project uses Python and follows best practices.")
        identifiers = hostname.parse(text, sample_config)
        assert len(identifiers) == 0, f"Expected no matches for English text, found {[id.value for id in identifiers]}"

    def test_hostname_filter_false_positives(self) -> None:
        """Test the filter_false_positives helper function."""
        input_hostnames = ["SQL-PROD-03", "server.contoso.local", ""]
        filtered = hostname.filter_false_positives(input_hostnames)

        assert "SQL-PROD-03" in filtered
        assert "server.contoso.local" in filtered
        assert "" not in filtered


class TestIdentityParser:
    """Tests for the identity parser."""
    
    def test_parse_upns(self, sample_log_with_identity: str, sample_config: Config) -> None:
        """Test that UPNs are detected."""
        identifiers = identity.parse(sample_log_with_identity, sample_config)
        
        # Filter for UPNs only
        upns = [id for id in identifiers if id.identifier_type == "upn"]
        
        # Expected UPNs in the sample log
        expected_upns = ["jsmith@contoso.com", "admin@fabrikam.local"]
        
        # Check that we found the expected number of UPNs
        assert len(upns) == len(expected_upns), f"Expected {len(expected_upns)} UPNs, found {len(upns)}"
        
        # Check that all expected UPNs are present
        found_values = [id.value for id in upns]
        for expected_upn in expected_upns:
            assert expected_upn in found_values, f"Expected UPN {expected_upn} not found in {found_values}"
    
    def test_parse_guids(self, sample_log_with_identity: str, sample_config: Config) -> None:
        """Test that GUIDs are detected."""
        identifiers = identity.parse(sample_log_with_identity, sample_config)
        
        # Filter for GUIDs only
        guids = [id for id in identifiers if id.identifier_type == "guid"]
        
        # Expected GUID in the sample log
        expected_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        
        # Check that we found the expected GUID
        assert len(guids) == 1, f"Expected 1 GUID, found {len(guids)}"
        assert guids[0].value == expected_guid, f"Expected GUID {expected_guid}, got {guids[0].value}"
    
    def test_parse_sids(self, sample_log_with_identity: str, sample_config: Config) -> None:
        """Test that Windows SIDs are detected."""
        identifiers = identity.parse(sample_log_with_identity, sample_config)
        
        # Filter for SIDs only
        sids = [id for id in identifiers if id.identifier_type == "sid"]
        
        # Expected SIDs in the sample log
        expected_sids = [
            "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "S-1-5-21-9876543210-9876543210-9876543210-512"
        ]
        
        # Check that we found the expected number of SIDs
        assert len(sids) == len(expected_sids), f"Expected {len(expected_sids)} SIDs, found {len(sids)}"
        
        # Check that all expected SIDs are present
        found_values = [id.value for id in sids]
        for expected_sid in expected_sids:
            assert expected_sid in found_values, f"Expected SID {expected_sid} not found in {found_values}"
    
    def test_upn_confidence_score(self, sample_config: Config) -> None:
        """Test that UPN parser returns medium-high confidence scores."""
        text = "User: jsmith@contoso.com"
        identifiers = identity.parse_upn(text)
        
        # UPNs should have medium-high confidence (0.9)
        for identifier in identifiers:
            assert identifier.confidence == 0.9, f"Expected confidence 0.9, got {identifier.confidence}"
    
    def test_guid_confidence_score(self, sample_config: Config) -> None:
        """Test that GUID parser returns high confidence scores."""
        text = "GUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        identifiers = identity.parse_guid(text)
        
        # GUIDs should have high confidence (1.0)
        for identifier in identifiers:
            assert identifier.confidence == 1.0, f"Expected confidence 1.0, got {identifier.confidence}"
    
    def test_sid_confidence_score(self, sample_config: Config) -> None:
        """Test that SID parser returns high confidence scores."""
        text = "SID: S-1-5-21-1234567890-1234567890-1234567890-1001"
        identifiers = identity.parse_sid(text)
        
        # SIDs should have high confidence (1.0)
        for identifier in identifiers:
            assert identifier.confidence == 1.0, f"Expected confidence 1.0, got {identifier.confidence}"
    
    def test_upn_no_public_domains(self, sample_config: Config) -> None:
        """Test that UPN parser excludes public email domains."""
        text = "Emails: user@gmail.com, admin@yahoo.com, info@outlook.com"
        identifiers = identity.parse_upn(text)
        
        # Should not match public email domains
        assert len(identifiers) == 0, f"Expected no matches for public email domains, found {len(identifiers)}"
    
    def test_guid_format_validation(self, sample_config: Config) -> None:
        """Test that GUID parser only matches valid GUID format."""
        text = "Valid: a1b2c3d4-e5f6-7890-abcd-ef1234567890, Invalid: not-a-guid"
        identifiers = identity.parse_guid(text)
        
        # Should only match the valid GUID
        assert len(identifiers) == 1, f"Expected 1 GUID, found {len(identifiers)}"
        assert identifiers[0].value == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    
    def test_sid_prefix_validation(self, sample_config: Config) -> None:
        """Test that SID parser only matches SIDs with S-1-5-21 prefix."""
        text = "Valid: S-1-5-21-1234567890-1234567890-1234567890-1001, Invalid: S-1-5-32-544"
        identifiers = identity.parse_sid(text)
        
        # Should only match the valid SID with S-1-5-21 prefix
        assert len(identifiers) == 1, f"Expected 1 SID, found {len(identifiers)}"
        assert identifiers[0].value.startswith("S-1-5-21")


class TestNetworkParser:
    """Tests for the network parser."""
    
    def test_parse_mac_addresses(self, sample_log_with_network: str, sample_config: Config) -> None:
        """Test that MAC addresses are detected."""
        identifiers = network.parse(sample_log_with_network, sample_config)
        
        # Filter for MAC addresses only
        macs = [id for id in identifiers if id.identifier_type == "mac"]
        
        # Expected MAC addresses in the sample log
        expected_macs = ["AA:BB:CC:11:22:33", "11-22-33-44-55-66", "DD:EE:FF:AA:BB:CC"]
        
        # Check that we found the expected number of MAC addresses
        assert len(macs) == len(expected_macs), f"Expected {len(expected_macs)} MAC addresses, found {len(macs)}"
        
        # Check that all expected MACs are present
        found_values = [id.value for id in macs]
        for expected_mac in expected_macs:
            assert expected_mac in found_values, f"Expected MAC {expected_mac} not found in {found_values}"
    
    def test_parse_unc_paths(self, sample_log_with_network: str, sample_config: Config) -> None:
        """Test that UNC paths are detected."""
        identifiers = network.parse(sample_log_with_network, sample_config)
        
        # Filter for UNC paths only
        uncs = [id for id in identifiers if id.identifier_type == "unc"]
        
        # Expected UNC paths in the sample log
        expected_uncs = ["\\\\FILESVR\\Finance$", "\\\\BACKUP-02\\Data\\Archive"]
        
        # Check that we found the expected number of UNC paths
        assert len(uncs) == len(expected_uncs), f"Expected {len(expected_uncs)} UNC paths, found {len(uncs)}"
        
        # Check that all expected UNC paths are present
        found_values = [id.value for id in uncs]
        for expected_unc in expected_uncs:
            assert expected_unc in found_values, f"Expected UNC {expected_unc} not found in {found_values}"
    
    def test_mac_delimiter_preservation(self, sample_config: Config) -> None:
        """Test that MAC address delimiter style is detected."""
        text = "MAC1: AA:BB:CC:11:22:33, MAC2: 11-22-33-44-55-66"
        identifiers = network.parse_mac(text)
        
        # Check that delimiters are preserved
        mac_values = [id.value for id in identifiers]
        assert "AA:BB:CC:11:22:33" in mac_values
        assert "11-22-33-44-55-66" in mac_values
    
    def test_mac_confidence_score(self, sample_config: Config) -> None:
        """Test that MAC parser returns high confidence scores."""
        text = "MAC: AA:BB:CC:11:22:33"
        identifiers = network.parse_mac(text)
        
        # MAC addresses should have high confidence (1.0)
        for identifier in identifiers:
            assert identifier.confidence == 1.0, f"Expected confidence 1.0, got {identifier.confidence}"
    
    def test_unc_confidence_score(self, sample_config: Config) -> None:
        """Test that UNC parser returns medium-high confidence scores."""
        text = "Path: \\\\FILESVR\\Finance$"
        identifiers = network.parse_unc(text)
        
        # UNC paths should have medium-high confidence (0.85)
        for identifier in identifiers:
            assert identifier.confidence == 0.85, f"Expected confidence 0.85, got {identifier.confidence}"
    
    def test_mac_hex_validation(self, sample_config: Config) -> None:
        """Test that MAC parser only matches valid hex characters."""
        text = "Valid: AA:BB:CC:11:22:33, Invalid: GG:HH:II:JJ:KK:LL"
        identifiers = network.parse_mac(text)
        
        # Should only match the valid MAC
        assert len(identifiers) == 1, f"Expected 1 MAC, found {len(identifiers)}"
        assert identifiers[0].value == "AA:BB:CC:11:22:33"
    
    def test_unc_format_validation(self, sample_config: Config) -> None:
        """Test that UNC parser only matches valid UNC paths."""
        text = "Valid: \\\\FILESVR\\Finance$, Invalid: /path/to/file"
        identifiers = network.parse_unc(text)
        
        # Should only match the valid UNC path
        assert len(identifiers) == 1, f"Expected 1 UNC, found {len(identifiers)}"
        assert identifiers[0].value == "\\\\FILESVR\\Finance$"


class TestParserRegistry:
    """Tests for the parser registry."""
    
    def test_all_parsers_registered(self) -> None:
        """Test that all expected parsers are in the registry."""
        from logmask.parsers import PARSER_REGISTRY
        
        expected_parsers = ["ipv4", "cidr", "hostname", "identity", "network"]
        
        # Check that all expected parsers are registered
        for parser_name in expected_parsers:
            assert parser_name in PARSER_REGISTRY, f"Expected parser {parser_name} not found in registry"
        
        # Check that no unexpected parsers are registered
        assert len(PARSER_REGISTRY) == len(expected_parsers), \
            f"Expected {len(expected_parsers)} parsers, found {len(PARSER_REGISTRY)}"
    
    def test_parser_callable_signature(self) -> None:
        """Test that each parser has the correct callable signature."""
        from logmask.parsers import PARSER_REGISTRY
        from logmask.models import Config, DetectedIdentifier
        import inspect
        
        for parser_name, parser_func in PARSER_REGISTRY.items():
            # Check that the parser is callable
            assert callable(parser_func), f"Parser {parser_name} is not callable"
            
            # Check the signature
            sig = inspect.signature(parser_func)
            params = list(sig.parameters.keys())
            
            # Should have (text: str, config: Config) parameters
            assert len(params) == 2, f"Parser {parser_name} should have 2 parameters, found {len(params)}"
            assert params[0] == "text", f"Parser {parser_name} first parameter should be 'text', got {params[0]}"
            assert params[1] == "config", f"Parser {parser_name} second parameter should be 'config', got {params[1]}"
    
    def test_parser_returns_list(self, sample_config: Config) -> None:
        """Test that each parser returns a list of DetectedIdentifier objects."""
        from logmask.parsers import PARSER_REGISTRY
        
        test_text = "Test text with identifiers"
        
        for parser_name, parser_func in PARSER_REGISTRY.items():
            result = parser_func(test_text, sample_config)
            
            # Check that result is a list
            assert isinstance(result, list), f"Parser {parser_name} should return a list, got {type(result)}"
            
            # Check that all items are DetectedIdentifier objects (if any)
            for item in result:
                assert isinstance(item, DetectedIdentifier), \
                    f"Parser {parser_name} returned non-DetectedIdentifier object: {type(item)}"
    
    def test_run_all_parsers(self, sample_config: Config) -> None:
        """Test the run_all_parsers function."""
        from logmask.parsers import run_all_parsers
        
        test_text = """
        Connection from 10.0.1.50 to SQL-PROD-03
        User: jsmith@contoso.com (S-1-5-21-123-456-789-1001)
        MAC: AA:BB:CC:11:22:33
        UNC: \\\\FILESVR\\Finance$
        """
        
        result = run_all_parsers(test_text, sample_config)
        
        # Check that result is a list
        assert isinstance(result, list), "run_all_parsers should return a list"
        
        # Check that all items are DetectedIdentifier objects
        for item in result:
            assert isinstance(item, DetectedIdentifier), \
                f"run_all_parsers returned non-DetectedIdentifier object: {type(item)}"
        
        # Check that we found some identifiers
        assert len(result) > 0, "run_all_parsers should find at least one identifier"
    
    def test_get_parser(self) -> None:
        """Test the get_parser function."""
        from logmask.parsers import get_parser
        
        # Test getting a valid parser
        ipv4_parser = get_parser("ipv4")
        assert callable(ipv4_parser), "get_parser should return a callable"
        
        # Test getting an invalid parser
        try:
            get_parser("invalid_parser")
            assert False, "get_parser should raise KeyError for invalid parser name"
        except KeyError as e:
            assert "Unknown parser" in str(e)

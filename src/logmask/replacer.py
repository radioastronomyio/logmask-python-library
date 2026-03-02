"""
Replacement engine using Aho-Corasick automaton for single-pass text replacement.

This module builds the automaton from the translation map and performs
deterministic, longest-match replacement to prevent substring collisions.

# [Agent context: Critical path for anonymize/reveal. The core algorithm lives in
# _apply_automaton() (longest-match-wins, non-overlapping). The Replacer class is
# stateful via self._automaton — see BUG comment on reveal_text() which mutates
# this state destructively. The module-level convenience functions anonymize_text()
# and reveal_text() are stateless and safe. When fixing the reveal_text bug, do NOT
# change _apply_automaton or _build_automaton — those are correct.]
"""

import ahocorasick
from pathlib import Path

from logmask.models import Config
from logmask.map_engine import load_merged_map


class Replacer:
    """
    Engine for performing single-pass text replacement using Aho-Corasick.
    """

    def __init__(self, config: Config) -> None:
        """
        Initialize the replacer with configuration.

        Args:
            config: Runtime configuration including map paths.
        """
        self.config = config
        self._automaton = None

    def build_automaton(self, mapping: dict[str, str]) -> None:
        """
        Build an Aho-Corasick automaton from the translation map.

        Args:
            mapping: Dictionary mapping original values to anonymized values.
        """
        self._automaton = _build_automaton(mapping)

    def replace_text(self, text: str) -> str:
        """
        Replace all identifiers in text using the built automaton.

        Args:
            text: Source text to process.

        Returns:
            Text with all identifiers replaced.
        """
        # TODO: Inconsistent lazy-loading — replace_text() auto-loads the map if
        # _automaton is None, but reveal_text() always reloads from disk. Unify the
        # lazy-loading strategy so both methods behave consistently.
        if self._automaton is None:
            # Load merged map and build automaton if not already built
            mapping = load_merged_map(self.config)
            self.build_automaton(mapping)

        # Apply shared replacement algorithm
        return _apply_automaton(self._automaton, text)

    def replace_file(self, input_path: Path, output_path: Path) -> None:
        """
        Replace identifiers in a file and write to output.

        Args:
            input_path: Path to the input file.
            output_path: Path to write the anonymized output.
        """
        # Read input file
        text = input_path.read_text(encoding="utf-8")

        # Replace text
        replaced_text = self.replace_text(text)

        # Create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write output file
        output_path.write_text(replaced_text, encoding="utf-8")

    def replace_directory(
        self,
        input_dir: Path,
        output_dir: Path,
    ) -> dict[Path, bool]:
        """
        Replace identifiers in all files in a directory.

        Args:
            input_dir: Directory containing files to process.
            output_dir: Directory to write processed files.

        Returns:
            Dictionary mapping file paths to success status.
        """
        results = {}

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Find all files matching configured extensions
        for input_file in input_dir.rglob("*"):
            if input_file.is_file():
                # Check if file extension matches
                if input_file.suffix.lower() in self.config.extensions:
                    # Calculate relative path and output path
                    relative_path = input_file.relative_to(input_dir)
                    output_file = output_dir / relative_path

                    try:
                        self.replace_file(input_file, output_file)
                        results[input_file] = True
                    except Exception:
                        results[input_file] = False

        return results

    def reveal_text(self, text: str) -> str:
        """
        Reverse replacement to reveal original values.

        Args:
            text: Anonymized text to reveal.

        Returns:
            Text with original values restored.
        """
        # Design choice: Use a local automaton variable for reveal operations
        # to avoid corrupting the forward automaton state stored in self._automaton.
        # This ensures replace_text() and reveal_text() can be called in any
        # order on the same Replacer instance without unexpected behavior.

        # Load merged map and invert it (swap keys and values)
        mapping = load_merged_map(self.config)
        inverted_mapping = {v: k for k, v in mapping.items()}

        # Build local automaton from inverted mapping (does not modify self._automaton)
        reveal_automaton = _build_automaton(inverted_mapping)

        # Apply shared replacement algorithm with local automaton
        return _apply_automaton(reveal_automaton, text)

    def reveal_file(self, input_path: Path, output_path: Path) -> None:
        """
        Reveal original values in a file.

        Args:
            input_path: Path to the anonymized file.
            output_path: Path to write the revealed output.
        """
        # Read input file
        text = input_path.read_text(encoding="utf-8")

        # Reveal text
        revealed_text = self.reveal_text(text)

        # Create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write output file
        output_path.write_text(revealed_text, encoding="utf-8")

    def reveal_directory(
        self,
        input_dir: Path,
        output_dir: Path,
    ) -> dict[Path, bool]:
        """
        Reveal original values in all files in a directory.

        Args:
            input_dir: Directory containing anonymized files.
            output_dir: Directory to write revealed files.

        Returns:
            Dictionary mapping file paths to success status.
        """
        results = {}

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Find all files matching configured extensions
        for input_file in input_dir.rglob("*"):
            if input_file.is_file():
                # Check if file extension matches
                if input_file.suffix.lower() in self.config.extensions:
                    # Calculate relative path and output path
                    relative_path = input_file.relative_to(input_dir)
                    output_file = output_dir / relative_path

                    try:
                        self.reveal_file(input_file, output_file)
                        results[input_file] = True
                    except Exception:
                        results[input_file] = False

        return results


def _build_automaton(mapping: dict[str, str]) -> ahocorasick.Automaton:
    """
    Build an Aho-Corasick automaton from a mapping dictionary.

    Args:
        mapping: Dictionary mapping original values to replacement values.

    Returns:
        Built Aho-Corasick automaton ready for searching.
    """
    automaton = ahocorasick.Automaton(store=ahocorasick.STORE_ANY)
    for key, value in mapping.items():
        automaton.add_word(key, (key, value))
    if mapping:
        automaton.make_automaton()
    return automaton


def _apply_automaton(automaton: ahocorasick.Automaton, text: str) -> str:
    """
    Apply an Aho-Corasick automaton to text using longest-match-wins algorithm.

    This is the core replacement algorithm shared by all replacement operations.
    It ensures deterministic, non-overlapping replacement with longest-match priority.

    Args:
        automaton: Built Aho-Corasick automaton ready for searching.
        text: Source text to process.

    Returns:
        Text with all matches replaced according to the automaton's values.
    """
    # If automaton has no patterns, return text unchanged
    if len(automaton) == 0:
        return text

    # Collect all matches first
    matches = []
    for end_index, (key, value) in automaton.iter(text):
        start_pos = end_index - len(key) + 1
        matches.append((start_pos, end_index, value))

    # Group matches by start position and keep longest at each position
    matches_by_start = {}
    for start, end, value in matches:
        if start not in matches_by_start or (end - start) > (matches_by_start[start][1] - matches_by_start[start][0]):
            matches_by_start[start] = (start, end, value)

    # Sort matches by start position
    selected = sorted(matches_by_start.values(), key=lambda x: x[0])

    # Select non-overlapping matches
    final_selected = []
    last_end = -1
    for start, end, value in selected:
        if start > last_end:
            final_selected.append((start, end, value))
            last_end = end

    # Build result from selected matches
    result = []
    last_pos = 0
    for start, end, value in final_selected:
        # Add unmodified text before this match
        if start > last_pos:
            result.append(text[last_pos:start])

        # Add replacement
        result.append(value)

        # Update last position
        last_pos = end + 1

    # Add remaining text after last match
    if last_pos < len(text):
        result.append(text[last_pos:])

    return "".join(result)


def anonymize_text(text: str, mapping: dict[str, str]) -> str:
    """
    Convenience function to anonymize text with a mapping.

    Args:
        text: Source text to anonymize.
        mapping: Dictionary mapping original values to anonymized values.

    Returns:
        Anonymized text.
    """
    automaton = _build_automaton(mapping)
    return _apply_automaton(automaton, text)


def reveal_text(text: str, mapping: dict[str, str]) -> str:
    """
    Convenience function to reveal text with a mapping.

    Args:
        text: Anonymized text to reveal.
        mapping: Dictionary mapping original values to anonymized values.

    Returns:
        Revealed text.
    """
    # Invert mapping
    inverted_mapping = {v: k for k, v in mapping.items()}

    # Use anonymize_text with inverted mapping
    return anonymize_text(text, inverted_mapping)

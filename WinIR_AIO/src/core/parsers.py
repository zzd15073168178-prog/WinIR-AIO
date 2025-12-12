"""
Parsers Module
Parses output from various tools (Autoruns, WMIC, etc.)
"""

import csv
import io
import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class BaseParser:
    """Base parser class"""
    @staticmethod
    def parse(data: str) -> Any:
        raise NotImplementedError


class CSVParser(BaseParser):
    """Generic CSV Parser"""
    
    @staticmethod
    def parse(data: str, delimiter: str = ',', skip_lines: int = 0) -> List[Dict[str, str]]:
        """
        Parse CSV data into a list of dictionaries
        
        Args:
            data: Raw CSV string
            delimiter: CSV delimiter
            skip_lines: Number of lines to skip at start
            
        Returns:
            List of dicts where keys are headers
        """
        if not data:
            return []
            
        try:
            # Handle potential BOM and whitespace
            data = data.strip()
            if data.startswith('\ufeff'):
                data = data[1:]
                
            lines = data.splitlines()
            if len(lines) <= skip_lines:
                return []
                
            lines = lines[skip_lines:]
            
            # Use csv.DictReader
            reader = csv.DictReader(lines, delimiter=delimiter)
            return [row for row in reader]
            
        except Exception as e:
            logger.error(f"CSV Parsing error: {e}")
            return []


class AutorunsParser(BaseParser):
    """Parser for Sysinternals Autoruns output (CSV format)"""
    
    @staticmethod
    def parse(data: str) -> List[Dict[str, Any]]:
        """
        Parse autorunsc -a * -c output
        
        Args:
            data: Output from autorunsc command
            
        Returns:
            List of autorun entries
        """
        # Autoruns CSV output usually starts immediately with headers if -nobanner is used
        # But sometimes we might need to clean it up
        
        entries = CSVParser.parse(data)
        
        processed_entries = []
        for entry in entries:
            # Normalize keys (strip whitespace, lower case)
            clean_entry = {k.strip().lower(): v.strip() for k, v in entry.items() if k}
            
            # Filter empty entries
            if not clean_entry.get('entry location') and not clean_entry.get('image path'):
                continue
                
            processed_entries.append(clean_entry)
            
        return processed_entries


class EventLogParser(BaseParser):
    """Parser for Get-WinEvent output (JSON or List format)"""
    
    @staticmethod
    def parse_json(data: str) -> List[Dict[str, Any]]:
        """Parse JSON output from ConvertTo-Json"""
        import json
        try:
            if not data:
                return []
            return json.loads(data)
        except Exception as e:
            logger.error(f"JSON Parsing error: {e}")
            return []

    @staticmethod
    def parse_text_list(data: str) -> List[Dict[str, Any]]:
        """
        Parse text list format (Key : Value)
        Used as fallback if JSON fails
        """
        entries = []
        current_entry = {}
        
        for line in data.splitlines():
            line = line.strip()
            if not line:
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                continue
                
            if ':' in line:
                key, value = line.split(':', 1)
                current_entry[key.strip()] = value.strip()
                
        if current_entry:
            entries.append(current_entry)
            
        return entries


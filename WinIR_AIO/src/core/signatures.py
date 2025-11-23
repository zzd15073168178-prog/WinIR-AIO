"""
Signatures Module
Handles digital signature verification using Sysinternals Sigcheck
Enhanced with batch processing and proper path handling
"""

import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

from .executor import CommandRunner, CommandResult
from .parsers import CSVParser
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config import get_tool_path

logger = logging.getLogger(__name__)

class SignatureVerifier:
    """Wrapper for sigcheck.exe"""
    
    def __init__(self):
        self.runner = CommandRunner()
        
    def verify_file(self, file_path: str, include_hash: bool = False) -> Dict[str, Any]:
        """
        Verify a single file signature
        
        Args:
            file_path: Path to the file
            include_hash: Whether to include file hashes (slower)
            
        Returns:
            Dict containing signature status
        """
        if not Path(file_path).exists():
            return {'verified': False, 'status': 'File not found', 'path': file_path}
            
        # Build args list
        args_list = ['-a', '-c', '-nobanner']
        if include_hash:
            args_list.append('-h')
        
        # Quote the file path if it contains spaces
        args_str = ' '.join(args_list) + f' "{file_path}"'
        
        # Note: run_sysinternals_tool now uses get_tool_path internally
        result = self.runner.run_sysinternals_tool('sigcheck', args_str)
        
        if not result.success:
            return {
                'verified': False, 
                'status': f'Error: {result.stderr}',
                'path': file_path
            }
            
        # Parse CSV output
        entries = CSVParser.parse(result.stdout)
        if not entries:
            return {
                'verified': False, 
                'status': 'Parse error',
                'path': file_path
            }
            
        info = entries[0]
        
        # Normalize keys (handle case variations and None values)
        clean_info = {k.strip().lower(): v.strip() if v else '' 
                     for k, v in info.items() if k}
        
        # Determine verification status
        verified_status = clean_info.get('verified', '').lower()
        is_verified = verified_status in ['signed', 'catalog signed']
        
        return {
            'verified': is_verified,
            'status': clean_info.get('verified', 'Unknown'),
            'signer': clean_info.get('signers', clean_info.get('signer', '')),
            'publisher': clean_info.get('publisher', clean_info.get('company', '')),
            'description': clean_info.get('description', ''),
            'product': clean_info.get('product', ''),
            'version': clean_info.get('file version', clean_info.get('version', '')),
            'date': clean_info.get('date', ''),
            'path': clean_info.get('path', file_path),
            'hash_md5': clean_info.get('md5', '') if include_hash else '',
            'hash_sha1': clean_info.get('sha1', '') if include_hash else '',
            'hash_sha256': clean_info.get('sha256', '') if include_hash else '',
        }
        
    def verify_batch(self, 
                    file_paths: List[str], 
                    include_hash: bool = False,
                    use_wildcard: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Verify multiple files
        
        Args:
            file_paths: List of file paths
            include_hash: Whether to include file hashes
            use_wildcard: If True and all files in same dir, use wildcard (faster)
            
        Returns:
            Dict mapping file paths to verification results
        """
        results = {}
        
        # Check if we can use wildcard optimization
        if use_wildcard and len(file_paths) > 5:
            # Check if all files in same directory
            paths = [Path(p) for p in file_paths]
            parent_dirs = set(p.parent for p in paths)
            
            if len(parent_dirs) == 1:
                # All in same dir - use wildcard
                parent_dir = paths[0].parent
                args_list = ['-a', '-c', '-nobanner']
                if include_hash:
                    args_list.append('-h')
                args_str = ' '.join(args_list) + f' "{parent_dir}\\*"'
                
                result = self.runner.run_sysinternals_tool('sigcheck', args_str)
                
                if result.success:
                    entries = CSVParser.parse(result.stdout)
                    for entry in entries:
                        clean_info = {k.strip().lower(): v.strip() if v else '' 
                                    for k, v in entry.items() if k}
                        file_path = clean_info.get('path', '')
                        
                        if file_path:
                            verified_status = clean_info.get('verified', '').lower()
                            is_verified = verified_status in ['signed', 'catalog signed']
                            
                            results[file_path] = {
                                'verified': is_verified,
                                'status': clean_info.get('verified', 'Unknown'),
                                'signer': clean_info.get('signers', clean_info.get('signer', '')),
                                'publisher': clean_info.get('publisher', clean_info.get('company', '')),
                                'description': clean_info.get('description', ''),
                                'product': clean_info.get('product', ''),
                                'version': clean_info.get('file version', clean_info.get('version', '')),
                                'date': clean_info.get('date', ''),
                                'path': file_path,
                                'hash_md5': clean_info.get('md5', '') if include_hash else '',
                                'hash_sha1': clean_info.get('sha1', '') if include_hash else '',
                                'hash_sha256': clean_info.get('sha256', '') if include_hash else '',
                            }
                    return results
        
        # Fallback: individual verification
        for path in file_paths:
            results[path] = self.verify_file(path, include_hash)
            
        return results
    
    def is_microsoft_signed(self, file_path: str) -> bool:
        """
        Quick check if file is signed by Microsoft
        
        Args:
            file_path: Path to check
            
        Returns:
            bool: True if signed by Microsoft Corporation
        """
        result = self.verify_file(file_path, include_hash=False)
        if not result.get('verified'):
            return False
            
        publisher = result.get('publisher', '').lower()
        signer = result.get('signer', '').lower()
        
        return 'microsoft' in publisher or 'microsoft' in signer

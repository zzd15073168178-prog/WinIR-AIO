#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Runner for WinIR-AIO
Provides flexible test execution options
"""
import sys
import subprocess
import argparse
from pathlib import Path

def run_tests(test_type='all', coverage=True, verbose=True, markers=None):
    """
    Run pytest with specified options
    
    Args:
        test_type: 'all', 'unit', 'integration', 'gui'
        coverage: Whether to generate coverage report
        verbose: Verbose output
        markers: Additional pytest markers
    """
    cmd = [sys.executable, '-m', 'pytest']
    
    # Select test path
    if test_type == 'unit':
        cmd.append('tests/unit')
    elif test_type == 'integration':
        cmd.append('tests/integration')
    elif test_type == 'gui':
        cmd.append('tests/gui')
    else:
        cmd.append('tests/')
    
    # Add options
    if verbose:
        cmd.append('-v')
    
    if coverage:
        cmd.extend(['--cov=src', '--cov-report=html', '--cov-report=term'])
    
    if markers:
        cmd.extend(['-m', markers])
    
    # Always show summary
    cmd.append('--tb=short')
    
    print("=" * 70)
    print("WinIR-AIO Automated Test Suite")
    print("=" * 70)
    print(f"Test Type: {test_type}")
    print(f"Coverage: {coverage}")
    print(f"Markers: {markers or 'None'}")
    print("=" * 70)
    print()
    print(f"Command: {' '.join(cmd)}")
    print()
    
    # Run tests
    result = subprocess.run(cmd)
    
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description='Run automated tests for WinIR-AIO'
    )
    
    parser.add_argument(
        'test_type',
        nargs='?',
        default='all',
        choices=['all', 'unit', 'integration', 'gui', 'quick'],
        help='Type of tests to run (default: all)'
    )
    
    parser.add_argument(
        '--no-coverage',
        action='store_true',
        help='Disable coverage reporting'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Less verbose output'
    )
    
    parser.add_argument(
        '-m', '--markers',
        type=str,
        help='Run tests matching given mark expression'
    )
    
    parser.add_argument(
        '-k', '--keyword',
        type=str,
        help='Run tests matching given keyword expression'
    )
    
    args = parser.parse_args()
    
    # Quick mode = unit tests only, no coverage
    if args.test_type == 'quick':
        args.test_type = 'unit'
        args.no_coverage = True
    
    returncode = run_tests(
        test_type=args.test_type,
        coverage=not args.no_coverage,
        verbose=not args.quiet,
        markers=args.markers
    )
    
    sys.exit(returncode)


if __name__ == '__main__':
    main()


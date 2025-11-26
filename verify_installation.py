#!/usr/bin/env python3
"""
Installation & Verification Script
Tests all dependencies and setup for DoS Detection System
"""

import sys
import subprocess
import importlib


def check_python_version():
    """Check Python version"""
    print("\n[1/5] Checking Python version...")
    version = sys.version_info
    
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor} - Requires 3.8+")
        return False


def check_dependencies():
    """Check required dependencies"""
    print("\n[2/5] Checking dependencies...")
    
    required = {
        'scapy': 'Scapy (packet manipulation)',
    }
    
    optional = {
        'pytest': 'pytest (testing)',
        'elasticsearch': 'Elasticsearch (alerting)',
    }
    
    all_ok = True
    
    for module, description in required.items():
        try:
            importlib.import_module(module)
            print(f"  ✓ {description}")
        except ImportError:
            print(f"  ✗ {description} - REQUIRED")
            all_ok = False
    
    for module, description in optional.items():
        try:
            importlib.import_module(module)
            print(f"  ✓ {description}")
        except ImportError:
            print(f"  • {description} - Optional")
    
    return all_ok


def check_permissions():
    """Check for required permissions"""
    print("\n[3/5] Checking permissions...")
    
    import os
    
    if os.geteuid() == 0:
        print("  ✓ Running with sudo (required for packet capture)")
        return True
    else:
        print("  ⚠ Not running with sudo")
        print("    Note: Required for live packet capture")
        return None  # Not fatal


def check_network_interfaces():
    """Check available network interfaces"""
    print("\n[4/5] Checking network interfaces...")
    
    try:
        import socket
        from scapy.arch import get_if_list
        
        interfaces = get_if_list()
        
        if interfaces:
            print(f"  ✓ Found {len(interfaces)} network interface(s):")
            for iface in interfaces:
                print(f"    - {iface}")
            return True
        else:
            print("  ✗ No network interfaces found")
            return False
    
    except Exception as e:
        print(f"  ✗ Error checking interfaces: {str(e)}")
        return False


def check_project_structure():
    """Verify project structure"""
    print("\n[5/5] Checking project structure...")
    
    import os
    from pathlib import Path
    
    required_dirs = [
        'src',
        'tests',
        'logs',
        'pcap_files',
    ]
    
    required_files = [
        'requirements.txt',
        'README.md',
        'config.py',
        'src/__init__.py',
        'src/packet_sniffer.py',
        'src/dos_detector.py',
        'src/alert_manager.py',
        'src/pcap_analyzer.py',
        'src/dos_detection_main.py',
        'src/utils.py',
        'tests/__init__.py',
        'tests/test_dos_detection.py',
        'quickstart_simulation.py',
    ]
    
    all_ok = True
    
    for dir_name in required_dirs:
        if os.path.isdir(dir_name):
            print(f"  ✓ {dir_name}/")
        else:
            print(f"  ✗ {dir_name}/ - MISSING")
            all_ok = False
    
    for file_name in required_files:
        if os.path.isfile(file_name):
            print(f"  ✓ {file_name}")
        else:
            print(f"  ✗ {file_name} - MISSING")
            all_ok = False
    
    return all_ok


def main():
    """Run all checks"""
    print("="*60)
    print("DoS ATTACK DETECTION SYSTEM - INSTALLATION CHECK")
    print("="*60)
    
    results = {
        'python_version': check_python_version(),
        'dependencies': check_dependencies(),
        'permissions': check_permissions(),
        'network': check_network_interfaces(),
        'structure': check_project_structure(),
    }
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    for check, result in results.items():
        if result is True:
            status = "✓ PASS"
        elif result is False:
            status = "✗ FAIL"
        else:
            status = "⚠ WARNING"
        
        print(f"  {status:10} - {check.replace('_', ' ').title()}")
    
    print("\n" + "="*60)
    
    # Installation instructions
    if not results['dependencies']:
        print("\nINSTALLATION REQUIRED:")
        print("\nRun the following commands:")
        print("  pip install -r requirements.txt")
        print("\nOn Ubuntu/Debian for optional Wireshark integration:")
        print("  sudo apt-get install wireshark wireshark-common")
    
    # Permission notice
    if results['permissions'] is None or results['permissions'] is False:
        print("\nPERMISSION SETUP:")
        print("For live packet capture, run with sudo:")
        print("  sudo python3 src/dos_detection_main.py")
        print("\nOr grant capabilities to Python:")
        print("  sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3")
    
    # Quick start
    if all([results['python_version'], results['dependencies'], results['structure']]):
        print("\nREADY TO USE!")
        print("\nQuick start:")
        print("1. Run simulation (no sudo needed):")
        print("   python3 quickstart_simulation.py")
        print("\n2. Start live detection (sudo required):")
        print("   sudo python3 src/dos_detection_main.py")
        print("\n3. Run unit tests:")
        print("   python3 -m unittest tests/test_dos_detection.py -v")
    
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()

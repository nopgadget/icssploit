#!/usr/bin/env python3
"""
ICSSPLOIT Configuration

This file contains all configuration settings for ICSSPLOIT.
You can modify these values to customize the behavior of the framework.
"""

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log file settings
LOG_FILE_NAME = "icssploit.log"
LOG_MAX_BYTES = 500000  # 500KB
LOG_LEVEL = 10  # DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50

# =============================================================================
# EXTRA PACKAGE CONFIGURATION
# =============================================================================

# Path to extra package directory
# Set to None to disable extra packages
EXTRA_PACKAGE_PATH = "extra_package"

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================

# Application name and version
APP_NAME = "ICSSPLOIT"
APP_VERSION = "0.2.0"
APP_DESCRIPTION = "ICS Exploitation Framework"

# GitHub repository information
GITHUB_URL = "https://github.com/nopgadget/icssploit"

# =============================================================================
# INTERFACE SETTINGS
# =============================================================================

# Prompt settings
DEFAULT_PROMPT_HOSTNAME = "icssploit"

# History file settings
HISTORY_FILE = "~/.icssploit_history"
HISTORY_LENGTH = 100

# =============================================================================
# MODULE SETTINGS
# =============================================================================

# Default module categories
MODULE_CATEGORIES = ['scanners', 'exploits', 'creds']

# =============================================================================
# NETWORK SETTINGS
# =============================================================================

# Default timeout for network operations (seconds)
DEFAULT_TIMEOUT = 30

# Default port for common protocols
DEFAULT_PORTS = {
    's7comm': 102,
    'modbus': 502,
    'profinet': 34964,
    'ethernetip': 44818,
    'bacnet': 47808,
    'opcua': 4840,
    'ssh': 22,
    'telnet': 23,
    'ftp': 21,
    'http': 80,
    'https': 443,
    'snmp': 161,
}

# =============================================================================
# VALIDATION SETTINGS
# =============================================================================

# Maximum number of targets for scanning
MAX_SCAN_TARGETS = 1000

# Maximum number of credentials for bruteforce
MAX_BRUTEFORCE_ATTEMPTS = 10000

# =============================================================================
# DEBUG SETTINGS
# =============================================================================

# Enable debug mode (more verbose output)
DEBUG_MODE = False

# Enable verbose network operations
VERBOSE_NETWORK = False

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# Enable SSL/TLS verification
VERIFY_SSL = True

# Allow insecure connections (for testing only)
ALLOW_INSECURE = False

# =============================================================================
# EXPORT SETTINGS
# =============================================================================

# Default export format
DEFAULT_EXPORT_FORMAT = "csv"

# Available export formats
EXPORT_FORMATS = ["csv", "json", "xml", "txt"]

# =============================================================================
# DEPRECATED SETTINGS (for backward compatibility)
# =============================================================================

# These settings are kept for backward compatibility
# They will be removed in future versions

# Old INI file settings (deprecated)
LOG_FILE_NAME_LEGACY = LOG_FILE_NAME
LOG_MAX_BYTES_LEGACY = LOG_MAX_BYTES
LOG_LEVEL_LEGACY = LOG_LEVEL
PACKAGE_PATH_LEGACY = EXTRA_PACKAGE_PATH 
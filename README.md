# MITRE ATT&CK Group Techniques Analyzer

This tool extracts and analyzes techniques used by threat actor groups documented in the MITRE ATT&CK framework.

## Overview

The MITRE ATT&CK Group Techniques Analyzer is a Python-based tool that:

1. Scrapes the MITRE ATT&CK website to collect information about known threat actor groups
2. Extracts detailed information about the techniques and sub-techniques used by each group
3. Organizes the data into structured formats for further analysis

## Features

- Retrieves comprehensive list of threat actor groups from MITRE ATT&CK
- Extracts detailed technique information including:
  - Parent techniques and sub-techniques
  - Technique IDs and names
  - Domains (Enterprise, Mobile, ICS)
  - Usage descriptions
- Handles complex table structures and relationships between techniques
- Exports data to CSV format for integration with other tools

## Requirements

- Python 3.6+
- Required packages:
  - pandas
  - requests
  - beautifulsoup4


# source_code scrapper

## Description

This script identifies and extracts potential sensitive information from the source code of given URLs. It uses regular expressions to search for patterns associated with various types of sensitive data, such as API keys, access tokens, and private keys.

## Features

- Scans multiple URLs for sensitive data.
- Supports various key types, including API keys, OAuth tokens, and private keys.
- Outputs identified sensitive information with associated key types.

## Usage

1. Provide a list of URLs in a text file.
2. Run the script to scan and identify sensitive data.
3. python3 scrapper.py -f urls.txt


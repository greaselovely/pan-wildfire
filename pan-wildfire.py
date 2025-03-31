"""
WildFire URL and File Verdict Tool

This script interacts with the Palo Alto Networks WildFire API to retrieve
verdicts for file hashes and URLs. It can check if files or domains are
malicious, phishing, C2 servers, or benign according to WildFire's analysis.

Usage:
    - No arguments: Runs URL verdict check only
    - -f/--file: Check file hashes in file_hashes.txt
    - -u/--url: Check URLs in domains.txt (can be combined with -f)

Requirements:
    - config.json with a valid WildFire API key
    - Python packages: requests, tabulate, xmltodict, pandas
"""

import os
import stat
import json
import pathlib
import argparse
from sys import argv, exit
import requests
import tabulate
import xmltodict
import pandas as pd
import random
from typing import Dict, Tuple, List, Any, Optional


# Configuration constants
FHNAME = 'file_hashes.txt'
UFNAME = 'domains.txt'
C2DOMAINS = 'known_malicious_domains.txt'
WF_API_URL = "https://wildfire.paloaltonetworks.com/publicapi/get/verdict"

# Verdict dictionary mapping API response codes to human-readable verdicts
VERDICT_DICT = {
    "0": "benign",  
    "1": "malware",  
    "2": "grayware", 
    "4": "phishing", 
    "5": "C2", 
    "-100": "verdict pending", 
    "-101": "error", 
    "-102": "not found", 
    "-103": "invalid hash"
}

# Initialize path variables
local_path = pathlib.Path(__file__).parent
file_hash_path = pathlib.Path.joinpath(local_path, FHNAME)
urls_file_path = pathlib.Path.joinpath(local_path, UFNAME)
c2_file_path = pathlib.Path.joinpath(local_path, C2DOMAINS)


def clear() -> None:
    """Clear the terminal screen in a cross-platform way.
    
    Uses 'cls' command for Windows systems and 'clear' command for Unix/Linux systems.
    """
    os.system("cls" if os.name == "nt" else "clear")


def parse_arguments() -> Tuple[bool, bool]:
    """Parse command line arguments to determine which verdict checks to run.
    
    Returns:
        Tuple[bool, bool]: A tuple containing (file_check, url_check) flags
    """
    parser = argparse.ArgumentParser(
        description='WildFire URL and File Verdict Tool. '
                    'Without arguments, only URL check is performed.'
    )
    parser.add_argument('-f', '--file', action='store_true',
                        help='Retrieve verdict for file hashes from file_hashes.txt',
                        required=False)
    parser.add_argument('-u', '--url', action='store_true',
                        help='Retrieve verdict for URLs from domains.txt',
                        required=False)
    args = parser.parse_args()
    return args.file, args.url


def load_config() -> Dict[str, Any]:
    """Load configuration from config.json or create a new one if it doesn't exist.
    
    The config file stores the WildFire API key and is secured with restrictive permissions.
    
    Returns:
        Dict[str, Any]: Dictionary containing configuration settings
        
    Raises:
        SystemExit: If the configuration file has invalid JSON
    """
    file_name = 'config.json'
    local_path = pathlib.Path(__file__).resolve().parent
    config_path = pathlib.Path.joinpath(local_path, file_name)

    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = json.load(file)
        secure_file(config_path, file_name)
        return config
    except FileNotFoundError:
        # Create an empty config.json file template
        config_init_starter = {"authentication": {"api_key": ""}}
        with open(config_path, 'w', encoding='utf-8') as file:
            json.dump(config_init_starter, file, indent=2)
        print(f"\n\n[i]\tEmpty {file_name} created.")
        secure_file(config_path, file_name)
        return load_config()
    except json.JSONDecodeError:
        print(f"Error decoding JSON in '{config_path}'.")
        exit(1)


def secure_file(config_path: pathlib.Path, file_name: str) -> None:
    """Set restrictive permissions on the configuration file to protect the API key.
    
    Args:
        config_path: Path to the configuration file
        file_name: Name of the configuration file for display purposes
    """
    if os.name == "nt":
        import ctypes
        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(config_path))
        is_read_only = attributes & 1
        if not is_read_only:
            ctypes.windll.kernel32.SetFileAttributesW(str(config_path), 1)
    else:
        current_permissions = stat.S_IMODE(os.lstat(config_path).st_mode)
        if current_permissions != 0o600:
            os.chmod(config_path, 0o600)
            print(f"\n\n[i]\tFile {file_name} secured.\n")


def get_file_verdict(api_key: str) -> None:
    """Retrieve verdict information for file hashes from WildFire API.
    
    Reads MD5 hashes from file_hashes.txt, submits each to the WildFire API,
    and displays the verdict results.
    
    Args:
        api_key: WildFire API key for authentication
        
    Raises:
        Exception: If there's an error submitting hashes to WildFire
    """
    print('Checking WildFire File Verdicts...\n')
    file_ver_dict = {}
    
    try:
        with open(file_hash_path, 'r', encoding='utf-8') as fh:
            file_hashes = fh.read().splitlines()
        
        for i, file_hash in enumerate(file_hashes):
            payload = {'apikey': (None, api_key), 'hash': (None, file_hash)}
            response = requests.post(WF_API_URL, files=payload, timeout=30)
            file_verdict_response = xmltodict.parse(response.text)
            file_ver_dict[i] = file_verdict_response
        
        display_results(file_ver_dict, 'md5')
    except FileNotFoundError:
        print(f"Error: {file_hash_path} not found. Please create this file with your file hashes.")
    except Exception as e:
        print(f'Error submitting hash to WildFire. Verify API key or hashes and try again.\n{e}')


def get_url_verdict(api_key: str) -> None:
    """Retrieve verdict information for URLs from WildFire API.
    
    Reads URLs from domains.txt (generates sample domains if file is empty),
    submits each to the WildFire API, and displays the verdict results.
    
    Args:
        api_key: WildFire API key for authentication
        
    Raises:
        Exception: If there's an error submitting URLs to WildFire
    """
    url_ver_dict = {}
    
    # Generate domains if file doesn't exist or is empty
    if not pathlib.Path.is_file(urls_file_path) or os.path.getsize(urls_file_path) == 0:
        domain_gen()
    
    try:
        with open(urls_file_path, 'r', encoding='utf-8') as uf:
            urls = uf.read().splitlines()
        
        for i, url in enumerate(urls):
            payload = {'apikey': (None, api_key), 'url': (None, url)}
            response = requests.post(WF_API_URL, files=payload, timeout=5)
            url_verdict_response = xmltodict.parse(response.text)
            url_ver_dict[i] = url_verdict_response
        
        if url_ver_dict:
            print('Checking WildFire URL Verdicts...\n')
            display_results(url_ver_dict, 'url')
        else:
            print("No domains to process...exiting\n\n")
    except Exception as e:
        print(f'Error submitting URL to WildFire.\n\n{e}\n\n')


def display_results(verdict_dict: Dict[int, Dict], key_type: str) -> None:
    """Display WildFire verdict results in a tabular format.
    
    Converts the XML response dictionary to a user-friendly table showing
    the submitted samples and their verdicts, followed by a summary count.
    
    Args:
        verdict_dict: Dictionary containing WildFire API responses
        key_type: Type of key to extract from results ('md5' for files or 'url' for URLs)
    """
    vkey_list = []
    verd_list = []
    
    for i, _ in enumerate(verdict_dict):
        verdict_info = verdict_dict.get(i).get('wildfire').get('get-verdict-info')
        vkey = verdict_info.get(key_type)
        verdict = verdict_info.get('verdict')
        
        if verdict is None:
            vkey = 'no verdict'
        
        vkey_list.append(vkey)
        verd_list.append(VERDICT_DICT.get(verdict))

    data = {"Sample Submitted": vkey_list, "Verdicts": verd_list}
    df = pd.DataFrame.from_dict(data)
    
    print("Sample Submitted")
    print(tabulate.tabulate(df, showindex=False))
    
    # Generate summary footer
    footer = {
        'Verdict': [
            VERDICT_DICT.get("0"),
            VERDICT_DICT.get("1"),
            VERDICT_DICT.get("2"),
            VERDICT_DICT.get("4"),
            VERDICT_DICT.get("5")
        ],
        'Totals': [
            verd_list.count('benign'),
            verd_list.count('malware'),
            verd_list.count('grayware'),
            verd_list.count('phishing'),
            verd_list.count('C2')
        ]
    }

    footer_df = pd.DataFrame.from_dict(footer)
    footer_df = footer_df.set_index('Verdict')
    print("\n\nTotals\n" + tabulate.tabulate(footer_df), end='\n\n')


def domain_gen() -> None:
    """Generate a sample list of domains for demonstration purposes.
    
    Reads 10 random domains from known_malicious_domains.txt and writes them
    to domains.txt. This is used when no domains are provided by the user.
    
    Raises:
        SystemExit: If no source domains file is available
    """
    domains_list = []
    
    if pathlib.Path.is_file(c2_file_path) and os.path.getsize(c2_file_path) > 0:
        with open(c2_file_path, 'r', encoding='utf-8') as f:
            domains_list_from_opendns = f.read().split()
    else:
        print('[!]\tNothing to generate from, and everything else is empty...exiting\n\n')
        exit(1)

    # Select 10 random domains
    for _ in range(10):
        random_domain = random.choice(domains_list_from_opendns)
        domains_list.append(random_domain)
    
    # Write domains to file
    with open(urls_file_path, 'w', encoding='utf-8') as f:
        for domain in domains_list:
            f.write(domain + '\n')


def clear_domain_file() -> None:
    """Clear the contents of the domains.txt file after processing.
    
    This prevents reusing the same sample domains on subsequent runs.
    """
    with open(urls_file_path, 'w', encoding='utf-8') as f:
        f.write('')


def main() -> None:
    """Main entry point for the script.
    
    Clears the screen, loads configuration, validates API key,
    and runs the requested verdict checks based on command-line arguments.
    """
    clear()
    
    # Load configuration and extract API key
    config = load_config()
    api_key = config.get('authentication', {}).get('api_key', '')
    
    if not api_key:
        print("\n\n[!]\tNo API Key found in config.json. Exiting.\n\n")
        exit(1)
    
    # Determine which checks to run based on arguments
    if len(argv) == 1:
        # Default behavior with no arguments: run URL verdict check only
        get_url_verdict(api_key)
    else:
        file_check, url_check = parse_arguments()
        
        if file_check:
            get_file_verdict(api_key)
        if url_check:
            get_url_verdict(api_key)

    # Clean up after execution
    clear_domain_file()


if __name__ == '__main__':
    main()
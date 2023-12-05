#!/usr/bin/env python

import os
import stat
import json
import pathlib
import requests
import argparse
import tabulate
import xmltodict
import pandas as pd
from sys import argv

"""
to do
-refactor
"""


############
#
fhname = 'file_hashes.txt'
ufname = 'domains.txt'
c2domains = 'known_malicious_domains.txt'
#
############

file_ver_dict = {}
url_ver_dict = {}
domains_list = []
ver_dict = { "0": "benign",  
            "1": "malware",  
            "2": "grayware", 
            "4": "phishing", 
            "5": "C2", 
            "-100": "verdict pending", 
            "-101": "error", 
            "-102": "not found", 
            "-103": "invalid hash" }

local_path = pathlib.Path(__file__).parent
file_hash = pathlib.Path.joinpath(local_path, fhname)
urls_file = pathlib.Path.joinpath(local_path, ufname)
c2_file = pathlib.Path.joinpath(local_path, c2domains)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def argue_with_me():
    """
    This is called if there are arguments passed to the script via cli,
    and assigns and stores boolean so that we know which one you want to 
    run, or both.  If you don't provide any, we will default to URL only.
    """
    parser = argparse.ArgumentParser(description='WildFire URL and File Verdict.  No arguments passed; URL is only submitted.')
    parser.add_argument('-f', '--file', action='store_true', help='Retrieve verdict for file hashes (must already have hashes stored)', required=False)
    parser.add_argument('-u', '--url', action='store_true', help='Retrieve verdict for url list (must already have list stored)', required=False)
    args = parser.parse_args()
    url = args.url
    file = args.file
    return file, url

def load_config():
    """
    Used to reference an external json file for
    custom config items, for this we use it to 
    store api_key from WildFire.  
    """
    file_name = 'config.json'
    local_path = pathlib.Path(__file__).resolve().parent
    config_path = pathlib.Path.joinpath(local_path, file_name)

    try:
        with open(config_path, 'r') as file:
            config = json.load(file)
        secure_file(config_path, file_name)
        return config
    except FileNotFoundError:
        """
        We'll build an empty config.json file.
        Edit to use api_key
        """
        config_init_starter = {"authentication" : {"api_key" : ""}}
        with open(config_path, 'w') as file:
            json.dump(config_init_starter, file, indent=2)
        print(f"\n\n[i]\tEmpty {file_name} created.")
        secure_file(config_path, file_name)
        return load_config()
    except json.JSONDecodeError:
        print(f"Error decoding JSON in '{config_path}'.")
        return None

def secure_file(config_path, file_name):
    """
    We want to make sure the API config is 
    secured against open permissions so
    we check the config file and enforce
    permissions if they aren't correct.
    """
    if os.name == "nt":
        import ctypes
        attributes = ctypes.windll.kernel32.GetFileAttributesW(config_path)
        is_read_only = attributes & 1
        if not is_read_only:
            ctypes.windll.kernel32.SetFileAttributesW(config_path, 1)
    else:
        current_permissions = stat.S_IMODE(os.lstat(config_path).st_mode)
        if current_permissions != 0o600:
            os.chmod(config_path, 0o600)
            print(f"\n\n[i]\tFile {file_name} secured.\n")
    return

def get_file_verdict():
    """
    When called from main, this function reads the md5 hashes from the file in the same 
    directory.  It creates 'payload' which is used in combo with the api_key to use 
    in the post request to WildFire.  WF returns a response, and we convert the xml to
    a dictionary, create a new selective dictionary to iterate from later and then 
    send it to results() to provide screen output of the results.
    """
    wf_url = "https://wildfire.paloaltonetworks.com/publicapi/get/verdict"
    print('Checking WildFire File Verdicts...\n')
    try:
        with open(file_hash, 'r') as fh:
            file_hashes = fh.read().splitlines()
        for i, file in enumerate(file_hashes):
            payload = { 'apikey': (None, api_key), 'hash': (None, file) }
            response = requests.post(wf_url, files=payload)
            file_verdict_response = xmltodict.parse(response.text)
            file_ver_dict[i] = file_verdict_response
        results(file_ver_dict, 'md5')
    except Exception as e:
        print(f'There was a problem submitting hash WildFire.  Verify API key or hashes and try again.\n{e}\n{response.status_code}')
        pass

def get_url_verdict():
    """
    When called from main, this function reads the list of domains from the file in the same 
    directory.  It creates 'payload' which is used in combo with the api_key to use 
    in the post request to WildFire.  WF returns a response, and we convert the xml to
    a dictionary, create a new selective dictionary to iterate from later and then 
    send it to results() to provide screen output of the results.
    """
    wf_url = "https://wildfire.paloaltonetworks.com/publicapi/get/verdict"
    
    if not pathlib.Path.is_file(urls_file) or os.path.getsize(urls_file) == 0:
        domain_gen()
    try:
        with open(urls_file, 'r') as uf:
            urls = uf.read().splitlines()
        for i, url in enumerate(urls):
            payload = { 'apikey': (None, api_key), 'url': (None, url) }
            response = requests.post(wf_url, files=payload)
            url_verdict_response = xmltodict.parse(response.text)
            url_ver_dict[i] = url_verdict_response
        if len(url_ver_dict) > 0:
            print('Checking WildFire URL Verdicts...\n')
            results(url_ver_dict, 'url')
        else:
            print("No domains to process...exiting\n\n")
    except Exception as e:
        print(f'There was a problem submitting hash WildFire.\n\n{e}\n\n')

def results(vdict: dict, xkey: str) -> None:
    """
    Receives a dictionary and a desired sub-key of the dict. 
    This converts the dictionary of results into a pandas dataframe solely
    for the purpose of a unified aligned print of results.
    Same is true for the footer which does a sum of verdicts for each verdict.
    """
    vkey_list = []
    verd_list = []
    for i, f in enumerate(vdict):
        vkey = vdict.get(i).get('wildfire').get('get-verdict-info').get(xkey)
        verdict = vdict.get(i).get('wildfire').get('get-verdict-info').get('verdict')
        if verdict == None: vkey = 'no verdict'
        vkey_list.append(vkey)
        verd_list.append(ver_dict.get(verdict))
    
    data = {"Sample Submitted": vkey_list, "Verdicts": verd_list}
    df = pd.DataFrame.from_dict(data)
    print("Sample Submitted")
    print(tabulate.tabulate(df, showindex=False))
    footer = {'Verdict':  [f'{ver_dict.get("0")}', f'{ver_dict.get("1")}', f'{ver_dict.get("2")}', f'{ver_dict.get("4")}', f'{ver_dict.get("5")}'], 'Totals': [verd_list.count('benign'), verd_list.count('malware'), verd_list.count('grayware'), verd_list.count('phishing'), verd_list.count('C2')]}
    footer_df = pd.DataFrame.from_dict(footer)
    footer_df = footer_df.set_index('Verdict')
    print("\n\nTotals\n" + tabulate.tabulate(footer_df), end='\n\n')

def domain_gen():
    """
    There's a known_malicious_domains.txt file along with this file, 
    so we just go grab it and grab 10 random domains_list from it
    and append it to the domains_list list.  To avoid using this, 
    create the domains.txt file, and enter a list of domains in it.
    This is more of a demo mode type solution for this script.  
    """
    if pathlib.Path.is_file(c2_file) and os.path.getsize(c2_file) > 0:
        domains_list_from_opendns = open(c2_file, 'r').read()
    else:
        print('[!]\tNothing to generate from, and everything else is empty...exiting\n\n')
        quit()
    
    domains_list_from_opendns = domains_list_from_opendns.split()

    import random

    i = 0
    while i < 10:
        random_domain = random.choice(domains_list_from_opendns)
        domains_list.append(random_domain)
        i += 1
    write_file()

def write_file():
    """
    Since the domains.txt file was empty / didn't exist
    we take the domain_gen results and save it to domains.txt
    """
    with open(urls_file, 'w') as f:
        for domain in domains_list:
            f.write(domain + '\n')

def clear_domain_file():
    with open(urls_file, 'w') as f:
        f.write('')

def main():
    clear()
    global config, api_key
    config = load_config()
    api_key = config.get('authentication').get('api_key')
    if api_key == "":
        print("\n\n[!]\tNo API Key found in config.json.  Exiting.\n\n")
        exit()
    if len(argv) == 1:
        get_url_verdict()
    else:
        file, url = argue_with_me()
        if file: get_file_verdict()
        if url: get_url_verdict()

    clear_domain_file()


if __name__ == '__main__':
    main()

#!/usr/bin/env python

import os
import pathlib
import pandas as pd
import requests
import xmltodict
import argparse
from sys import argv


############
# I know, and if you want to store the key somewhere else, I totally get it.
api_key = 'enter_your_key_here'
#
############

file_ver_dict = {}
url_ver_dict = {}
ver_dict = { "0": "benign",  
            "1": "malware",  
            "2": "grayware", 
            "4": "phishing", 
            "5": "C2", 
            "-100": "verdict pending", 
            "-101": "error", 
            "-102" : "not found", 
            "-103": "invalid hash" }

lpath = pathlib.Path(__file__).parent
file_hash = os.path.join(lpath, 'file_hashes.txt')
urls_file = os.path.join(lpath, 'urls.txt')

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
        i_hash_error += 1
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
    print('Checking WildFire URL Verdicts...\n')
    try:
        with open(urls_file, 'r') as uf:
            urls = uf.read().splitlines()
        for i, url in enumerate(urls):
            payload = { 'apikey': (None, api_key), 'url': (None, url) }
            response = requests.post(wf_url, files=payload)
            url_verdict_response = xmltodict.parse(response.text)
            url_ver_dict[i] = url_verdict_response
        results(url_ver_dict, 'url')
    except Exception as e:
        print(f'There was a problem submitting hash WildFire.  Verify API key or hashes and try again.\n{e}\n{response.status_code}')
        pass

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
    df = df.set_index(["Sample Submitted"])
    print(df,'\n\n')
    footer = {'Verdict':  ['benign', 'malware', 'grayware', 'phishing', 'C2'], 'Totals': [verd_list.count('benign'), verd_list.count('malware'), verd_list.count('grayware'), verd_list.count('phishing'), verd_list.count('C2')]}
    footer_df = pd.DataFrame.from_dict(footer)
    footer_df = footer_df.set_index('Verdict')
    print(footer_df)


def main():
    clear()
    if len(argv) == 1:
        get_url_verdict()
    else:
        file, url = argue_with_me()
        if file: get_file_verdict()
        if url: get_url_verdict()


if __name__ == '__main__':
    main()

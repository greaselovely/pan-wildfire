# pan-wildfire
Query Wildfire for verdict on file hashes (MD5) or list of domain names / urls.

### Install modules
```pip install -r requirements.txt```

### API Key
- Update the api_key with your own from https://wildfire.paloaltonetworks.com, under Accounts
- api_key = Wildfire API key

### Files
- file_hash = Name of file containing list of hashes to submit to WF
- url_file = Name of the file containing a list of domain names to receive verdict on

### Usage
```
usage: pan-wildfire.py [-h] [-f] [-u]

WildFire URL and File Verdict. No arguments passed; URL is only submitted.

options:
  -h, --help  show this help message and exit
  -f, --file  Retrieve verdict for file hashes (must already have hashes stored)
  -u, --url   Retrieve verdict for url list (must already have list stored)
```

### Demo Mode
If you don't give us domains to query in the domains.txt, we'll generate 10 random one's from
our known_malicious_domains.txt and run the query.

### Output Example:
```
Checking WildFire URL Verdicts...

Sample Submitted
--------------------------------------  -------
blumenhof-wegleitner.at                 malware
seminoc.com                             malware
simulatebrain.com                       malware
n1-headache.com                         benign
frontierweldingllc.com                  malware
bimnapratica.com                        malware
garage-lecompte-rouen.fr                malware
mepavex.nl                              benign
evangelische-pfarrgemeinde-tuniberg.de  malware
simpkinsedwards.co.uk                   benign
--------------------------------------  -------


Totals
--------  -
benign    3
malware   7
grayware  0
phishing  0
C2        0
--------  -
```

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

### Output Example:
```
Checking WildFire URL Verdicts...

                        Verdicts
Sample Submitted                
sendspace.com             benign
marbling.pe.kr           malware
nacjalneg.info            benign
pronline.ru               benign
purplehoodie.com          benign
qsng.cn                   benign
comcast.net               benign
seksburada.net           malware
sportsmansclub.net        benign
stock888.cn              malware
fc2.com                   benign
tathli.com               malware
teamclouds.com            benign
texaswhitetailfever.com   benign
Hotfile.com               benign
wadefamilytree.org       malware
xnescat.info             malware
Mail.Ru                   benign
yt118.com                 benign 


          Totals
Verdict         
benign        13
malware        6
grayware       0
phishing       0
C2             0
```
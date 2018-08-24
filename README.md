
# Scout - a Contactless Active Reconnaissance Tool
![image](https://user-images.githubusercontent.com/31168456/44460301-6d61b500-a604-11e8-9999-13084576d758.png)

Scout is a python tool which utilizes Internet-wide scanning data provided by [Censys](https://censys.io/) to identify known vulnerabilites. Scout relies on the user having access to a MongoDB instance containing National Vulnerability Database's data feeds as well as having a API access to Censys.

Scout is a product of a honours project from Edinburgh Napier University. The associated dissertation can be read on [ResearchGate](https://www.researchgate.net/publication/325857437_Honours_Project_-_Scout_A_Contactless_'Active'_Reconnaissance_Known_Vulnerability_Assessment_Tool). This dissertation coins the term contactless active reconnissance to differtentiate the methodology used from classic contactless recon. 

## Recomended Python Version
Python 3 is the only Python version currently supported by Scout.

## Dependencies
Scout is dependent on

- censys

- editdistance

- pymongo

## Installation

Scout requires a MongoDB instance containing the NVD's datafeeds. "[cve-search](https://github.com/cve-search/cve-search)" is highly reccomended. After installing cve-search:

### Installing MongoDB

Install & run MongoDB
```
brew install mongodb
mkdir -p /data/db
mongod
```
Then install [cve-search](https://github.com/cve-search/cve-search)

Clone Scout into your local directory
```
git clone https://github.com/TheHairyJ/Scout


cd Scout

pip install -r requirements.txt
```
Place your censys API key and secret in a new file called secrets.txt


*Note: Editing of the source code may be required to correctly configure the database connection. Specifically the pymongo assignments.*
=======


## Usage
To use Scout, provide a valid Censys query as a command line argument.
```
python scout.py 192.168.0.0/16
```

## License
=======
*Note: Scout is currently limited to services operating on port 80, this is due to information and API access provided by Censys.* 

## Thanks
Special thanks to [Lachlan Kidson](https://twitter.com/lachlankidson) for his invaluable assistance during development and my supervisors for their support and feedback throughout my honours project.

## License
GNU General Public License Version 3

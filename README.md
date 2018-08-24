
# Scout
Scout is a python tool which utilizes Internet-wide scanning data provided by Censys to identify known vulnerabilites. Scout relies on the user having access to a MongoDB instance containing National Vulnerability Database's data feeds as well as having a API access to Censys.

## Recomended Python Version

Python 3 is the only Python version currently supported by Scout.

## Dependencies

Scout is dependent on

- censys

- editdistance

- pymongo

## Installation
Scout requires a MongoDB instance containing the NVD's datafeeds. [cve-search](https://github.com/cve-search/cve-search) is highly recommended.

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
Place your censys API key and secret in secrets.txt


*Note: Editing of the source code may be required to correctly configure the database connection*

## Usage
To use Scout, provide a valid Censys query as a command line argument.
```
python scout.py 192.168.0.0/16
```
*Note: Scout is currently limited to services operating on port 80, this is due to information and API access provided by Censys.*

## License

GNU General Public License Version 3

"""
Scout.py
"""
# standard library imports
from pprint import pprint
import argparse

# third party imports
import pymongo
from censys.ipv4 import CensysIPv4
import editdistance

CLIENT = pymongo.MongoClient('localhost', 27017)
DATABASE = CLIENT['cvedb']
parser = argparse.ArgumentParser()
parser.add_argument("ip", help="Provide an IP address or range to be passed to Censys", type=str)
args = parser.parse_args()
parser.parse_args()

def print_scout():

    print(r"""
 ______     ______     ______     __  __     ______  
/\  ___\   /\  ___\   /\  __ \   /\ \/\ \   /\__  _\ 
\ \___  \  \ \ \____  \ \ \/\ \  \ \ \_\ \  \/_/\ \/ 
 \/\_____\  \ \_____\  \ \_____\  \ \_____\    \ \_\ 
  \/_____/   \/_____/   \/_____/   \/_____/     \/_/ 

Scout is a contactless 'active' reconnaissance known vulnerability assessment tool.                                                                                
""")


def censys_search(censys_query):

    terms = ['ip', '80.http.get.metadata.description']
    censys = CensysIPv4(api_id="",
                        api_secret="")
    return censys.search(censys_query, fields=terms)


def cpe_exception(cpe_string):

    cpe_string = cpe_string.lower().split()
    cpe_better = []
    cpe_good = []
    application = "cpe:2.3:a:"
    for entry in DATABASE['cpe'].find():
        # Skip operating systems ('o') and device hardware ('h').
        entry_id = entry['id']
        if not entry_id.startswith(application):
            continue

        setvar = set(cpe_string).symmetric_difference(
            set(entry_id.replace(application, '').split(':')))

        # Best case scenario, len(setvar) = 0, return match.
        if not setvar:
            return entry_id

        if len(setvar) < 2:
            cpe_better.append(entry_id)
        elif len(setvar) == 2:
            lens = list(setvar)
            len_0 = lens[0]
            len_1 = lens[1]
            if len(len_1 if len(len_1) > len(len_0) else len_0) \
                    > editdistance.eval(len_0, len_1):
                cpe_good.append(entry_id)
    if len(cpe_better) == 1:
        return cpe_better[0]
    elif len(cpe_good) == 1:
        return cpe_good[0]
    return 'no CPE found'


def cve_search(search_string):

    cursor = DATABASE['cves'].find({"vulnerable_configuration": search_string})
    cve_dict = {'cves': {}}
    for entry in cursor:
        cve_dict['cves'][entry['id']] = {'cvss2': entry['cvss']}
    return cve_dict


def search_results(results_dict, gen):

    results_dict[gen['ip']] = {}
    if '80.http.get.metadata.description' in gen:
        cpe_string = cpe_exception(gen['80.http.get.metadata.description'])
        results_dict[gen['ip']] = {
            'metadata': gen['80.http.get.metadata.description'],
            'cpe': cpe_string
        }
        if 'not found' not in cpe_string:
            results_dict[gen['ip']]['vulns'] = cve_search(cpe_string)


if __name__ == '__main__':
    results_dict = {}
    print_scout()
    for x in censys_search(args.ip):
        search_results(results_dict, x)
    pprint(results_dict, indent=4)

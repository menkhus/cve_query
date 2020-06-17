#!/usr/bin/env python3
""" CVE search via NIST NVD CVE API

    input file is a text file with product:version info that works with
    CPE syntax to look for vulnerabilities

License:
All rights reserved.

Copyright 2020 Mark Menkhus, mark.menkhus@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import json
import re
import requests
import click


def get_cpe_data(cpe):
    """ get data from NIST NVD API
        - match based on CPE uri of possibly vendor,program name, and version in the CPE URI
    """
    url = r"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=%s" % cpe
    try:
        data = requests.get(url=url)
        return(data.json())
    except json.decoder.JSONDecodeError:
        return None


def get_cve(cve_id):
    """ get a single CVE from NVD
    """
    url = r"https://services.nvd.nist.gov/rest/json/cve/1.0/%s" % cve_id
    try:
        data = requests.get(url=url)
        return(data.json())
    except json.decoder.JSONDecodeError:
        return None


def search_cve(search_term):
    url = r"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=%s" % search_term
    try:
        data = requests.get(url=url)
        return(data.json())
    except json.decoder.JSONDecodeError:
        return None


def print_cve(cve_id,cve):
    """ print the single cve data retrieved from NVD
    """
    try:
        item = cve['result']['CVE_Items']
    except KeyError:
        print('%s not found' % cve_id)
        exit()
    try:
        # CVSS v3
        print ("%s: CVSSv3 score: %s\nDescription: %s\n" % (cve_id, item[0]['impact']['baseMetricV3']['cvssV3']['baseScore'], item[0]['cve']['description']['description_data'][0]['value']))
    except KeyError:
        try:
            # CVSS v2
            print ("%s: CVSSv2 score: %s\nDescription: %s\n" % (item[0]['cve']['CVE_data_meta']['ID'], item[0]['impact']['baseMetricV2']['cvssV2']['baseScore'], item[0]['cve']['description']['description_data'][0]['value']))
        except KeyError:
            # no CVSS score
            print ("\t%s - %s: score: %s\n\tdescription: %s\n" % (cve_id, item[0]['cve']['CVE_data_meta']['ID'], 'NA', item[0]['cve']['description']['description_data'][0]['value']))
        except TypeError:
            print("print_cve: TypeError: data being assessed is %s" % item)


def report_findings(count, score, software_list_file, findings):
    """ simple report of CVE matches
    
        input [['string we searched for'][json data from NVD]]
        optional count and minimum score

    """
    #print("potential vulnerability findings for the items in %s file:" % software_list_file)
    print("************************************************************")
    for finding in findings:
        print("***** data for %s *****" % finding[0])
        for item in finding[1]['result']['CVE_Items']:
            if count > 0:
                try:
                    # CVSS v3
                    if score <= item['impact']['baseMetricV3']['cvssV3']['baseScore']:
                        print ("\t%s - %s: CVSSv3 score: %s\n\tdescription: %s\n" % (finding[0], item['cve']['CVE_data_meta']['ID'], item['impact']['baseMetricV3']['cvssV3']['baseScore'], item['cve']['description']['description_data'][0]['value']))
                        count -= 1
                except KeyError:
                    try:
                        # CVSS v2
                        if score <= item['impact']['baseMetricV2']['cvssV2']['baseScore']:
                            print ("\t%s - %s: CVSSv2 score: %s\n\tdescription: %s\n" % (finding[0], item['cve']['CVE_data_meta']['ID'], item['impact']['baseMetricV2']['cvssV2']['baseScore'], item['cve']['description']['ßdescription_data'][0]['value']))
                            count -= 1
                    except KeyError:
                        # no CVSS score
                        print ("\t%s - %s: score: %s\n\tdescription: %s\n" % (finding[0], item['cve']['CVE_data_meta']['ID'], 'NA', item['cve']['description']['description_data'][0]['value']))
                        count -= 1

        print("************************************************************")


def get_cpe_string(product_vendor, product_name, product_version):
    """ make this as a format string, with logic

        There are only 5 cases we support 
        x product_vendor product_name and product_version
        x product_vendor and product_name
        x product_name and product_version
        x product_name only
        x product_vendor only

    """
    cpe = ['']
    if product_vendor and product_name and product_version:
        cpe = [cpe[0] + product_vendor + ':' + product_name + ':' + product_version]
        return cpe      
    if product_vendor and product_name:
        cpe = [cpe[0] + product_vendor + ':' + product_name + ':*']
        return cpe
    if product_vendor:
        cpe = [cpe[0] + product_vendor + ':*:*']
        return cpe        
    if product_vendor == None and product_name and (product_version == None):
            cpe = [cpe[0] + '*:' + product_name + ':*']
            return cpe
    if product_vendor == None and product_name and product_version:
        cpe = [cpe[0] + '*:' + product_name + ':' + product_version]
        return cpe
    else:
        if product_vendor == None and product_name == None and product_version == None:
            cpe = [cpe[0] + '*:' + product_name + ':*']
            return cpe
    return None 

@click.command()
@click.option('--software_list_file', default='test/testlist.txt', help='input file that lists program name:version')
@click.option('--cve', help='CVE id to search NVD for')
@click.option('--product_vendor', help='name of vendor of program to search NVD for')
@click.option('--product_name', help='name of program to search NVD for')
@click.option('--product_version', help='version of program to search NVD for')
@click.option('--search_term', help='word or phrase you want to search NVD for')
@click.option('--count', default=20, help='maximum number of CVEs to list matches for')
@click.option('--score', default=0.0, help='minimum CVSS score to report')
def main(count, score, cve, product_vendor, product_name, product_version, search_term, software_list_file):
    """cve_query - check for CVE matches from a list in a file. Or check for a certain program, and version in NVD,  Optionally report for score greater than a provided value (0 to 9.9) and only report a certain number of CVEs per product.

    depends on internet access to https://services.nvd.nist.gov, if you need a proxy define:
    HTTP_PROXY, HTTPS_PROXY in your shell environment

Copyright 2020 Mark Menkhus, mark.menkhus@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
    """
    if cve:
        print_cve(cve,get_cve(cve))
        exit()
    if search_term:
        data = [(search_term,search_cve(search_term))]
        report_findings(count, score, search_term, findings=data)
        exit()
    if (product_vendor == None and product_name == None and product_version == None):
        cpes = open(software_list_file).readlines()
    else:
        cpes = get_cpe_string(product_vendor, product_name, product_version)
    findings_list = []
    no_findings_list = []
    findings = []
    #
    for cpe in cpes:
        cpe = cpe.rstrip('\r')
        cpe = cpe.rstrip('\n')
        if re.search(r'^#', cpe):
            continue
        if len(cpe.split(":")) == 3:
            cpe = "cpe:2.3:a:" + cpe + ":"
        elif len(cpe.split(':')) == 2:
            cpe = "cpe:2.3:a:*:" + cpe + ":"
        elif len(cpe.split(':')) == 1:
            cpe = "cpe:2.3:a:*:" + cpe + ":*:"
        print(r"searching NIST NVD for %s" % cpe)
        data = get_cpe_data(cpe)
        if data and data['totalResults'] > 0:
            findings_list.append(cpe)
            findings.append((cpe, data))
        else:
            no_findings_list.append(cpe)

    report_findings(count, score, software_list_file, findings)


if __name__ == "__main__":
    main()


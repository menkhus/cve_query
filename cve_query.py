#!/usr/bin/env python3
""" CVE search via NIST NVD CVE API

    input file is a text file with product:version info that works with
    CPE syntax to look for vulnerabilities

License:
All rights reserved.

Copyright 2020-2022 Mark Menkhus, mark.menkhus@gmail.com

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
from get_data_from_cve import nvd_findall as nvd_findall
import sys

__version__ = '1.0'

def get_cpe_data(cpe,debug):
    """ get data from NIST NVD API
        - match based on CPE uri of possibly vendor,program name, and version
        in the CPE URI
    """
    url = r"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=%s" % cpe
    try:
        if debug:
            print(url)
        data = nvd_findall(url)
        return data
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
    url = r"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=%s" % (search_term)
    try:
        data = nvd_findall(url)
        return data
    except json.decoder.JSONDecodeError:
        return None


def print_cve(cve_id,cve,raw):
    """ print the single cve data retrieved from NVD
    """
    if raw:
        print(cve)
        sys.exit()
    try:
        item = cve['result']['CVE_Items']
    except KeyError:
        print('%s not found' % cve_id)
        sys.exit()
    try:
        # CVSS v3
        print ("%s: CVSSv3 score: %s\nDescription: %s\nPublished_date: %s\n" % (cve_id, item[0]['impact']['baseMetricV3']['cvssV3']['baseScore'], item[0]['cve']['description']['description_data'][0]['value'],item[0]['publishedDate']
        ))
    except KeyError:
        try:
            # CVSS v2
            print ("%s: CVSSv2 score: %s\nDescription: %s\nPublished_date: %s\n" % (item[0]['cve']['CVE_data_meta']['ID'], item[0]['impact']['baseMetricV2']['cvssV2']['baseScore'], item[0]['cve']['description']['description_data'][0]['value'],item[0]['publishedDate']))
        except KeyError:
            # no CVSS score
            print ("\t%s - %s: score: %s\n\tdescription: %s\nPublished_date: %s\n" % (cve_id, item[0]['cve']['CVE_data_meta']['ID'], 'NA', item[0]['cve']['description']['description_data'][0]['value'],item[0]['publishedDate']))
        except TypeError:
            print("print_cve: TypeError: data being assessed is %s" % item)


def report_findings(raw, count, score, software_list_file, debug,findings):
    """ simple report of CVE matches
    
        input [['string we searched for'][json data from NVD]]
        optional count and minimum score

    """
    if raw:
        print(findings)
        sys.exit()
    print("-------------------------------------------------------------------")
    for finding in findings:
        for cve in finding:
            print("***** data for %s *****" % finding[0])
            try:
                for item in cve[1]['result']['CVE_Items']:
                    if count > 0:
                        try:
                            # CVSS v3
                            if score <= item['impact']['baseMetricV3']['cvssV3']['baseScore']:
                                print ("\t%s - %s: CVSSv3 score: %s\n\tdescription: %s\n\tPublished_date: %s\n" % (finding[0], item['cve']['CVE_data_meta']['ID'], item['impact']['baseMetricV3']['cvssV3']['baseScore'], item['cve']['description']['description_data'][0]['value'],item['publishedDate']))
                                count -= 1
                        except KeyError:
                            try:
                                # CVSS v2
                                if score <= item['impact']['baseMetricV2']['cvssV2']['baseScore']:
                                    print ("\t%s - %s: CVSSv2 score: %s\n\tdescription: %s\n\tPublished_date: %s\n" % (finding[0], item['cve']['CVE_data_meta']['ID'], item['impact']['baseMetricV2']['cvssV2']['baseScore'], item['cve']['description']['description_data'][0]['value'],item['publishedDate']))
                                    count -= 1
                            except KeyError:
                                # no CVSS score
                                # If there is a score limit passed in we are goint not print this CVE
                                if score > 0:
                                    continue
                                else:
                                    print ("\t%s - %s: score: %s\n\tdescription: %s\n\tPublished_date: %s\n" % (finding[0], item['cve']['CVE_data_meta']['ID'], 'NA', item['cve']['description']['description_data'][0]['value'],item['publishedDate']))
                                    count -= 1
            except Exception as oops:
                if debug:
                    print("report_findings: %s\n bad finding: %s\n " % (oops,finding))
                continue
            print("-------------------------------------------------------------------")


def get_cpe_string(product_vendor, product_name, product_version):
    """ make this as a format string, with logic

        There are only 6 cases we support 
        x product_vendor product_name and product_version
        x product_vendor and product_name
        x product_name and product_version
        x product_name only
        x product_vendor only
        x product_version only

    """
    cpe = ['']
    if product_vendor and product_name and product_version:
        cpe = [cpe[0] + product_vendor + ':' + product_name + ':' + product_version]
        return cpe      
    elif product_vendor and product_name:
        cpe = [cpe[0] + product_vendor + ':' + product_name + ':*']
        return cpe
    elif product_vendor:
        cpe = [cpe[0] + product_vendor + ':*:*']
        return cpe        
    elif product_vendor == None and product_name and (product_version == None):
            cpe = [cpe[0] + '*:' + product_name + ':*']
            return cpe
    elif product_vendor == None and product_name and product_version:
        cpe = [cpe[0] + '*:' + product_name + ':' + product_version]
        return cpe
    elif product_vendor == None and product_name == None and product_version:
        cpe = [cpe[0] + '*:' + '*:' + product_version]
        return cpe
    elif product_vendor and product_name == None and product_version:
        cpe = [cpe[0] + product_vendor +  '*:' + product_version]
        return cpe
    else:
        if product_vendor == None and product_name == None and product_version == None:
            return None
    return None 


@click.command()
@click.option('--CVE','-cve', help='CVE id to search NVD for')
@click.option('--product_vendor','-pv', help='name of vendor of program to search NVD for')
@click.option('--product_name','-pn', help='name of program to search NVD for')
@click.option('--product_version','-v', help='version of program to search NVD for')
@click.option('--search_term','-t', help='word or phrase you want to search NVD for')
@click.option('--count', '-c', default=20, help='maximum number of CVEs to list matches for')
@click.option('--score', '-s', default=0.0, help='minimum CVSS score to report')
@click.option('--debug', '-d', is_flag = True, help='enable debug output')
@click.option('--raw','-r', default=False, help='output the JSON data received from the request, must be True to enable')
@click.option('--software_list_file','-f', help="input file that lists work to do in form product:version")
def main(count, score, cve, product_vendor, product_name, product_version, search_term, software_list_file,debug,raw):
    """cve_query - check for CVE matches from a list in a file. Or check for a certain program, and version in NVD,  Optionally report for score greater than a provided value (0 to 9.9) and only report a certain number of CVEs per product.

    depends on internet access to https://services.nvd.nist.gov, if you need a proxy define:
    HTTP_PROXY, HTTPS_PROXY in your shell environment

Copyright 2021 Mark Menkhus, mark.menkhus@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
    """

    if debug == True:
        print('Debug enabled')
    else:
        debug = False

    if cve:
        print_cve(cve,get_cve(cve),raw)
        sys.exit()

    if search_term:
        data = [(search_term,search_cve(search_term))]
        report_findings(raw,count, score, search_term, debug,findings=data)
        sys.exit()

    if (product_vendor == None and product_name == None and product_version == None):
        if software_list_file == None:
            print("nothing requested, try again with --help")
            sys.exit()

    if software_list_file:
        cpes = ''
        try:
            cpes = open(software_list_file).readlines()
        except Exception as oops:
            print('main: %s: filename: %s' % (oops,software_list_file))
            sys.exit()

    cpes = get_cpe_string(product_vendor, product_name, product_version)
    findings_list = []
    no_findings_list = []
    findings = []

    if cpes == None:
        print("No CPE found")
        sys.exit()

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
        if debug:
            print (r"searching NIST NVD for %s" % cpe)
        data = get_cpe_data(cpe, debug)
        if len(data[0]) + int(data[0]['totalResults']) > 0:
            findings_list.append(cpe)
            findings.append((cpe, data))
        else:
            no_findings_list.append(cpe)

    report_findings(raw,count, score, software_list_file, debug, findings)


if __name__ == "__main__":
    main()


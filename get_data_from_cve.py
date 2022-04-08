#!/usr/bin/env python3
import json
import requests


def get_data(url):
    try:
        data = requests.get(url=url)
        data = data.json()
    except Exception as oops:
        print("get_data_from_cve: get_data: url: %s %s" % (url,oops))
        exit()
    return data


def get_item_count(data):
    cves = data['result']['CVE_Items']
    return len(cves)


def get_total_item_count(data):
    return data['totalResults']


def get_results_per_page(data):
    return data['resultsPerPage']


def nvd_findall(url):
    initial_offset = 0
    requested_number_of_items_per_page = 20
    count_items_received = 0
    initial_url = url + r'&startIndex=' + str(initial_offset) + r'&resultsPerPage=' + str(requested_number_of_items_per_page)
    #print("initial URL: %s" % initial_url)
    data_list = []
    data = get_data(initial_url)
    data_list.append(data)
    count_items_received += requested_number_of_items_per_page
    offset = initial_offset + requested_number_of_items_per_page
    
    while count_items_received != 0:
        frame_url = url + r'&startIndex=' + str(offset) + r'&resultsPerPage=' + str(requested_number_of_items_per_page)
        #print(" URL: %s" % frame_url)
        offset += requested_number_of_items_per_page
        data = get_data(frame_url)
        if get_item_count(data) != 0:
            data_list.append(data)
        count_items_received = get_item_count(data)
    
    return data_list


def main():
    """ general purpose CVE and CPE searcher

        input: is the complete URL for a search syntax
        function: make the URL search support getting all the possible information items.  
        returns: a list of returned CVE data complete as if received from NVD and json encoded into python dictionary/list form.  
    """
    # a couple of test examples
    url_search = r"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=%s" % "openssl"
    url_cpe = r"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=%s" % "cpe:2.3:a:apache:http_server:2.4.23"
    url_search_data = nvd_findall(url_search)
    print("openssl: frames: %s " % (len(url_search_data)))
    #for item in url_search_data:
    #    print(len(item['result']['CVE_Items']))
    cpe_data = nvd_findall(url_cpe)
    print("apache http_server 2.4.23: frames: %s" % (len(cpe_data)))
    #for item in cpe_data:
    #    print(len(item['result']['CVE_Items']))

if __name__ == '__main__':
    main()

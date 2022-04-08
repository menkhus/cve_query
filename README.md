# cve_query

  cve_query - check for CVE matches from a list in a file. Or check for a
  certain program, and version in NVD,  Optionally report for score greater
  than a provided value (0 to 9.9) and only report a certain number of CVEs
  per product.  

* depends on internet access to https://services.nvd.nist.gov, if you
need a proxy define:     HTTP_PROXY, HTTPS_PROXY in your shell
environment

  Copyright 2020-2022 Mark Menkhus, mark.menkhus@gmail.com

* Licensed under the Apache License, Version 2.0 (the "License"); you may
  not use this file except in compliance with the License. You may obtain a
  copy of the License at  

      <http://www.apache.org/licenses/LICENSE-2.0>

Options:
  -cve, --CVE TEXT               CVE id to search NVD for
  -pv, --product_vendor TEXT     name of vendor of program to search NVD for
  -pn, --product_name TEXT       name of program to search NVD for
  -v, --product_version TEXT     version of program to search NVD for
  -t, --search_term TEXT         word or phrase you want to search NVD for
  -c, --count INTEGER            maximum number of CVEs to list matches for
  -s, --score FLOAT              minimum CVSS score to report
  -d, --debug                    enable debug output
  -r, --raw BOOLEAN              output the JSON data received from the
                                 request, must be True to enable
  -f, --software_list_file TEXT  input file that lists work to do in form
                                 product:version
  --help                         Show this message and exit.


### tests are  in ./test
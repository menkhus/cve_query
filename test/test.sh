#!/bin/zsh
echo "testing vendor,product,version - apache http_server 2.4.23"
../cve_query.py --product_vendor apache --product_name http_server --product_version 2.4.23
if [ $? != 0 ]
then 
	echo "failed vendor product version test"
	exit
fi
echo "testing vendor,product - apache http_server"
../cve_query.py --product_vendor apache --product_name http_server
if [ $? != 0 ]
then 
	echo "failed vendor and product test"
	exit
fi
echo "testing vendor - apache"
../cve_query.py --product_vendor apache
if [ $? != 0 ]
then 
	echo "failed vendor only test"
	exit
fi
echo "testing product - http_server"
../cve_query.py --product_name http_server
if [ $? != 0 ]
then 
	echo "failed product onliy test"
	exit
fi
echo "testing input file - testlist.txt"
../cve_query.py --software_list_file testlist.txt
if [ $? != 0 ]
then 
	echo "failed input file test"
	exit
fi
echo "testing CVE search - CVE-2014-0160"
../cve_query.py -cve CVE-2014-0160
if [ $? != 0 ]
then 
	echo "failed input file test"
	exit
fi
echo "testing string search - HPE NonStop"
../cve_query.py --search_term "HPE NonStop"
if [ $? != 0 ]
then 
	echo "failed search term test"
	exit
fi
echo "testing complete"

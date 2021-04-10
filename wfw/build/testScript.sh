#!/usr/pkg/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
host=$1

[ $# -eq 0 ] && { echo "Usage: $0 hostname"; exit 1; }

udpTest1=$(nc -6 -v -w 1 -u  ${host} 13 2>&1 | grep -c '2020')

tcpTest=$(nc -6 -v -w 1 ${host} 13 2>&1 | grep -c 'failed')

udpTest2=$(nc -6 -v -w 1 -u ${host} 13 2>&1 | grep -c '2020')

if (( $udpTest1 != 0)) && (( $tcpTest != 0 )) && (( $udpTest2 == 0 ));
then
    echo -e "${GREEN}Success!${NC}"
    exit 0;
else 
    echo -e "${RED}Failure.${NC}"
    echo -e "First UDP Test had ${udpTest1} matches."
    echo -e "First TCP Test had ${tcpTest} matches."
    echo -e "Second UDP Test had ${udpTest2} matches."
    exit 1;
fi
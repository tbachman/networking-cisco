#!/bin/bash

echo "**** Running Tox tests ****"

tox
result=$?

echo "**** Getting Change Ids of all new gerrit reviews in progress ****"

New_Change_Ids=`ssh -p 29418 jenkins@cis-gerrit.cisco.com gerrit query --format=JSON status:new project:openstack-cisco-cpnrdhcp-driver | grep -o 'Change-Id: [[:alnum:]]*' | awk '{print $2}'`

echo "**** Adding each OpenStack CPNR developer as reviewer ****"

for Change_Id in $New_Change_Ids; do
    ssh -p 29418 jenkins@cis-gerrit.cisco.com gerrit set-reviewers \
    -a amccormi@cisco.com -a mcaulfie@cisco.com -a rajagast@cisco.com -a vhosakot@cisco.com $Change_Id
done

exit $result

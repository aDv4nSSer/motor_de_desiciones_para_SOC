#!/bin/bash
source /etc/duckdns/duck.conf
curl -sk "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=" -o /var/log/duckdns.log

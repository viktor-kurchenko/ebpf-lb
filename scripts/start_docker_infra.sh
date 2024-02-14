#!/bin/sh

LB_INTERFACE=${1:?"LB_INTERFACE is missing"} 
LB_PORT=${2:?"LB_PORT is missing"} 
BE_PORT=${3:?"BE_PORT is missing"} 

LB_IP=$(ip addr show $LB_INTERFACE | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
echo "LB IP: $LB_IP"

echo "Starting BE-1 ..."
docker run -e HTTP_PORT=$BE_PORT -h be-1 --name be-1 --rm -d -t mendhak/http-https-echo:31
BE1_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' be-1)
echo "BE-1 IP: $BE1_IP"

echo "Starting BE-2 ..."
docker run -e HTTP_PORT=$BE_PORT -h be-2 --name be-2 --rm -d -t mendhak/http-https-echo:31
BE2_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' be-2)
echo "BE-2 IP: $BE2_IP"

echo "Starting clients ..."
docker run --name cl-1 --rm -d -it nicolaka/netshoot /bin/bash
docker run --name cl-2 --rm -d -it nicolaka/netshoot /bin/bash

echo "Preparing LB config ..."
rm -f config.yaml
yq eval ".lb = {\"ip\": \"$LB_IP\", \"port\": $LB_PORT}" config_template.yaml > config.yaml 
yq eval ".backends += [{\"ip\": \"$BE1_IP\", \"port\": $BE_PORT}]" -i config.yaml
yq eval ".backends += [{\"ip\": \"$BE2_IP\", \"port\": $BE_PORT}]" -i config.yaml

echo "Done!"

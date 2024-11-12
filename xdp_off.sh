#!/bin/bash

NETWORK_INTERFACE="ens33"        
sudo ip link set dev $NETWORK_INTERFACE xdpgeneric off
#!/bin/bash
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8000
echo "https://$(hostname -I)"

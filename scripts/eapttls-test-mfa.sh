#!/bin/bash

read -p "Username: " USERNAME
read -s -p "Password (include the 6-digit OTP at the end, no separator): " FULLPASSWORD
echo

eapol_test -c <(cat << EOF
network={
    eap=TTLS
    phase2="auth=PAP"
    identity="${USERNAME}"
    anonymous_identity="anonymous"
    password="${FULLPASSWORD}"
    ca_cert="/etc/freeradius/3.0/certs/ca.pem"
}
EOF
) -a 127.0.0.1 -p 1812 -s testing123

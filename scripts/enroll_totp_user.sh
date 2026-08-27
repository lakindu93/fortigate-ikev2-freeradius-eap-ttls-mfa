#!/bin/bash

read -rp "Enter username: " USERNAME

ISSUER="DEMO-VPN"

sudo mkdir -p /etc/freeradius/3.0/mods-config/python3/otp_secrets

SAFE_USERNAME=$(echo "$USERNAME" | sed 's/[^A-Za-z0-9_.-]/_/g')

SECRET=$(python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))')

SECRET_FILE="/etc/freeradius/3.0/mods-config/python3/otp_secrets/${SAFE_USERNAME}.secret"

echo "$SECRET" | sudo tee "$SECRET_FILE" > /dev/null

sudo chmod 600 "$SECRET_FILE"
sudo chown freerad:freerad "$SECRET_FILE"

OTPAUTH_URI="otpauth://totp/${ISSUER}:${USERNAME}?secret=${SECRET}&issuer=${ISSUER}&digits=6&period=30"

echo
echo "OTP secret created successfully."
echo "Username: $USERNAME"
echo "Secret file: $SECRET_FILE"
echo
echo "Scan the following QR code with your authenticator app:"
echo

qrencode -t ANSIUTF8 "$OTPAUTH_URI"

echo
echo "OTP Auth URI:"
echo "$OTPAUTH_URI"

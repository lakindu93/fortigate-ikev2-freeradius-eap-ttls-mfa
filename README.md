# FortiGate IKEv2 IPsec VPN with FreeRADIUS EAP-TTLS and MFA

![FortiGate](https://img.shields.io/badge/FortiGate-IPsec%20VPN-red)
![FreeRADIUS](https://img.shields.io/badge/FreeRADIUS-EAP--TTLS-blue)
![IKEv2](https://img.shields.io/badge/IKEv2-IPsec-orange)
![MFA](https://img.shields.io/badge/MFA-TOTP-green)
![Asgardeo](https://img.shields.io/badge/Asgardeo-Identity%20Platform-purple)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A reference implementation for integrating a **FortiGate IKEv2 IPsec dial-up VPN** with **FreeRADIUS EAP-TTLS/PAP**, **WSO2 Identity Platform (Asgardeo)**, and **Google Authenticator-compatible TOTP MFA**.

This project provides the FreeRADIUS configuration, Python-based authentication policy engine, TOTP validation, group mapping, and helper scripts required to build a layered VPN authentication solution.

> 📖 **For the complete step-by-step implementation guide, configuration details, screenshots, and troubleshooting, see the full article on SysOps Technix:**
>
> **[Secure FortiGate IPsec Dial-Up VPN with FreeRADIUS EAP-TTLS Authentication](https://sysopstechnix.com/fortigate-ipsec-dial-up-vpn-with-freeradius/)**

---

## Overview

This project demonstrates how to build a secure remote-access VPN architecture using:

- **FortiGate** as the IKEv2/IPsec VPN gateway
- **FreeRADIUS 3.x** as the RADIUS and EAP-TTLS authentication server
- **EAP-TTLS/PAP** for protected inner authentication
- **WSO2 Identity Platform (Asgardeo)** for password validation and group information
- **Google Authenticator-compatible TOTP** for multi-factor authentication
- **Python 3** for custom authentication and authorization logic
- **FortiGate group-based authorization** based on the user's Asgardeo group

The implementation separates VPN connectivity, credential protection, identity validation, MFA, and authorization into distinct components.

---

## Architecture

```text
┌─────────────────────┐
│     FortiClient     │
│   Windows / macOS   │
└──────────┬──────────┘
           │
           │ IKEv2 / IPsec
           │
           ▼
┌─────────────────────┐
│      FortiGate      │
│   VPN Gateway       │
└──────────┬──────────┘
           │
           │ RADIUS
           │ EAP-TTLS
           ▼
┌─────────────────────┐
│     FreeRADIUS      │
│                     │
│   EAP-TTLS / PAP    │
│   Python Policy     │
└──────┬─────────┬────┘
       │         │
       │         │ TOTP validation
       │         ▼
       │   ┌─────────────────────┐
       │   │ Google Authenticator│
       │   │       (TOTP)        │
       │   └─────────────────────┘
       │
       │ OAuth2 / UserInfo
       ▼
┌─────────────────────┐
│       Asgardeo      │
│ WSO2 Identity       │
│ Platform            │
└─────────────────────┘

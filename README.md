# FortiGate IKEv2 IPsec VPN with FreeRADIUS EAP-TTLS and MFA

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

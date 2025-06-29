# <p align="center"> Mobile App Threat Modelling - PASTA </p>

## Project Overview

I simulated the role of a cybersecurity professional at a company that serves sneaker enthusiasts and collectors. The business is preparing to launch a mobile app that makes it easy for their customers to buy and sell shoes. I used PASTA  (Process for Attack Simulation and Threat Analysis) framework to identify and assess security risks associated with the app prior to its release.


## Scenario

Description of why the sneaker company decided to develop this new app:

Our application should seamlessly connect sellers and shoppers. It should be easy for users to sign-up, log in, and manage their accounts. Data privacy is a big concern for us. We want users to feel confident that we're being responsible with their information.

Buyers should be able to directly message sellers with questions. They should also have the ability to rate sellers to encourage good service. Sales should be clear and quick to process. Users should have several payment options for a smooth checkout process. Proper payment handling is really important because we want to avoid legal issues.

App Components:
Application programming interface (API): An API is a set of rules that define how software components interact with each other. In application development, third-party APIs are commonly used to add functionality without having to program it from scratch.

Public key infrastructure (PKI): PKI is an encryption framework that secures the exchange of online information. The mobile app uses a combination of symmetric and asymmetric encryption algorithms: AES and RSA. AES encryption is used to encrypt sensitive data, such as credit card information. RSA encryption is used to exchange keys between the app and a user's device.

SHA-256: SHA-256 is a commonly used hash function that takes an input of any length and produces a digest of 256 bits. The sneaker app will use SHA-256 to protect sensitive user data, like passwords and credit card numbers.

Structured query language (SQL): SQL is a programming language used to create, interact with, and request information from a database. For example, the mobile app uses SQL to store information about the sneakers that are for sale, as well as the sellers who are selling them. It also uses SQL to access that data during a purchase.

---

## Process

### Business & Security Objectives

**Business objectives:**
- Provide seamless user experience: registration, messaging, listings, and checkout
- Ensure ease of use and build trust with users

**Security objectives:**
- Ensure data privacy and secure payment handling
- Comply with regulations such as PCI DSS
- Avoid legal liabilities from data breaches

### Technical Scope

Technologies used in the app:
- APIs (internal & third-party)
- PKI (RSA/AES)
- SHA-256
- SQL

**Primary Focus:** APIs are critical because they facilitate interactions between users, third-party services, and internal components. This makes them a high-priority security concern.

### Application Decomposition

**Potential Attack Vectors or Processes:** 
1. User authentication & registration
2. User profile management
3. Product listing management
4. Product search
5. Transaction processing (via third-party API)
6. Messaging system
7. Rating system
8. Audit trail
9. Third-party API session token

**Databases & Key Data Elements:**
1. User_DB: Buyer/seller credentials, PII (hashed passwords)
2. Product_DB: Sneaker listings, seller data
3. Transaction_DB: Payment records, PCI data (AES encrypted)
4. Message_DB: Buyer-Seller communications
5. Rating_DB: Seller and product ratings
6. Database_Logs: Audit logs


**Data Flows:**
```
Users/Sellers ↔ Mobile App Interface
                     ↓
    ├── Login Query ↔ User_DB
    ├── Search Query ↔ Product_DB  
    ├── Insert/Update Query ↔ Product_DB
    ├── Transaction API ↔ [Third-Party Payment API] ↔ Banking Network
    │         ↓
    │   Transaction_DB + Product_DB + UserDB
    │
    ├── Messaging Query ↔ Message_DB
    └── Rating Query ↔ Rating_DB

All SQL Queries → Database_Logs (audit trail) → Security Team
```

### Threat Analysis

- Unauthorized access to user data or private messages via injection, session hijacking, brute force, or stolen credentials
- Data breaches exposing PII or PCI data
- Third-party API risks (token leakage, insecure integration)

Note: The mobile app uses API tokens (e.g., OAuth2 access tokens) for authentication. These differ from traditional session tokens, which are typically stored in cookies in web apps.

### Vulnerability Analysis

- Unsanitized input, weak input validation
- Misconfigured or leaked API token
- Weak password policy
- Insufficient authentication mechanisms
- Excessive database privileges

### Attack modelling

**Attack Tree: Unauthorized Access to User Data**
```
Goal: Access Sensitive User Data
├── Injection Attacks
│   ├── Search Field Injection
│   └── Login Bypass  
├── API Token Theft (Session Hijacking)
│   ├── Insecure token storage on device
│   ├── Logs or crash reports exposing tokens
│   └── Lack of token expiration or rotation
├── Third-Party API Exploits
│   ├── Misconfigured or leaked API token
│   └── Vulnerable third-party integrations
└── Authentication & Authorization Attacks
    ├── Brute Force Login (weak passwords, no account lockout)
    ├── Social engineering
    └── Misconfigured access permissions (no RBAC)
```

### Risk Analysis & Management

**Risk Assessment:**
- **Critical**: Injection attacks → PCI data breach, legal exposure
- **High**: Session hijacking, phishing, API token compromise → Account takeover, financial loss, loss of user trust
- **Medium**: Excessive privileges → Internal data exposure

**Security Controls:**
- **Injection Prevention**: Use prepared statements,input validation, output encoding. Use web app firewall (WAF)
- **Session Security**: Enforce short-lived, securely stored session tokens. Validate and rotate API tokens.
- **Authentication**: Enforce strong passwords, MFA, and provide phishing awareness training
- **Access Control**: EnforceRBAC with least privilege principles
- **Monitoring**: Enable real-time threat detection, logging, and incident response.

---

## Summary

By applying the PASTA methodology, I identified critical threats to the mobile app before release. The most significant risks stemmed from injection vulnerabilities, insecure token handling, and weak authentication or access controls.

Proper encryption, secure token handling, strict authentication, and role-based access control are essential to minimize risk and maintain user trust.

---

## Notes

- Avoid SHA-256 for password storage; use slower password hashing algorithms bcrypt, scrypt, or Argon2 for stronger protection
- Sensitive data like credit card numbers should be encrypted instead of hashed, and ensure secure key storage.
- Perform regular security audits and pentesting, especially on third-party APIs.

---
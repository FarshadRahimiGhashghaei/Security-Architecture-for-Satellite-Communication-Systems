# Satellite Communication System Security Architecture Simulation


## Authors

- Farshad Rahimi Ghashghaei
- Yonghao Wang
- Mohammad Shojafar
- De Mi
- Yussuf Ahmed

## Affiliations

- Farshad Rahimi Ghashghaei, Yonghao Wang, De Mi, and Yussuf Ahmed: School of Computing and Digital Technology, Birmingham City University, Birmingham, United Kingdom
- Mohammad Shojafar: Institute for Communication Systems, University of Surrey, Guildford GU2 7XH, United Kingdom

## Overview

The main components of the simulation include:

1. RSA Encryption and Decryption
2. Quantum Key Distribution
3. User Roles and Permissions
4. Network Segments
5. Satellite and Ground Station Communication
6. Threat Detection
7. Multi-Factor Authentication
8. Incident Response

## Code Explanation

### RSA Encryption and Decryption

The RSAEncryption class handles RSA encryption and decryption using public and private keys.

### Quantum Key Distribution

The QKD class simulates QKD key generation between satellites and ground stations. It generates random qubits and bases, and matches them to produce a shared key.

### User Roles and Permissions

Roles (`admin`, `user`, `guest`) are defined with specific permissions. Users are assigned roles and MFA status.

### Network Segments

Network segments (`public`, `internal`, `sensitive`) restrict access based on user roles. Traffic is logged if users have the appropriate permissions.

### Satellite and Ground Station Communication

Satellites establish secure communication channels with ground stations using either QKD or RSA. Data is transmitted securely, and decrypted at the receiving end.

### Threat Detection

The ThreatDetection class identifies unauthorized access attempts and logs them as threats.

### Multi-Factor Authentication (MFA)

The MFA class simulates MFA for users. Only users with MFA enabled can authenticate successfully.

### Incident Response

The IncidentResponse class responds to detected threats and logs incidents.

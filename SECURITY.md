# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

The security of our project is a top priority. If you believe you have found a security vulnerability, please follow these steps:

1. **Do Not** disclose the vulnerability publicly
2. **Do Not** open a public issue on GitHub
3. Email us directly at [your-security-email@example.com] with details about the vulnerability
4. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix, if available

## What to Expect

Once you've submitted a vulnerability report, here's our process:

1. We will acknowledge receipt of your report within 48 hours
2. We will work to confirm the vulnerability and determine its impact
3. We will develop and test a fix
4. We will release a security update
5. We will publicly acknowledge your responsible disclosure (unless you prefer to remain anonymous)

## Security Best Practices

When deploying this software:

1. Always run the latest version with security updates
2. Follow the principle of least privilege when setting up service accounts
3. Regularly audit access to the system
4. Enable proper network security controls
5. Keep all dependencies up to date
6. Consider network segmentation to isolate the router/firewall system

## Security Features

This router/firewall distribution includes several security features:

- IDS/IPS capabilities via Suricata
- Network behavioral analysis via Zeek
- Immutable base operating system (Talos Linux)
- Container isolation for network services
- Automatic security updates
- Comprehensive logging for security auditing

Thank you for helping keep our project secure!
# Takeover Triage Architecture

## Overview

Takeover Triage is designed around a **Three-Gate Verification System** to reduce false positives during subdomain takeover assessment.

Unlike traditional fingerprint-only scanners, the tool validates multiple conditions before recommending manual verification.

---

# Workflow

```
                User Input
                     │
                     ▼
            Hostname Validation
                     │
                     ▼
             DNS Resolution
                     │
                     ▼
           CNAME / NS Analysis
                     │
                     ▼
      Service Identification Engine
                     │
                     ▼
          HTTP Response Analysis
                     │
                     ▼
      Fingerprint Verification
                     │
                     ▼
        Three-Gate Verification
                     │
                     ▼
          Final Classification
```

---

# Three-Gate Verification

## Gate 1 — Third-Party Service Detection

The tool determines whether the hostname ultimately points to a supported third-party provider.

Examples include:

* AWS S3
* Azure Storage
* Azure App Service
* Azure Traffic Manager
* GitHub Pages
* Netlify
* WP Engine
* Heroku

If no supported service is detected:

```
Verdict:
DEAD
```

---

## Gate 2 — Resource State Validation

The tool determines whether the backing resource still exists.

Validation methods include:

* DNS resolution
* NXDOMAIN detection
* HTTP fingerprint analysis
* Service-specific logic

Examples

AWS S3

```
NoSuchBucket
```

Azure Storage

```
Requires NXDOMAIN
```

GitHub Pages

```
There isn't a GitHub Pages site here
```

If the resource still exists:

```
Verdict:
DEAD
```

---

## Gate 3 — Claimability

Automation cannot reliably determine whether every provider allows re-registration.

Instead, the tool provides guidance for manual verification.

Possible outcomes:

```
CONFIRM_MANUALLY
```

or

```
NEEDS_CARE
```

depending on the provider.

---

# Detection Pipeline

```
Input
   │
   ▼
Hostname Validation
   │
   ▼
DNS Lookup
   │
   ▼
CNAME Chain
   │
   ▼
Provider Detection
   │
   ▼
HTTP Request
   │
   ▼
Fingerprint Matching
   │
   ▼
Three-Gate Verification
   │
   ▼
Final Verdict
```

---

# Verdicts

## CONFIRM_MANUALLY

High-confidence candidate.

Automation indicates:

* Third-party service
* Backing resource removed
* Service appears claimable

Manual verification is required.

---

## NEEDS_CARE

Potential takeover candidate.

Additional provider-specific verification is recommended.

---

## DEAD

No evidence of a takeover opportunity.

Examples include:

* Live resource
* Unsupported provider
* Protected service
* Ownership verification
* Resolution inconclusive

---

# Design Philosophy

Takeover Triage prioritizes **accuracy over volume**.

Rather than generating a large number of potential findings, the goal is to minimize false positives by validating each candidate through multiple independent checks.

The scanner is intended to assist security researchers during authorized security testing and should not be considered proof of exploitability without manual confirmation.

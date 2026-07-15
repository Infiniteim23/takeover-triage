# Supported Providers

This document describes how Takeover Triage evaluates supported services and explains the conditions required before a finding is classified as **CONFIRM_MANUALLY**.

> **Important**
>
> A fingerprint match alone is **not** considered evidence of a subdomain takeover. Takeover Triage combines DNS analysis, service-specific behavior, and provider-aware logic to reduce false positives.

---

# Verification Levels

| Status       | Meaning                                                                                                  |
| ------------ | -------------------------------------------------------------------------------------------------------- |
| ✅ Vulnerable | Service is generally claimable if the backing resource has been removed.                                 |
| ⚠️ Edge Case | Additional provider-specific validation is required.                                                     |
| ❌ Protected  | Modern ownership verification or infrastructure protections prevent takeover under normal circumstances. |

---

# Amazon Web Services (AWS)

## Amazon S3

**Detection**

* `*.s3.amazonaws.com`
* `*.s3-<region>.amazonaws.com`

**Gate 2**

Requires one of the following:

* `NoSuchBucket`
* `The specified bucket does not exist`

**Status**

✅ Vulnerable

---

## Elastic Beanstalk

**Detection**

* `*.elasticbeanstalk.com`

**Gate 2**

Requires:

* NXDOMAIN

**Status**

✅ Vulnerable

---

# Microsoft Azure

## Azure App Service

**Detection**

* `*.azurewebsites.net`

**Gate 2**

Requires:

* NXDOMAIN

HTTP errors alone are not sufficient.

**Status**

✅ Vulnerable

---

## Azure Blob Storage

**Detection**

* `*.blob.core.windows.net`

**Gate 2**

Requires:

* NXDOMAIN

**Status**

✅ Vulnerable

---

## Azure Static Website

**Detection**

* `*.web.core.windows.net`

**Gate 2**

Requires:

* NXDOMAIN

The response:

```
The requested content does not exist
```

does **not** indicate a takeover by itself. It usually means the Storage Account still exists but the requested website content is missing.

**Status**

✅ Vulnerable (only when the Storage Account no longer exists)

---

## Azure Traffic Manager

**Detection**

* `*.trafficmanager.net`

**Gate 2**

Requires:

* NXDOMAIN

If DNS still resolves, the Traffic Manager profile is considered active.

**Status**

✅ Vulnerable

---

## Azure API Management

**Detection**

* `*.azure-api.net`

**Gate 2**

Requires:

* NXDOMAIN

**Status**

✅ Vulnerable

---

## Azure Cloud Service (Classic)

**Detection**

* `*.cloudapp.net`

**Gate 2**

Requires:

* NXDOMAIN

**Status**

✅ Vulnerable

---

## Azure Front Door

**Detection**

* `*.azurefd.net`

Modern Azure Front Door deployments use randomly generated endpoint names and ownership verification.

**Status**

❌ Protected

---

# GitHub

## GitHub Pages

**Detection**

* `*.github.io`

**Gate 2**

Typical fingerprint:

```
There isn't a GitHub Pages site here
```

**Status**

✅ Vulnerable

---

# Netlify

## Netlify

**Detection**

* `*.netlify.app`

Typical fingerprint:

```
Site not found
```

**Status**

✅ Vulnerable

---

# Heroku

## Heroku

**Detection**

* `*.herokuapp.com`
* `*.herokudns.com`

Typical fingerprint:

```
No such app
```

Provider restrictions may prevent successful claiming.

**Status**

⚠️ Edge Case

---

# Shopify

## Shopify

Typical fingerprint:

```
Sorry, this shop is currently unavailable
```

Modern ownership verification may prevent takeover.

**Status**

⚠️ Edge Case

---

# WP Engine

## WP Engine

Typical fingerprint:

```
Site not available
```

Manual verification required.

**Status**

✅ Vulnerable

---

# Pantheon

## Pantheon

Typical fingerprint:

```
404 Page Not Found
```

**Status**

✅ Vulnerable

---

# Ghost

## Ghost(Pro)

Typical fingerprint:

```
Site not found
```

**Status**

✅ Vulnerable

---

# Readme.io

Typical fingerprint:

```
Project doesn't exist... yet!
```

**Status**

✅ Vulnerable

---

# Cargo

Typical fingerprint:

```
404 Not Found
```

**Status**

✅ Vulnerable

---

# Tumblr

Typical fingerprint:

```
Whatever you were looking for doesn't currently exist
```

**Status**

✅ Vulnerable

---

# WordPress.com

Typical fingerprint:

```
Do you want to register...
```

**Status**

✅ Vulnerable

---

# Wasabi

Typical fingerprint:

```
NoSuchBucket
```

**Status**

✅ Vulnerable

---

# SendGrid

Requires:

* NXDOMAIN

**Status**

✅ Vulnerable

---

# Unbounce

Typical fingerprint:

```
Page Not Found
```

**Status**

✅ Vulnerable

---

# Surge.sh

Typical fingerprint:

```
project not found
```

**Status**

✅ Vulnerable

---

# Protected Providers

The following providers implement ownership verification or infrastructure protections that generally prevent classic subdomain takeover attacks.

| Provider                | Status      |
| ----------------------- | ----------- |
| Azure Front Door        | ❌ Protected |
| Fastly                  | ❌ Protected |
| Cloudflare              | ❌ Protected |
| Zendesk                 | ❌ Protected |
| Akamai CDN              | ❌ Protected |
| Google Workspace (GHS)  | ❌ Protected |
| Azure Application Proxy | ❌ Protected |
| Microsoft Edge CDN      | ❌ Protected |

---

# Edge Cases

The following services may still require provider-specific validation before a takeover can be confirmed.

| Provider                   | Status       |
| -------------------------- | ------------ |
| Heroku                     | ⚠️ Edge Case |
| Shopify                    | ⚠️ Edge Case |
| CloudFront                 | ⚠️ Edge Case |
| Salesforce Marketing Cloud | ⚠️ Edge Case |

---

# Detection Philosophy

Takeover Triage is designed to prioritize **accuracy over volume**.

Instead of reporting every matching fingerprint as a vulnerability, each candidate passes through a structured verification process:

1. **Gate 1** — Confirm the hostname points to a supported third-party provider.
2. **Gate 2** — Verify that the backing resource has actually been removed using DNS state, HTTP fingerprints, and service-specific logic.
3. **Gate 3** — Recommend manual verification only when the resource appears claimable.

This approach significantly reduces false positives while providing actionable guidance for authorized security testing.

# HDWebmobile Social Login

"Continue with Google" login and signup for WooCommerce -- every identity token is cryptographically verified before any account is ever touched.

- **WordPress.org:** https://wordpress.org/plugins/hdwebmobile-social-login/
- **Requires:** WordPress 6.9+, WooCommerce, PHP 7.4+
- **License:** GPLv2 or later

## Description

HDWebmobile Social Login adds a "Continue with Google" button to your WooCommerce login and registration forms, alongside the normal password login. Customers can sign up or sign back in with one click, without typing a password.

## Why this plugin exists

A competing WooCommerce social-login plugin had a critical authentication-bypass vulnerability (CVE-2026-8457, CVSS 9.8): its "Sign in with Apple" handler read the email address out of the identity token and logged the visitor straight in as the matching WordPress account -- without ever verifying the token's digital signature against Apple's public keys. An attacker could hand-craft a token claiming to be any email address, including an administrator's, and be logged in with zero credentials and zero existing access. This plugin closes that entire vulnerability class by construction:

* Every Google identity token is cryptographically verified against Google's own, currently-published public keys (fetched live from Google's own JWKS endpoint, never hardcoded or stale) before a single claim inside it is trusted -- the exact check the vulnerable plugin skipped.
* Algorithm, issuer, audience (this site's own Client ID), expiry, and Google's own "email verified" flag are all independently checked. Any single failure rejects the token completely.
* A returning visitor is matched only by Google's own permanent account id (`sub`) in a dedicated, uniquely-constrained database table -- never by email.
* If a WordPress account already exists with the same email as a first-time Google sign-in, this plugin does not auto-link or log in -- the visitor is asked to log in with their password first and connect Google from My Account, an explicit, already-authenticated opt-in action.
* The login endpoint is protected against forged cross-site submissions using Google's own documented double-submit cookie check.

## Features

* "Continue with Google" button on the WooCommerce login page
* New visitors get a real WooCommerce customer account created automatically
* Existing customers can connect or disconnect Google from My Account > Account details
* Zero third-party libraries -- RS256 signature verification is done with PHP's own OpenSSL functions

## Limitations (v1)

* Google only -- no Facebook, Apple, or other providers
* Requires a free Google OAuth Client ID from Google Cloud Console

## Installation

1. Upload the plugin to `/wp-content/plugins/hdwebmobile-social-login`, or install through the WordPress plugins screen.
2. Activate the plugin. WooCommerce must already be installed and active.
3. Under WooCommerce > HDWebmobile > Social Login, create a Google OAuth Client ID as instructed and paste it in.

## License

GPLv2 or later. See [LICENSE](LICENSE).

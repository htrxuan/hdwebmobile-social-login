=== HDWebmobile Social Login ===
Contributors: htrxuan
Donate link: https://paypal.me/htrxuan/20
Tags: woocommerce, login, google, social login, sign in with google
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
Requires Plugins: woocommerce
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

"Continue with Google" login and signup for WooCommerce -- every identity token is cryptographically verified before any account is ever touched.

== Description ==

HDWebmobile Social Login adds a "Continue with Google" button to your WooCommerce login and registration forms, alongside the normal password login. Customers can sign up or sign back in with one click, without typing a password.

= Why this plugin exists =
A competing WooCommerce social-login plugin had a critical authentication-bypass vulnerability (CVE-2026-8457, CVSS 9.8): its "Sign in with Apple" handler read the email address out of the identity token and logged the visitor straight in as the matching WordPress account -- without ever verifying the token's digital signature against Apple's public keys. An attacker could hand-craft a token claiming to be any email address, including an administrator's, and be logged in with zero credentials and zero existing access. This plugin closes that entire vulnerability class by construction, not by a bolted-on check:

* Every Google identity token is cryptographically verified against Google's own, currently-published public keys (fetched live from Google's own JWKS endpoint, never hardcoded or stale) before a single claim inside it is trusted -- the exact check the vulnerable plugin skipped.
* The token's algorithm, issuer, audience (this site's own Client ID), expiry, and Google's own "email verified" flag are all independently checked. Any single failure rejects the token completely -- there is no partial-trust fallback.
* A returning visitor is matched only by Google's own permanent account id (`sub`) in a dedicated, uniquely-constrained database table -- never by email -- so a raw email match can never silently attach a login to an account it doesn't belong to.
* If a WordPress account already exists with the same email as a first-time Google sign-in, this plugin does not auto-link or log in -- the visitor is asked to log in with their password first and connect Google from My Account, an explicit, already-authenticated opt-in action.
* The login endpoint itself is protected against forged cross-site submissions using Google's own documented double-submit cookie check, matching Google's official implementation guidance.

= Key Features =
* "Continue with Google" button on the WooCommerce login page, next to the normal password form
* New visitors get a real WooCommerce customer account created automatically on first sign-in
* Existing customers can connect or disconnect Google from My Account > Account details
* Zero third-party libraries -- token signature verification is done with PHP's own OpenSSL functions

= Limitations (please read before installing) =
* Google only in this version -- no Facebook, Apple, or other providers
* Requires a free Google OAuth Client ID from Google Cloud Console (a few minutes of one-time setup)

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/hdwebmobile-social-login` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress. WooCommerce must already be installed and active.
3. Under WooCommerce > HDWebmobile > Social Login, create a Google OAuth Client ID as instructed and paste it in.

== How to Use ==

= 1. Get a Google Client ID =
Visit Google Cloud Console's Credentials page, create an OAuth 2.0 Client ID (Web application), and add your site's home URL and the shown redirect URL as authorized origins.

= 2. Configure the plugin =
Paste the Client ID into WooCommerce > HDWebmobile > Social Login and save.

= 3. Customers sign in =
The "Continue with Google" button now appears on your My Account login page.

== Screenshots ==

1. The "Continue with Google" button on the My Account login page.
2. The Social Login settings tab under WooCommerce > HDWebmobile.
3. The Connected Accounts section under My Account > Account details.

== Changelog ==

= 1.0.0 =
* Initial release: Google Sign In with full cryptographic identity-token verification, opt-in account linking, My Account connect/disconnect.

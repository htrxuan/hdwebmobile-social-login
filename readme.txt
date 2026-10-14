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

= Security by design =
The most dangerous mistake a social login can make is reading the email address out of an identity token and logging the visitor straight in as the matching WordPress account -- without ever verifying the token's digital signature against the identity provider's public keys (CWE-347). An attacker could hand-craft a token claiming to be any email address, including an administrator's, and be logged in with zero credentials. This plugin closes that entire vulnerability class by construction, not by a bolted-on check:

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

= Enjoying this plugin? =
If it helps your site, please consider [leaving an honest review on WordPress.org](https://wordpress.org/support/plugin/hdwebmobile-social-login/reviews/#new-post) -- it helps other WordPress users find it. Found a problem or have an idea? Please [open a support topic](https://wordpress.org/support/plugin/hdwebmobile-social-login/) first so it can be fixed.

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

== External services ==

This plugin connects to Google's sign-in service ("Sign in with Google" / Google Identity Services) to let customers log in or register with their Google account. Nothing is sent to Google until the site owner has entered their own Google OAuth Client ID in the plugin settings.

* **Google Identity Services client script** (`https://accounts.google.com/gsi/client`) is loaded in the visitor's browser on the WooCommerce My Account page, to show the "Continue with Google" button. When a visitor clicks it, Google handles the sign-in and returns a signed identity token (containing the visitor's Google account id, name, email address and email-verified status) to this site. Loading the script also sends Google the usual browser request data (such as IP address and user agent).
* **Google's public signing keys** (`https://www.googleapis.com/oauth2/v3/certs`) are fetched by the server to verify that identity token's signature. This request sends no visitor or site data; the keys are cached according to Google's own cache headers.

This service is provided by Google LLC: [Terms of Service](https://policies.google.com/terms), [Privacy Policy](https://policies.google.com/privacy).

== Screenshots ==

1. The "Continue with Google" button on the My Account login page.
2. The Social Login settings tab under WooCommerce > HDWebmobile.
3. The Connected Accounts section under My Account > Account details.

== Changelog ==

= 1.0.0 =
* Initial release: Google Sign In with full cryptographic identity-token verification, opt-in account linking, My Account connect/disconnect.

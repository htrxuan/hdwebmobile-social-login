<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Receives Google's Sign In button POST (`admin-post.php?action=hdsl_google_login`), verifies
 * it end-to-end, and is the ONLY place a session is ever created from a social login. Nothing
 * here trusts a claim before HDSL_JWT_Verifier has cryptographically checked it -- see that
 * class for the CVE-2026-8457 details.
 *
 * Account-linking policy (deliberately stricter than "log in whoever has this verified
 * email", which is itself a real, separate risk class beyond the literal CVE -- an email
 * address can be reused/reassigned over time, or a store admin may have created a local
 * account for a customer using an email that customer doesn't yet control on Google):
 *
 *  - Returning visitor: matched ONLY by (provider, subject_id) in HDSL_Repository -- never by
 *    email. A returning visitor is logged into the exact account they previously linked.
 *  - First time this Google account has ever been seen, and no WordPress user exists with
 *    that verified email either: a brand new customer account is created and immediately
 *    linked to that Google subject_id.
 *  - First time this Google account has been seen, but a WordPress user ALREADY exists with
 *    that email: this plugin does NOT auto-link or log the visitor into that existing
 *    account. It is shown a message to log in normally first and link Google from My Account
 *    (class-hdsl-myaccount.php) -- an explicit, already-authenticated opt-in action, closing
 *    the account-takeover-by-email-collision risk that a naive "verified email = same person"
 *    assumption would otherwise reopen.
 */
class HDSL_Auth
{
    private static $instance = null;

    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        add_action('admin_post_hdsl_google_login', array($this, 'handle_login'));
        add_action('admin_post_nopriv_hdsl_google_login', array($this, 'handle_login'));
    }

    public function handle_login()
    {
        $client_id = get_option('hdsl_google_client_id', '');
        if (!$client_id) {
            $this->fail(__('Google Sign In is not configured on this site.', 'hdwebmobile-social-login'));
        }

        // Google's own documented CSRF protection for this exact POST flow: a random value is
        // set in a first-party cookie when the button renders, and Google echoes the same
        // value back in the POST body. The two must match exactly, or this request did not
        // originate from Google's own button on this page.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- this endpoint is verified via Google's own double-submit g_csrf_token below, not a WP nonce (there is no logged-in session yet to bind a nonce to).
        $cookie_token = isset($_COOKIE['g_csrf_token']) ? sanitize_text_field(wp_unslash($_COOKIE['g_csrf_token'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above.
        $body_token = isset($_POST['g_csrf_token']) ? sanitize_text_field(wp_unslash($_POST['g_csrf_token'])) : '';
        if (!$cookie_token || !$body_token || !hash_equals($cookie_token, $body_token)) {
            $this->fail(__('Could not verify this sign-in request. Please try again.', 'hdwebmobile-social-login'));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above; the credential itself is cryptographically verified below, which is the actual authorization boundary for this endpoint.
        $credential = isset($_POST['credential']) ? sanitize_text_field(wp_unslash($_POST['credential'])) : '';
        if (!$credential) {
            $this->fail(__('No identity token was received.', 'hdwebmobile-social-login'));
        }

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-jwt-verifier.php';
        $payload = HDSL_JWT_Verifier::verify_google_id_token($credential, $client_id);

        if (is_wp_error($payload)) {
            $this->fail($payload->get_error_message());
        }

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-repository.php';
        $subject_id = $payload['sub'];
        $email      = sanitize_email($payload['email'] ?? '');

        $user_id = HDSL_Repository::find_user_id_by_identity(HDSL_Repository::PROVIDER_GOOGLE, $subject_id);

        if ($user_id) {
            $this->log_in($user_id);
        }

        if (!$email) {
            $this->fail(__('Google did not provide an email address.', 'hdwebmobile-social-login'));
        }

        $existing = get_user_by('email', $email);
        if ($existing) {
            // Deliberately do NOT log in or auto-link -- see class docblock.
            $this->fail(sprintf(
                /* translators: %s: account email address */
                __('An account already exists for %s. Please log in with your password first, then connect Google from My Account.', 'hdwebmobile-social-login'),
                esc_html($email)
            ));
        }

        $new_user_id = $this->create_customer($email, $payload);
        if (is_wp_error($new_user_id)) {
            $this->fail($new_user_id->get_error_message());
        }

        HDSL_Repository::link($new_user_id, HDSL_Repository::PROVIDER_GOOGLE, $subject_id, $email);
        $this->log_in($new_user_id);
    }

    private function create_customer($email, array $payload)
    {
        $username = $this->unique_username_from_email($email);
        $user_id  = wc_create_new_customer($email, $username, wp_generate_password(32, true, true));
        if (is_wp_error($user_id)) {
            return $user_id;
        }

        $name = trim((string) ($payload['name'] ?? ''));
        if ($name) {
            wp_update_user(array('ID' => $user_id, 'display_name' => $name));
        }
        if (!empty($payload['given_name'])) {
            update_user_meta($user_id, 'first_name', sanitize_text_field($payload['given_name']));
        }
        if (!empty($payload['family_name'])) {
            update_user_meta($user_id, 'last_name', sanitize_text_field($payload['family_name']));
        }

        return $user_id;
    }

    private function unique_username_from_email($email)
    {
        $base     = sanitize_user(current(explode('@', $email)), true);
        $base     = $base ?: 'user';
        $username = $base;
        $i        = 1;
        while (username_exists($username)) {
            $username = $base . $i;
            $i++;
        }
        return $username;
    }

    private function log_in($user_id)
    {
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id, true);
        // This is WordPress core's own login hook, fired here for compatibility with any other
        // plugin (security logging, analytics, etc.) that listens for a normal login -- not a
        // hook this plugin defines itself, so it deliberately isn't prefixed like our own hooks.
        do_action('wp_login', get_userdata($user_id)->user_login, get_userdata($user_id)); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
        wp_safe_redirect(wc_get_page_permalink('myaccount'));
        exit;
    }

    private function fail($message)
    {
        $redirect = wc_get_page_permalink('myaccount') ?: home_url('/');
        set_transient('hdsl_login_error_' . self::client_fingerprint(), $message, 60);
        wp_safe_redirect(add_query_arg('hdsl_error', '1', $redirect));
        exit;
    }

    /**
     * A short-lived, per-visitor key for handing the (already-safe, non-sensitive) error
     * message back to the next page load without putting it in the URL itself.
     */
    public static function client_fingerprint()
    {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- used only as a non-sensitive cache-key seed, never output or trusted for authorization.
        return md5((isset($_COOKIE[LOGGED_IN_COOKIE]) ? $_COOKIE[LOGGED_IN_COOKIE] : '') . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''));
    }
}

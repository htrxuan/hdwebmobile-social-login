<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Renders Google's own "Sign In With Google" button and loads Google's own script for it --
 * this class never builds or parses a token itself; it only displays the button and points its
 * POST at admin-post.php?action=hdsl_google_login, where class-hdsl-auth.php does the actual
 * verification. Placed via woocommerce_before_customer_login_form -- outside both the login and
 * register <form> elements entirely, avoiding any nested-form ambiguity on the My Account page.
 */
final class HDSL_Frontend
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
        add_action('woocommerce_before_customer_login_form', array($this, 'render_button'));
        add_action('wp_enqueue_scripts', array($this, 'maybe_enqueue_assets'));
        add_action('wp', array($this, 'maybe_show_error_notice'));
    }

    public function maybe_enqueue_assets()
    {
        if (!$this->is_configured() || !is_account_page()) {
            return;
        }
        wp_enqueue_style('hdsl-frontend', HDSL_PLUGIN_URL . 'assets/css/hdsl-frontend.css', array(), HDSL_VERSION);
        // Google's own client script for the Sign In button and token issuance -- loading it
        // is the feature itself (an OAuth-style login integration the site owner explicitly
        // configures with their own Client ID), not undisclosed third-party offloading. There
        // is no local copy to bundle instead: Google serves this from their own CDN only, and
        // a stale mirrored copy would silently break as Google evolves the client-side flow.
        wp_enqueue_script('google-identity-services', 'https://accounts.google.com/gsi/client', array(), HDSL_VERSION, true);
    }

    public function render_button()
    {
        if (!$this->is_configured()) {
            return;
        }

        $client_id = get_option('hdsl_google_client_id', '');
        $login_uri = admin_url('admin-post.php?action=hdsl_google_login');
        ?>
        <div class="hdsl-google-signin">
            <div id="g_id_onload"
                data-client_id="<?php echo esc_attr($client_id); ?>"
                data-login_uri="<?php echo esc_url($login_uri); ?>"
                data-context="signin"
                data-ux_mode="redirect"
                data-itp_support="true">
            </div>
            <div class="g_id_signin"
                data-type="standard"
                data-shape="rectangular"
                data-theme="outline"
                data-text="continue_with"
                data-size="large"
                data-logo_alignment="left">
            </div>
            <p class="hdsl-divider"><span><?php esc_html_e('or use your email and password', 'hdwebmobile-social-login'); ?></span></p>
        </div>
        <?php
    }

    public function maybe_show_error_notice()
    {
        if (!is_account_page() || empty($_GET['hdsl_error'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only flag selecting whether to display a stored, non-sensitive notice; the message itself is never taken from the request.
            return;
        }
        $key     = 'hdsl_login_error_' . HDSL_Auth::client_fingerprint();
        $message = get_transient($key);
        if (!$message) {
            return;
        }
        delete_transient($key);
        add_action('woocommerce_before_customer_login_form', function () use ($message) {
            wc_print_notice($message, 'error');
        }, 5);
    }

    private function is_configured()
    {
        return (bool) get_option('hdsl_google_client_id', '');
    }
}

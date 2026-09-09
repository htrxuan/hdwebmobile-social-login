<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The only way an EXISTING WordPress account (created by normal registration, or by an admin)
 * can ever become linked to a Google identity: the account owner must already be logged in
 * (normal password session) and explicitly click "Connect Google" here. This is the opt-in
 * counterpart to class-hdsl-auth.php's refusal to auto-link a first-time Google sign-in to a
 * pre-existing account by email match alone -- see that class's docblock for why.
 */
final class HDSL_MyAccount
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
        // Deliberately woocommerce_after_edit_account_form, not woocommerce_edit_account_form --
        // the latter fires INSIDE the account-edit <form>, and this section renders its own
        // <form> (for the Disconnect button); nesting forms breaks HTML parsing and silently
        // misroutes the submit. This hook fires after that form's closing tag.
        add_action('woocommerce_after_edit_account_form', array($this, 'render_connected_accounts'));
        add_action('admin_post_hdsl_google_link', array($this, 'handle_link'));
        add_action('admin_post_hdsl_unlink', array($this, 'handle_unlink'));
        add_action('wp_enqueue_scripts', array($this, 'maybe_enqueue_assets'));
    }

    public function maybe_enqueue_assets()
    {
        if (!is_account_page() || !get_option('hdsl_google_client_id', '') || !is_user_logged_in()) {
            return;
        }
        // See class-hdsl-frontend.php's identical enqueue for why this is loaded from Google's
        // own CDN rather than bundled -- it's this feature's own required client script.
        wp_enqueue_script('google-identity-services', 'https://accounts.google.com/gsi/client', array(), HDSL_VERSION, true);
    }

    public function render_connected_accounts()
    {
        $client_id = get_option('hdsl_google_client_id', '');
        if (!$client_id) {
            return;
        }

        $error_key = 'hdsl_link_error_' . get_current_user_id();
        $error     = get_transient($error_key);
        if ($error) {
            delete_transient($error_key);
            wc_print_notice($error, 'error');
        }

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-repository.php';
        $identity = HDSL_Repository::find_identity_for_user(get_current_user_id(), HDSL_Repository::PROVIDER_GOOGLE);

        echo '<h3>' . esc_html__('Connected Accounts', 'hdwebmobile-social-login') . '</h3>';

        if ($identity) {
            echo '<p>' . sprintf(
                /* translators: %s: linked Google account email */
                esc_html__('Google is connected (%s).', 'hdwebmobile-social-login'),
                esc_html($identity->email)
            ) . '</p>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="hdsl_unlink" />';
            wp_nonce_field('hdsl_unlink', 'hdsl_unlink_nonce');
            echo '<button type="submit" class="button">' . esc_html__('Disconnect Google', 'hdwebmobile-social-login') . '</button>';
            echo '</form>';
            return;
        }

        $login_uri = admin_url('admin-post.php?action=hdsl_google_link');
        ?>
        <p><?php esc_html_e('Connect your Google account for faster sign-in next time.', 'hdwebmobile-social-login'); ?></p>
        <div id="g_id_onload"
            data-client_id="<?php echo esc_attr($client_id); ?>"
            data-login_uri="<?php echo esc_url($login_uri); ?>"
            data-context="use"
            data-ux_mode="redirect"
            data-itp_support="true">
        </div>
        <div class="g_id_signin" data-type="standard" data-theme="outline" data-text="signin_with" data-size="medium"></div>
        <?php
    }

    /**
     * Linking an EXISTING session to a new Google identity. The visitor is already
     * authenticated by their own password before reaching this endpoint -- this only ever adds
     * a link for get_current_user_id(), never a user id taken from the request.
     */
    public function handle_link()
    {
        if (!is_user_logged_in()) {
            wp_die(esc_html__('You must be logged in to connect an account.', 'hdwebmobile-social-login'));
        }

        $client_id = get_option('hdsl_google_client_id', '');

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified via Google's own double-submit g_csrf_token below, matching class-hdsl-auth.php's login endpoint.
        $cookie_token = isset($_COOKIE['g_csrf_token']) ? sanitize_text_field(wp_unslash($_COOKIE['g_csrf_token'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above.
        $body_token = isset($_POST['g_csrf_token']) ? sanitize_text_field(wp_unslash($_POST['g_csrf_token'])) : '';
        if (!$client_id || !$cookie_token || !$body_token || !hash_equals($cookie_token, $body_token)) {
            $this->redirect_with_notice(__('Could not verify this request. Please try again.', 'hdwebmobile-social-login'));
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see above; the credential is cryptographically verified below.
        $credential = isset($_POST['credential']) ? sanitize_text_field(wp_unslash($_POST['credential'])) : '';

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-jwt-verifier.php';
        $payload = HDSL_JWT_Verifier::verify_google_id_token($credential, $client_id);
        if (is_wp_error($payload)) {
            $this->redirect_with_notice($payload->get_error_message());
        }

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-repository.php';
        $subject_id = $payload['sub'];
        $email      = sanitize_email($payload['email'] ?? '');

        $already_linked_to = HDSL_Repository::find_user_id_by_identity(HDSL_Repository::PROVIDER_GOOGLE, $subject_id);
        if ($already_linked_to && $already_linked_to !== get_current_user_id()) {
            $this->redirect_with_notice(__('That Google account is already connected to a different account.', 'hdwebmobile-social-login'));
        }

        if (!$already_linked_to) {
            HDSL_Repository::link(get_current_user_id(), HDSL_Repository::PROVIDER_GOOGLE, $subject_id, $email);
        }

        wp_safe_redirect(wc_get_endpoint_url('edit-account', '', wc_get_page_permalink('myaccount')));
        exit;
    }

    public function handle_unlink()
    {
        if (!is_user_logged_in() || !isset($_POST['hdsl_unlink_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['hdsl_unlink_nonce'])), 'hdsl_unlink')) {
            wp_die(esc_html__('Invalid request.', 'hdwebmobile-social-login'));
        }

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-repository.php';
        HDSL_Repository::unlink(get_current_user_id(), HDSL_Repository::PROVIDER_GOOGLE);

        wp_safe_redirect(wc_get_endpoint_url('edit-account', '', wc_get_page_permalink('myaccount')));
        exit;
    }

    private function redirect_with_notice($message)
    {
        set_transient('hdsl_link_error_' . get_current_user_id(), $message, 60);
        wp_safe_redirect(wc_get_endpoint_url('edit-account', '', wc_get_page_permalink('myaccount')));
        exit;
    }
}

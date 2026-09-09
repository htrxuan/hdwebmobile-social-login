<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

class HDSL_Admin
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
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-hub.php';
        add_filter('hdwebmobile_hub_tabs', array($this, 'register_hub_tabs'));
        add_action('admin_post_hdsl_save_settings', array($this, 'save_settings'));
    }

    public function register_hub_tabs($tabs)
    {
        $tabs['social-login'] = array(
            'label'  => __('Social Login', 'hdwebmobile-social-login'),
            'order'  => 14,
            'render' => array($this, 'render_page'),
        );
        return $tabs;
    }

    public function save_settings()
    {
        if (!current_user_can('manage_woocommerce') || !isset($_POST['hdsl_settings_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['hdsl_settings_nonce'])), 'hdsl_save_settings')) {
            wp_die(esc_html__('You do not have permission to do this.', 'hdwebmobile-social-login'));
        }

        $client_id = isset($_POST['hdsl_google_client_id']) ? sanitize_text_field(wp_unslash($_POST['hdsl_google_client_id'])) : '';
        update_option('hdsl_google_client_id', $client_id);

        wp_safe_redirect(admin_url('admin.php?page=hdwebmobile&tab=social-login&updated=1'));
        exit;
    }

    public function render_page()
    {
        if (!current_user_can('manage_woocommerce')) {
            wp_die(esc_html__('You do not have permission to do this.', 'hdwebmobile-social-login'));
        }

        $client_id = get_option('hdsl_google_client_id', '');
        $login_url = wc_get_page_permalink('myaccount');
        ?>
        <p><?php esc_html_e('Let customers sign in or register with "Continue with Google" on the login page, alongside the normal password login.', 'hdwebmobile-social-login'); ?></p>

        <?php if (!empty($_GET['updated'])) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only success flag, no state change. ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved.', 'hdwebmobile-social-login'); ?></p></div>
        <?php endif; ?>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="hdsl_save_settings" />
            <?php wp_nonce_field('hdsl_save_settings', 'hdsl_settings_nonce'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="hdsl_google_client_id"><?php esc_html_e('Google OAuth Client ID', 'hdwebmobile-social-login'); ?></label></th>
                    <td>
                        <input type="text" id="hdsl_google_client_id" name="hdsl_google_client_id" value="<?php echo esc_attr($client_id); ?>" class="regular-text" placeholder="<?php esc_attr_e('Paste your Google Client ID here', 'hdwebmobile-social-login'); ?>" />
                        <p class="description">
                            <?php
                            printf(
                                /* translators: %s: Google Cloud Console URL */
                                esc_html__('Create an OAuth 2.0 Client ID at %s (Web application type). Add this site\'s home URL as an Authorized JavaScript origin, and the URL below as an Authorized redirect URI.', 'hdwebmobile-social-login'),
                                '<a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener noreferrer">console.cloud.google.com/apis/credentials</a>'
                            );
                            ?>
                        </p>
                        <p class="description"><code><?php echo esc_html(admin_url('admin-post.php?action=hdsl_google_login')); ?></code></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(__('Save Settings', 'hdwebmobile-social-login')); ?>
        </form>

        <?php if ($client_id) : ?>
            <p>
                <?php
                printf(
                    /* translators: %s: My Account login page URL */
                    esc_html__('The button is live on the %s page.', 'hdwebmobile-social-login'),
                    '<a href="' . esc_url($login_url) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('My Account login', 'hdwebmobile-social-login') . '</a>'
                );
                ?>
            </p>
        <?php endif; ?>
        <?php
    }
}

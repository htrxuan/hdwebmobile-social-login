<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

final class HDSL_Core
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
        $this->includes();
        $this->init_hooks();
    }

    private function __clone()
    {
    }

    private function includes()
    {
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-repository.php';
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-jwt-verifier.php';
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-auth.php';
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-frontend.php';
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-myaccount.php';
        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-admin.php';
    }

    private function init_hooks()
    {
        add_action('admin_notices', array($this, 'render_missing_woocommerce_notice'));
        add_action('admin_init', array(HDSL_Activator::class, 'maybe_upgrade_db'));

        if (!class_exists('WooCommerce')) {
            return;
        }

        HDSL_Auth::get_instance();
        HDSL_Frontend::get_instance();
        HDSL_MyAccount::get_instance();

        // HDSL_Admin registers admin-menu/settings hooks itself, but this must load
        // unconditionally (not only when is_admin()) since it also owns the
        // hdwebmobile_hub_tabs registration used by the shared hub page.
        HDSL_Admin::get_instance();
    }

    public function render_missing_woocommerce_notice()
    {
        $screen = get_current_screen();
        if (!$screen || 'plugins' !== $screen->id) {
            return;
        }

        if (!get_transient('hdsl_wc_missing_notice')) {
            return;
        }
        delete_transient('hdsl_wc_missing_notice');
        ?>
        <div class="notice notice-error is-dismissible">
            <p>
                <?php esc_html_e('HDWebmobile Social Login requires WooCommerce to be installed and active. The plugin has been deactivated.', 'hdwebmobile-social-login'); ?>
            </p>
        </div>
        <?php
    }
}

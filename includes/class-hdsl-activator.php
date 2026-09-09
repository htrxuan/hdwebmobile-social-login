<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

class HDSL_Activator
{

    public static function activate()
    {
        if (!self::is_woocommerce_active()) {
            deactivate_plugins(plugin_basename(HDSL_PLUGIN_FILE));
            set_transient('hdsl_wc_missing_notice', true, 30);
            return;
        }

        self::maybe_upgrade_db();
    }

    public static function is_woocommerce_active()
    {
        if (!function_exists('is_plugin_active')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        return is_plugin_active('woocommerce/woocommerce.php') || class_exists('WooCommerce');
    }

    public static function maybe_upgrade_db()
    {
        if (get_option('hdsl_db_version') === HDSL_VERSION) {
            return;
        }

        require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-repository.php';
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        dbDelta(HDSL_Repository::get_schema_sql());

        update_option('hdsl_db_version', HDSL_VERSION);
    }

    public static function declare_hpos_compatibility()
    {
        if (class_exists('\Automattic\WooCommerce\Utilities\FeaturesUtil')) {
            \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', HDSL_PLUGIN_FILE, true);
        }
    }
}

<?php

/**
 * Plugin Name: HDWebmobile Social Login
 * Plugin URI: https://hdwebmobile.com/plugins/hdwebmobile-social-login/
 * Description: "Continue with Google" login and signup for WooCommerce, offered alongside the normal password login. Every identity token is cryptographically verified against Google's own current public keys, issuer, audience, and expiry before any account is ever touched -- an unverified or forged token never creates a session, no matter whose email it claims.
 * Version: 1.0.0
 * Author: htrxuan - Han Tran
 * Author URI: https://hdwebmobile.com/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: hdwebmobile-social-login
 * Domain Path: /languages
 * Requires Plugins: woocommerce
 * Requires PHP: 7.4
 * Requires at least: 6.9
 */

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

// Define Constants
define('HDSL_VERSION', '1.0.0');
define('HDSL_PLUGIN_FILE', __FILE__);
define('HDSL_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('HDSL_PLUGIN_URL', plugin_dir_url(__FILE__));

require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-activator.php';

register_activation_hook(HDSL_PLUGIN_FILE, array(HDSL_Activator::class, 'activate'));
add_action('before_woocommerce_init', array(HDSL_Activator::class, 'declare_hpos_compatibility'));

add_action('plugins_loaded', function () {
    require_once HDSL_PLUGIN_DIR . 'includes/class-hdsl-core.php';
    HDSL_Core::get_instance();
});

add_filter('plugin_action_links_' . plugin_basename(HDSL_PLUGIN_FILE), function ($links) {
    $donate_link = '<a href="https://paypal.me/htrxuan/20" target="_blank" style="color:#d54e21;font-weight:bold;">' . __('Donate', 'hdwebmobile-social-login') . '</a>';
    array_unshift($links, $donate_link);
    return $links;
});

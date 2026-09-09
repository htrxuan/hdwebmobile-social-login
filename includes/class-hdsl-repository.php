<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Maps a verified provider identity (`provider` + `subject_id`, e.g. Google's `sub` claim) to
 * exactly one WordPress user. A UNIQUE KEY on (provider, subject_id) means two different WP
 * users can never simultaneously claim the same Google account, and lookups are always keyed
 * by subject_id -- never by email -- so a raw email match (which this plugin does not use for
 * authentication at all, only for display and for the explicit opt-in linking flow) can never
 * silently attach a login to a pre-existing account it doesn't actually belong to.
 *
 * Direct queries against a custom table are unavoidable here -- there is no WP API for this
 * data -- so DirectDatabaseQuery/NoCaching advisories are expected and accepted for this
 * class, matching standard practice for custom-table plugins in this suite.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
class HDSL_Repository
{
    const PROVIDER_GOOGLE = 'google';

    public static function get_table_name()
    {
        global $wpdb;
        return $wpdb->prefix . 'hdsl_identities';
    }

    public static function get_schema_sql()
    {
        global $wpdb;
        $table           = self::get_table_name();
        $charset_collate = $wpdb->get_charset_collate();

        return "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            provider VARCHAR(20) NOT NULL,
            subject_id VARCHAR(255) NOT NULL,
            user_id BIGINT UNSIGNED NOT NULL,
            email VARCHAR(255) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY identity (provider, subject_id),
            KEY user_id (user_id)
        ) {$charset_collate};";
    }

    /**
     * The only lookup ever used to decide "who is this visitor" -- always by (provider,
     * subject_id) from an already-verified token, never by email.
     */
    public static function find_user_id_by_identity($provider, $subject_id)
    {
        global $wpdb;
        $user_id = $wpdb->get_var($wpdb->prepare(
            'SELECT user_id FROM %i WHERE provider = %s AND subject_id = %s',
            self::get_table_name(),
            $provider,
            $subject_id
        ));
        return $user_id ? (int) $user_id : 0;
    }

    public static function find_identity_for_user($user_id, $provider)
    {
        global $wpdb;
        return $wpdb->get_row($wpdb->prepare(
            'SELECT * FROM %i WHERE user_id = %d AND provider = %s',
            self::get_table_name(),
            (int) $user_id,
            $provider
        ));
    }

    /**
     * Creates the one link between a provider identity and a WP user. The UNIQUE KEY makes a
     * concurrent double-link attempt for the same provider identity fail atomically rather than
     * racily creating two rows -- the caller (class-hdsl-auth.php) already checked
     * find_user_id_by_identity() returned nothing, but this is the actual safety net.
     */
    public static function link($user_id, $provider, $subject_id, $email)
    {
        global $wpdb;
        $inserted = $wpdb->insert(
            self::get_table_name(),
            array(
                'provider'   => $provider,
                'subject_id' => $subject_id,
                'user_id'    => (int) $user_id,
                'email'      => $email,
                'created_at' => current_time('mysql'),
            ),
            array('%s', '%s', '%d', '%s', '%s')
        );
        return false !== $inserted;
    }

    public static function unlink($user_id, $provider)
    {
        global $wpdb;
        return false !== $wpdb->delete(
            self::get_table_name(),
            array('user_id' => (int) $user_id, 'provider' => $provider),
            array('%d', '%s')
        );
    }
}

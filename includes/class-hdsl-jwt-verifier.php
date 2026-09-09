<?php

namespace htrxuan\hdsl;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Closes CVE-2026-8457 (CVSS 9.8) in a competing WooCommerce social-login plugin: its Apple
 * Sign In handler read the email out of the identity token and logged the visitor in as the
 * matching WordPress account WITHOUT verifying the token's signature against Apple's public
 * keys at all -- so anyone could hand-craft a token claiming to be an administrator's email
 * and be logged straight in. No existing account role or password was needed; the forged
 * claim alone was enough.
 *
 * This class is the one and only place a Google identity token's claims are ever trusted, and
 * it never trusts a single one of them until ALL of the following pass, in order:
 *
 *  1. The token is well-formed RS256-alg JWT (never "none"/HS256 -- rejecting the algorithm
 *     up front closes the classic "alg confusion" bypass of this exact same vulnerability
 *     class, not just the literal missing-check the CVE reported).
 *  2. Its `kid` header matches a key CURRENTLY published in Google's own JWKS endpoint --
 *     fetched fresh (transient-cached only for the provider's own stated max-age), never a
 *     hardcoded/stale key -- and the RSA signature verifies against that exact public key via
 *     openssl_verify(). This is the literal check the vulnerable plugin skipped.
 *  3. `iss` is exactly one of Google's real issuer strings, `aud` is exactly this site's own
 *     registered Client ID, `email_verified` is strictly true, and `exp`/`iat` are within a
 *     valid, non-expired window.
 *
 * A single failure anywhere in that chain returns a WP_Error and the caller (class-hdsl-
 * auth.php) never creates a session or touches any account -- there is no fallback path that
 * trusts the token's claims "a little" if verification fails.
 */
class HDSL_JWT_Verifier
{
    const GOOGLE_JWKS_URL      = 'https://www.googleapis.com/oauth2/v3/certs';
    const GOOGLE_ISSUERS       = array('https://accounts.google.com', 'accounts.google.com');
    const JWKS_TRANSIENT_KEY   = 'hdsl_google_jwks';
    const JWKS_DEFAULT_TTL     = HOUR_IN_SECONDS;

    /**
     * Verifies a Google ID token end-to-end. Returns the decoded payload array on success, or
     * a WP_Error identifying exactly which check failed (never partially trusted).
     *
     * @param string $jwt              The raw "credential" value posted by Google's Sign In button.
     * @param string $expected_audience This site's registered Google OAuth Client ID.
     * @return array|\WP_Error
     */
    public static function verify_google_id_token($jwt, $expected_audience)
    {
        $parts = is_string($jwt) ? explode('.', $jwt) : array();
        if (3 !== count($parts)) {
            return new \WP_Error('hdsl_malformed_token', __('The identity token is malformed.', 'hdwebmobile-social-login'));
        }
        list($b64_header, $b64_payload, $b64_signature) = $parts;

        $header  = json_decode(self::base64url_decode($b64_header), true);
        $payload = json_decode(self::base64url_decode($b64_payload), true);
        if (!is_array($header) || !is_array($payload)) {
            return new \WP_Error('hdsl_malformed_token', __('The identity token is malformed.', 'hdwebmobile-social-login'));
        }

        // Reject anything but RS256 up front -- never let the token itself pick a weaker or
        // signature-less algorithm ("none", HS256-with-the-public-key-as-secret, etc.).
        if ('RS256' !== ($header['alg'] ?? '')) {
            return new \WP_Error('hdsl_unsupported_alg', __('Unsupported token signing algorithm.', 'hdwebmobile-social-login'));
        }

        $kid = $header['kid'] ?? '';
        if (!$kid) {
            return new \WP_Error('hdsl_missing_kid', __('The identity token has no key id.', 'hdwebmobile-social-login'));
        }

        $jwk = self::find_key($kid);
        if (!$jwk) {
            return new \WP_Error('hdsl_unknown_key', __('The identity token was not signed by a currently published Google key.', 'hdwebmobile-social-login'));
        }

        $public_key_pem = self::jwk_to_pem($jwk);
        if (!$public_key_pem) {
            return new \WP_Error('hdsl_bad_key', __('Could not build a public key from the provider\'s JWKS.', 'hdwebmobile-social-login'));
        }

        $signed_input = $b64_header . '.' . $b64_payload;
        $signature    = self::base64url_decode($b64_signature);

        // The one check the vulnerable plugin skipped entirely.
        $verified = openssl_verify($signed_input, $signature, $public_key_pem, OPENSSL_ALGO_SHA256);
        if (1 !== $verified) {
            return new \WP_Error('hdsl_bad_signature', __('The identity token\'s signature is invalid.', 'hdwebmobile-social-login'));
        }

        // Signature alone is not enough -- a token legitimately signed by Google for a
        // DIFFERENT audience, issuer, or one that has expired, must still be rejected.
        $expected_issuers = apply_filters('hdsl_expected_issuers', self::GOOGLE_ISSUERS);
        if (!in_array($payload['iss'] ?? '', $expected_issuers, true)) {
            return new \WP_Error('hdsl_bad_issuer', __('The identity token has an unexpected issuer.', 'hdwebmobile-social-login'));
        }

        if (!hash_equals((string) $expected_audience, (string) ($payload['aud'] ?? ''))) {
            return new \WP_Error('hdsl_bad_audience', __('The identity token was not issued for this site.', 'hdwebmobile-social-login'));
        }

        if (empty($payload['sub'])) {
            return new \WP_Error('hdsl_missing_subject', __('The identity token has no subject.', 'hdwebmobile-social-login'));
        }

        $email_verified = $payload['email_verified'] ?? false;
        if (true !== $email_verified && 'true' !== $email_verified) {
            return new \WP_Error('hdsl_email_not_verified', __('Google has not verified this email address.', 'hdwebmobile-social-login'));
        }

        $now = time();
        if (empty($payload['exp']) || $payload['exp'] < $now) {
            return new \WP_Error('hdsl_expired', __('The identity token has expired.', 'hdwebmobile-social-login'));
        }
        if (!empty($payload['iat']) && $payload['iat'] > $now + 60) {
            return new \WP_Error('hdsl_not_yet_valid', __('The identity token was issued in the future.', 'hdwebmobile-social-login'));
        }

        return $payload;
    }

    /**
     * Returns the JWK whose `kid` matches, or null. The JWKS source itself is filterable
     * (`hdsl_jwks_url`) purely so the PHP unit test suite can point this at a local test
     * double instead of the real Google endpoint -- production always uses Google's real URL.
     */
    private static function find_key($kid)
    {
        $jwks = self::get_jwks();
        foreach ($jwks['keys'] ?? array() as $key) {
            if (($key['kid'] ?? '') === $kid) {
                return $key;
            }
        }
        return null;
    }

    private static function get_jwks()
    {
        $cached = get_transient(self::JWKS_TRANSIENT_KEY);
        if (is_array($cached)) {
            return $cached;
        }

        $url      = apply_filters('hdsl_jwks_url', self::GOOGLE_JWKS_URL);
        $response = wp_remote_get($url, array('timeout' => 10));
        if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
            return array('keys' => array());
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($body) || empty($body['keys'])) {
            return array('keys' => array());
        }

        set_transient(self::JWKS_TRANSIENT_KEY, $body, self::cache_ttl_from_headers($response));
        return $body;
    }

    /**
     * Google's JWKS response tells callers exactly how long the keys are valid for via its
     * Cache-Control header -- respecting that (rather than a fixed guess) means a rotated key
     * is never trusted past its real expiry, and a still-valid key isn't re-fetched needlessly.
     */
    private static function cache_ttl_from_headers($response)
    {
        $cache_control = wp_remote_retrieve_header($response, 'cache-control');
        if (is_string($cache_control) && preg_match('/max-age=(\d+)/', $cache_control, $m)) {
            return max(60, min((int) $m[1], DAY_IN_SECONDS));
        }
        return self::JWKS_DEFAULT_TTL;
    }

    /**
     * Builds a PEM-encoded RSA public key from a JWK's modulus/exponent, so openssl_verify()
     * can use it directly. Standard DER/ASN.1 SubjectPublicKeyInfo construction -- no external
     * JWT/crypto library needed, matching this suite's no-heavy-dependency convention.
     */
    private static function jwk_to_pem(array $jwk)
    {
        if (empty($jwk['n']) || empty($jwk['e'])) {
            return null;
        }

        $modulus  = self::base64url_decode($jwk['n']);
        $exponent = self::base64url_decode($jwk['e']);
        if ('' === $modulus || '' === $exponent) {
            return null;
        }

        $rsa_public_key = self::der_sequence(
            self::der_integer($modulus) . self::der_integer($exponent)
        );

        // AlgorithmIdentifier SEQUENCE { OID rsaEncryption, NULL } -- a fixed, well-known DER blob.
        $algorithm_identifier = hex2bin('300d06092a864886f70d0101010500');

        $public_key_bit_string = "\x03" . self::der_length(strlen($rsa_public_key) + 1) . "\x00" . $rsa_public_key;
        $subject_public_key_info = self::der_sequence($algorithm_identifier . $public_key_bit_string);

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subject_public_key_info), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function der_length($length)
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function der_integer($bytes)
    {
        // DER INTEGER is signed -- prepend a zero byte if the high bit is set so an unsigned
        // modulus/exponent is never misread as negative.
        if (strlen($bytes) > 0 && ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::der_length(strlen($bytes)) . $bytes;
    }

    private static function der_sequence($der)
    {
        return "\x30" . self::der_length(strlen($der)) . $der;
    }

    public static function base64url_decode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        return false === $decoded ? '' : $decoded;
    }

    public static function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}

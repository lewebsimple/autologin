<?php
/**
 * Plugin Name:     AutoLogin
 * Plugin URI:      https://gitlab.ledevsimple.ca/wordpress/autologin
 * Description:     Generate password-less login links for users.
 * Author:          Pascal Martineau <pascal@lewebsimple.ca>
 * Author URI:      https://lewebsimple.ca
 * Text Domain:     autologin
 * Domain Path:     /languages
 * Version:         0.2.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AUTOLOGIN_OPTION', 'autologin' );
define( 'AUTOLOGIN_DEFAULT_EXPIRATION', DAY_IN_SECONDS * 30 );

define( 'AUTOLOGIN_INVALID_LINK', 'link' );
define( 'AUTOLOGIN_INVALID_USER', 'user' );
define( 'AUTOLOGIN_INVALID_AUTH', 'auth' );

// Load plugin textdomain
add_action( 'plugins_loaded', 'autologin_plugins_loaded' );
function autologin_plugins_loaded() {
	load_plugin_textdomain( 'autologin', false, basename( dirname( __FILE__ ) ) . '/languages' );
}

// Create random endpoint when plugin is activated
register_activation_hook( __FILE__, 'autologin_create_random_endpoint' );
function autologin_create_random_endpoint() {
	if ( empty( autologin_get_endpoint() ) ) {
		$option = array(
			'endpoint' => autologin_get_random_string( 4 ),
		);
		update_option( AUTOLOGIN_OPTION, json_encode( $option ) );
	}
}

// Helper: Return stored autologin endpoint
function autologin_get_endpoint() {
	$option = json_decode( get_option( AUTOLOGIN_OPTION, '{}' ), true );

	return empty( $option['endpoint'] ) ? false : $option['endpoint'];
}

// Helper: Generate cryptographically secure pseudo-random string
function autologin_get_random_string( $min, $max = null ) {
	$min = absint( $min );
	$max = absint( $max ? $max : $min );

	return bin2hex( random_bytes( random_int( $min, $max ) ) );
}

// Helper: Return signature to check against private key
function autologin_get_signature( $public, $user_id ) {
	$endpoint = autologin_get_endpoint();
	$domain   = $_SERVER['SERVER_NAME'];

	return "$public|$endpoint|$domain|$user_id";
}

// Helper: Generate encrypted public token from $user_id / $redirect
function autologin_get_public_token( $user_id, $redirect = '/' ) {
	return md5( json_encode( array(
		'user_id'  => $user_id,
		'redirect' => $redirect
	) ) );
}

// Intercept autologin request (i.e. "$endpoint/$public")
add_action( 'init', 'autologin_intercept_request' );
function autologin_intercept_request() {
	$request   = trim( $_SERVER['REQUEST_URI'], '/' );
	$fragments = explode( '/', $request );
	if ( 2 !== count( $fragments ) ) {
		// This is not the request you're looking for...
		return;
	}
	list( $endpoint, $public ) = $fragments;
	autologin_handle_request( $endpoint, $public );
}

// Handle autologin request
function autologin_handle_request( $endpoint, $public ) {
	if ( $endpoint !== autologin_get_endpoint() ) {
		// This is not the request you're looking for...
		return;
	}
	if ( empty( $transient = get_transient( AUTOLOGIN_OPTION . '/' . $public ) ) ) {
		$message = apply_filters( 'autologin_failed_message', __( "Missing or expired AutoLogin link.", 'autologin' ), AUTOLOGIN_INVALID_LINK );
		wp_die( $message );
	}
	$magic = json_decode( $transient, true );
	if ( empty( $magic['user_id'] ) || empty( $user = get_user_by( 'id', $magic['user_id'] ) ) ) {
		$message = apply_filters( 'autologin_failed_message', __( "Missing or invalid user.", 'autologin' ), AUTOLOGIN_INVALID_USER );
		wp_die( $message );
	}
	$signature = autologin_get_signature( $public, $magic['user_id'] );
	if ( empty( $magic['private'] ) || ! wp_check_password( $signature, $magic['private'] ) ) {
		$message = apply_filters( 'autologin_failed_message', __( "AutoLogin authentication failed.", 'autologin' ), AUTOLOGIN_INVALID_AUTH );
		wp_die( $message );
	}
	wp_set_auth_cookie( $magic['user_id'] );
	wp_redirect( home_url( $magic['redirect'] ) );
	exit;
}

// Helper: Generate autologin link from $user_id / $redirect
function autologin_generate_link( $user_id, $redirect = '/', $expiration = AUTOLOGIN_DEFAULT_EXPIRATION ) {
	$endpoint = autologin_get_endpoint();
	$redirect = str_replace( home_url(), '', $redirect );
	$public   = autologin_get_public_token( $user_id, $redirect );
	if ( empty( $existing = get_transient( AUTOLOGIN_OPTION . '/' . $public ) ) ) {
		$private = wp_hash_password( autologin_get_signature( $public, $user_id ) );
		$magic   = [
			'user_id'  => $user_id,
			'private'  => $private,
			'redirect' => $redirect,
			'time'     => time(),
		];
		set_transient( AUTOLOGIN_OPTION . '/' . $public, json_encode( $magic ), $expiration );
	} else {
		set_transient( AUTOLOGIN_OPTION . '/' . $public, $existing, $expiration );
	}

	return home_url( "$endpoint/$public" );
}

// Register [autologin] shortcode (USE WITH CARE)
add_shortcode( 'autologin', 'autologin_shortcode' );
function autologin_shortcode( $atts ) {
	$atts = shortcode_atts( array(
		'user_id'    => '',
		'redirect'   => '/',
		'expiration' => AUTOLOGIN_DEFAULT_EXPIRATION,
	), $atts, 'autologin' );
	if ( empty( get_user_by( 'id', $atts['user_id'] ) ) ) {
		return '';
	}

	return autologin_generate_link( $atts['user_id'], $atts['redirect'], $atts['expiration'] );
}

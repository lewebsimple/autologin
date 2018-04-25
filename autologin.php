<?php
/**
 * Plugin Name:     AutoLogin
 * Plugin URI:      https://gitlab.ledevsimple.ca/wordpress/autologin
 * Description:     Generate password-less login links for users.
 * Author:          Pascal Martineau <pascal@lewebsimple.ca>
 * Author URI:      https://lewebsimple.ca
 * Text Domain:     autologin
 * Domain Path:     /languages
 * Version:         0.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AUTOLOGIN_OPTION', 'autologin' );
define( 'AUTOLOGIN_DEFAULT_EXPIRATION', DAY_IN_SECONDS * 30 );

// Load plugin textdomain
add_action( 'plugins_loaded', 'autologin_plugins_loaded' );
function autologin_plugins_loaded() {
	load_plugin_textdomain( 'autologin', false, basename( dirname( __FILE__ ) ) . '/languages' );
}

// Create random endpoint when plugin is activated
register_activation_hook( __FILE__, 'autologin_activate' );
function autologin_activate() {
	$option = array(
		'endpoint' => autologin_randomness( 4 ),
	);
	update_option( AUTOLOGIN_OPTION, json_encode( $option ) );
}

// Destroy endpoint when plugin is deactivated
register_deactivation_hook( __FILE__, 'autologin_deactivate' );
function autologin_deactivate() {
	delete_option( AUTOLOGIN_OPTION );
}

// Intercept login link request
add_action( 'init', 'autologin_loaded' );
function autologin_loaded() {
	$request   = trim( $_SERVER['REQUEST_URI'], '/' );
	$fragments = explode( '/', $request );
	if ( 2 !== count( $fragments ) ) {
		return;
	}
	list( $endpoint, $public ) = $fragments;
	autologin_handle( $endpoint, $public );
}

// Handle login link request
function autologin_handle( $endpoint, $public ) {
	$option = json_decode( get_option( AUTOLOGIN_OPTION ) );
	if ( $endpoint !== $option->endpoint ) {
		return;
	}
	$magic = json_decode( get_transient( AUTOLOGIN_OPTION . '/' . $public ) );
	if ( empty( $magic->user ) || ( ! $user = new WP_User( $magic->user ) ) || ! $user->exists() ) {
		wp_die( __( "Invalid user.", 'autologin' ) );
	}
	if ( empty( $magic->private ) || ! wp_check_password( autologin_signature( $public, $user->ID ), $magic->private ) ) {
		wp_die( __( "AutoLogin authentication failed.", 'autologin' ) );
	}
	wp_set_auth_cookie( $user->ID );
	wp_redirect( home_url( $magic->redirect ) );
	exit;
}

// Generate pre-authorized login link for user
function autologin_generate( $user_id, $redirect = '/', $expiration = AUTOLOGIN_DEFAULT_EXPIRATION ) {
	$option = json_decode( get_option( AUTOLOGIN_OPTION ) );
	$public = implode( '-', [
		autologin_randomness( 3, 5 ),
		autologin_randomness( 3, 5 ),
		autologin_randomness( 3, 5 ),
	] );

	$private = wp_hash_password( autologin_signature( $public, $user_id ) );
	$magic   = [
		'user'     => $user_id,
		'private'  => $private,
		'redirect' => $redirect,
		'time'     => time(),
	];
	set_transient( AUTOLOGIN_OPTION . '/' . $public, json_encode( $magic ), $expiration );

	return home_url( "$option->endpoint/$public" );
}

// Generate signature to check against private key
function autologin_signature( $public, $user_id ) {
	$option = json_decode( get_option( AUTOLOGIN_OPTION ) );
	$domain = parse_url( home_url(), PHP_URL_HOST );

	return "$public|$option->endpoint|$domain|$user_id";
}

// Generate cryptographically secure pseudo-random string
function autologin_randomness( $min, $max = null ) {
	$min = absint( $min );
	$max = absint( $max ? $max : $min );

	return bin2hex( random_bytes( random_int( $min, $max ) ) );
}

// Helper: Get existing autologin link
function autologin_get_existing_link( $user_id ) {
	global $wpdb;
	$option = json_decode( get_option( AUTOLOGIN_OPTION ) );

	$query   = "SELECT * FROM {$wpdb->prefix}options WHERE option_value LIKE '{\"user\":{$user_id},%'";
	$results = $wpdb->get_results( $query, ARRAY_A );
	if ( empty( $results ) ) {
		return false;
	}
	$transient = reset( $results );
	$public = explode('/', $transient['option_name'])[1];

	// Check if existing link is still valid
	$magic = json_decode( get_transient( AUTOLOGIN_OPTION . '/' . $public ) );
	if ( empty( $magic->user ) || ( ! $user = new WP_User( $magic->user ) ) || ! $user->exists() ) {
		return false;
	}
	if ( empty( $magic->private ) || ! wp_check_password( autologin_signature( $public, $user->ID ), $magic->private ) ) {
		return false;
	}

	return home_url( "$option->endpoint/$public" );
}

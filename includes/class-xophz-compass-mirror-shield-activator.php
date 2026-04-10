<?php

/**
 * Fired during plugin activation
 *
 * @link       http://www.mycompassconsulting.com/
 * @since      1.0.0
 *
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/includes
 */

/**
 * Fired during plugin activation.
 *
 * Creates custom database tables for attack logging and trap configuration.
 *
 * @since      1.0.0
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/includes
 * @author     Xoph <xoph@midnightnerd.com>
 */
class Xophz_Compass_Mirror_Shield_Activator {

	/**
	 * Run activation tasks.
	 *
	 * Creates the mirror_shield_logs table for tracking attack attempts
	 * and mirror_shield_traps table for honeypot configuration.
	 *
	 * @since    1.0.0
	 */
	public static function activate() {
		if ( !function_exists('is_plugin_active') ) {
			include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
		}
		
		if ( !class_exists( 'Xophz_Compass' ) ) {  
			die('This plugin requires COMPASS to be active.');
		}
		
		self::create_tables();
	}

	/**
	 * Create custom database tables.
	 *
	 * @since    1.0.0
	 */
	private static function create_tables() {
		global $wpdb;
		
		$charset_collate = $wpdb->get_charset_collate();
		$logs_table = $wpdb->prefix . 'mirror_shield_logs';
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';

		// Attack logs table
		$sql_logs = "CREATE TABLE IF NOT EXISTS $logs_table (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address VARCHAR(45) NOT NULL,
			trap_type VARCHAR(50) NOT NULL,
			trap_id BIGINT(20) UNSIGNED DEFAULT NULL,
			user_agent TEXT,
			request_uri TEXT,
			request_method VARCHAR(10) DEFAULT 'GET',
			post_data TEXT,
			blocked TINYINT(1) DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY ip_address (ip_address),
			KEY trap_type (trap_type),
			KEY created_at (created_at)
		) $charset_collate;";

		// Honeypot traps configuration table
		$sql_traps = "CREATE TABLE IF NOT EXISTS $traps_table (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			trap_type VARCHAR(50) NOT NULL,
			name VARCHAR(255) NOT NULL,
			target_url VARCHAR(500) DEFAULT NULL,
			config TEXT,
			is_active TINYINT(1) DEFAULT 1,
			hit_count BIGINT(20) UNSIGNED DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY trap_type (trap_type),
			KEY is_active (is_active)
		) $charset_collate;";

		// Blocked IPs table
		$sql_blocked = "CREATE TABLE IF NOT EXISTS $blocked_table (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address VARCHAR(45) NOT NULL,
			reason VARCHAR(255) DEFAULT NULL,
			blocked_until DATETIME DEFAULT NULL,
			is_permanent TINYINT(1) DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY ip_address (ip_address)
		) $charset_collate;";

		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		dbDelta( $sql_logs );
		dbDelta( $sql_traps );
		dbDelta( $sql_blocked );

		// Insert default honeypot traps
		self::seed_default_traps();
	}

	/**
	 * Seed default honeypot traps.
	 *
	 * @since    1.0.0
	 */
	private static function seed_default_traps() {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		// Check if traps already exist
		$count = $wpdb->get_var("SELECT COUNT(*) FROM $traps_table");
		if ( $count > 0 ) {
			return;
		}

		$default_traps = array(
			array(
				'trap_type' => 'decoy_endpoint',
				'name' => 'Fake Backup File',
				'target_url' => '/wp-admin/backup.php',
				'config' => json_encode(array('response' => 'forbidden')),
				'is_active' => 1
			),
			array(
				'trap_type' => 'decoy_endpoint',
				'name' => 'Fake Config File',
				'target_url' => '/wp-config.bak',
				'config' => json_encode(array('response' => 'forbidden')),
				'is_active' => 1
			),
			array(
				'trap_type' => 'decoy_endpoint',
				'name' => 'Fake Admin Panel',
				'target_url' => '/administrator/',
				'config' => json_encode(array('response' => 'tarpit')),
				'is_active' => 1
			),
			array(
				'trap_type' => 'honeypot_field',
				'name' => 'Login Form Honeypot',
				'target_url' => null,
				'config' => json_encode(array('field_name' => 'website_url', 'forms' => array('login', 'comment'))),
				'is_active' => 1
			)
		);

		foreach ( $default_traps as $trap ) {
			$wpdb->insert( $traps_table, $trap );
		}
	}
}

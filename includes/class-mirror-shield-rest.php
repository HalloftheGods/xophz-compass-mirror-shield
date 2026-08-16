<?php

/**
 * Mirror Shield REST API Controller
 *
 * @link       http://www.mycompassconsulting.com/
 * @since      1.0.0
 *
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/includes
 */

/**
 * REST API endpoints for Mirror Shield.
 *
 * Provides endpoints for logs, stats, traps, and IP blocking.
 *
 * @since      1.0.0
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/includes
 * @author     Xoph <xoph@midnightnerd.com>
 */
class Xophz_Compass_Mirror_Shield_Rest {

	/**
	 * The namespace for REST routes.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string
	 */
	private $namespace = 'xophz-compass/v1';

	/**
	 * Register REST routes.
	 *
	 * @since    1.0.0
	 */
	public function register_routes() {
		// Logs endpoints
		register_rest_route( $this->namespace, '/mirror-shield/logs', array(
			'methods'  => 'GET',
			'callback' => array( $this, 'get_logs' ),
			'permission_callback' => array( $this, 'check_admin_permission' ),
			'args' => array(
				'page' => array( 'default' => 1, 'sanitize_callback' => 'absint' ),
				'per_page' => array( 'default' => 20, 'sanitize_callback' => 'absint' ),
				'trap_type' => array( 'sanitize_callback' => 'sanitize_text_field' ),
				'blocked' => array( 'sanitize_callback' => 'absint' ),
				'date_from' => array( 'sanitize_callback' => 'sanitize_text_field' ),
				'date_to' => array( 'sanitize_callback' => 'sanitize_text_field' ),
			)
		));

		// Stats endpoint (Unified Mirror Shield + WP Defender stats)
		register_rest_route( $this->namespace, '/mirror-shield/stats', array(
			'methods'  => 'GET',
			'callback' => array( $this, 'get_stats' ),
			'permission_callback' => array( $this, 'check_admin_permission' ),
		));

		// WP Defender Status & Overview
		register_rest_route( $this->namespace, '/mirror-shield/defender-status', array(
			'methods'  => 'GET',
			'callback' => array( $this, 'get_defender_status' ),
			'permission_callback' => array( $this, 'check_admin_permission' ),
		));

		// WP Defender Security Scan & Integrity
		register_rest_route( $this->namespace, '/mirror-shield/defender-scan', array(
			array(
				'methods'  => 'GET',
				'callback' => array( $this, 'get_defender_scan' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			),
			array(
				'methods'  => 'POST',
				'callback' => array( $this, 'trigger_defender_scan' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			)
		));

		// WP Defender Security Tweaks (Hardening)
		register_rest_route( $this->namespace, '/mirror-shield/defender-tweaks', array(
			array(
				'methods'  => 'GET',
				'callback' => array( $this, 'get_defender_tweaks' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			),
			array(
				'methods'  => 'POST',
				'callback' => array( $this, 'resolve_defender_tweak' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			)
		));

		// WP Defender Firewall & Lockouts
		register_rest_route( $this->namespace, '/mirror-shield/defender-firewall', array(
			array(
				'methods'  => 'GET',
				'callback' => array( $this, 'get_defender_firewall' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			),
			array(
				'methods'  => 'POST',
				'callback' => array( $this, 'update_defender_firewall' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			)
		));

		// Traps endpoints
		register_rest_route( $this->namespace, '/mirror-shield/traps', array(
			array(
				'methods'  => 'GET',
				'callback' => array( $this, 'get_traps' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			),
			array(
				'methods'  => 'POST',
				'callback' => array( $this, 'create_trap' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			)
		));

		register_rest_route( $this->namespace, '/mirror-shield/traps/(?P<id>\d+)', array(
			array(
				'methods'  => 'PUT',
				'callback' => array( $this, 'update_trap' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			),
			array(
				'methods'  => 'DELETE',
				'callback' => array( $this, 'delete_trap' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			)
		));

		// Block IP endpoints
		register_rest_route( $this->namespace, '/mirror-shield/block', array(
			array(
				'methods'  => 'GET',
				'callback' => array( $this, 'get_blocked_ips' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			),
			array(
				'methods'  => 'POST',
				'callback' => array( $this, 'block_ip' ),
				'permission_callback' => array( $this, 'check_admin_permission' ),
			)
		));

		register_rest_route( $this->namespace, '/mirror-shield/block/(?P<ip>[^/]+)', array(
			'methods'  => 'DELETE',
			'callback' => array( $this, 'unblock_ip' ),
			'permission_callback' => array( $this, 'check_admin_permission' ),
		));
	}

	/**
	 * Check if user has admin permissions.
	 *
	 * @since    1.0.0
	 * @return   bool
	 */
	public function check_admin_permission() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get paginated attack logs.
	 *
	 * @since    1.0.0
	 * @param    WP_REST_Request $request
	 * @return   WP_REST_Response
	 */
	public function get_logs( $request ) {
		global $wpdb;
		$logs_table = $wpdb->prefix . 'mirror_shield_logs';

		$page = $request->get_param('page');
		$per_page = min( $request->get_param('per_page'), 100 );
		$offset = ( $page - 1 ) * $per_page;

		$where = array('1=1');
		$params = array();

		if ( $request->get_param('trap_type') ) {
			$where[] = 'trap_type = %s';
			$params[] = $request->get_param('trap_type');
		}

		if ( $request->get_param('blocked') !== null ) {
			$where[] = 'blocked = %d';
			$params[] = $request->get_param('blocked');
		}

		if ( $request->get_param('date_from') ) {
			$where[] = 'created_at >= %s';
			$params[] = $request->get_param('date_from') . ' 00:00:00';
		}

		if ( $request->get_param('date_to') ) {
			$where[] = 'created_at <= %s';
			$params[] = $request->get_param('date_to') . ' 23:59:59';
		}

		$where_sql = implode(' AND ', $where);

		// Get total count
		$count_sql = "SELECT COUNT(*) FROM $logs_table WHERE $where_sql";
		if ( !empty($params) ) {
			$count_sql = $wpdb->prepare($count_sql, $params);
		}
		$total = $wpdb->get_var($count_sql);

		// Get logs
		$sql = "SELECT * FROM $logs_table WHERE $where_sql ORDER BY created_at DESC LIMIT %d OFFSET %d";
		$params[] = $per_page;
		$params[] = $offset;
		$logs = $wpdb->get_results( $wpdb->prepare($sql, $params) );

		return rest_ensure_response(array(
			'logs' => $logs,
			'total' => (int) $total,
			'page' => $page,
			'per_page' => $per_page,
			'total_pages' => ceil( $total / $per_page )
		));
	}

	/**
	 * Get aggregated statistics for charts.
	 *
	 * @since    1.0.0
	 * @return   WP_REST_Response
	 */
	public function get_stats() {
		global $wpdb;
		$logs_table = $wpdb->prefix . 'mirror_shield_logs';
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		// Total attacks
		$total_attacks = $wpdb->get_var("SELECT COUNT(*) FROM $logs_table");

		// Attacks in last 24 hours
		$attacks_24h = $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(*) FROM $logs_table WHERE created_at >= %s",
			date('Y-m-d H:i:s', strtotime('-24 hours'))
		));

		// Blocked IPs count
		$blocked_count = $wpdb->get_var("SELECT COUNT(*) FROM $blocked_table");

		// Active traps count
		$active_traps = $wpdb->get_var("SELECT COUNT(*) FROM $traps_table WHERE is_active = 1");

		// Attacks per day (last 30 days)
		$attacks_per_day = $wpdb->get_results($wpdb->prepare(
			"SELECT DATE(created_at) as date, COUNT(*) as count 
			 FROM $logs_table 
			 WHERE created_at >= %s 
			 GROUP BY DATE(created_at) 
			 ORDER BY date ASC",
			date('Y-m-d', strtotime('-30 days'))
		));

		// Attacks by trap type
		$attacks_by_type = $wpdb->get_results(
			"SELECT trap_type, COUNT(*) as count FROM $logs_table GROUP BY trap_type"
		);

		// Top attackers (by IP)
		$top_attackers = $wpdb->get_results(
			"SELECT ip_address, COUNT(*) as count 
			 FROM $logs_table 
			 GROUP BY ip_address 
			 ORDER BY count DESC 
			 LIMIT 10"
		);

		return rest_ensure_response(array(
			'total_attacks' => (int) $total_attacks,
			'attacks_24h' => (int) $attacks_24h,
			'blocked_count' => (int) $blocked_count,
			'active_traps' => (int) $active_traps,
			'attacks_per_day' => $attacks_per_day,
			'attacks_by_type' => $attacks_by_type,
			'top_attackers' => $top_attackers
		));
	}

	/**
	 * Get all traps.
	 *
	 * @since    1.0.0
	 * @return   WP_REST_Response
	 */
	public function get_traps() {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		$traps = $wpdb->get_results("SELECT * FROM $traps_table ORDER BY created_at DESC");

		// Parse config JSON
		foreach ( $traps as &$trap ) {
			$trap->config = json_decode( $trap->config );
		}

		return rest_ensure_response($traps);
	}

	/**
	 * Create a new trap.
	 *
	 * @since    1.0.0
	 * @param    WP_REST_Request $request
	 * @return   WP_REST_Response
	 */
	public function create_trap( $request ) {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		$data = array(
			'trap_type' => sanitize_text_field( $request->get_param('trap_type') ),
			'name' => sanitize_text_field( $request->get_param('name') ),
			'target_url' => sanitize_text_field( $request->get_param('target_url') ),
			'config' => wp_json_encode( $request->get_param('config') ?: array() ),
			'is_active' => $request->get_param('is_active') !== false ? 1 : 0
		);

		$result = $wpdb->insert( $traps_table, $data );

		if ( $result === false ) {
			return new WP_Error( 'create_failed', 'Failed to create trap', array( 'status' => 500 ) );
		}

		$data['id'] = $wpdb->insert_id;
		$data['config'] = json_decode( $data['config'] );

		return rest_ensure_response($data);
	}

	/**
	 * Update a trap.
	 *
	 * @since    1.0.0
	 * @param    WP_REST_Request $request
	 * @return   WP_REST_Response
	 */
	public function update_trap( $request ) {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';
		$id = $request->get_param('id');

		$data = array();
		$fields = array('trap_type', 'name', 'target_url', 'is_active');

		foreach ( $fields as $field ) {
			if ( $request->get_param($field) !== null ) {
				$data[$field] = $field === 'is_active' 
					? ($request->get_param($field) ? 1 : 0)
					: sanitize_text_field( $request->get_param($field) );
			}
		}

		if ( $request->get_param('config') !== null ) {
			$data['config'] = wp_json_encode( $request->get_param('config') );
		}

		$result = $wpdb->update( $traps_table, $data, array('id' => $id) );

		if ( $result === false ) {
			return new WP_Error( 'update_failed', 'Failed to update trap', array( 'status' => 500 ) );
		}

		return rest_ensure_response(array('success' => true, 'id' => $id));
	}

	/**
	 * Delete a trap.
	 *
	 * @since    1.0.0
	 * @param    WP_REST_Request $request
	 * @return   WP_REST_Response
	 */
	public function delete_trap( $request ) {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';
		$id = $request->get_param('id');

		$result = $wpdb->delete( $traps_table, array('id' => $id) );

		if ( $result === false ) {
			return new WP_Error( 'delete_failed', 'Failed to delete trap', array( 'status' => 500 ) );
		}

		return rest_ensure_response(array('success' => true));
	}

	/**
	 * Get blocked IPs.
	 *
	 * @since    1.0.0
	 * @return   WP_REST_Response
	 */
	public function get_blocked_ips() {
		global $wpdb;
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';

		$blocked = $wpdb->get_results("SELECT * FROM $blocked_table ORDER BY created_at DESC");

		return rest_ensure_response($blocked);
	}

	/**
	 * Block an IP address.
	 *
	 * @since    1.0.0
	 * @param    WP_REST_Request $request
	 * @return   WP_REST_Response
	 */
	public function block_ip( $request ) {
		global $wpdb;
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';

		$ip = sanitize_text_field( $request->get_param('ip') );
		$reason = sanitize_text_field( $request->get_param('reason') ?: 'Manual block' );
		$is_permanent = $request->get_param('is_permanent') ? 1 : 0;
		$duration = absint( $request->get_param('duration_hours') ?: 0 );

		$blocked_until = null;
		if ( !$is_permanent && $duration > 0 ) {
			$blocked_until = date('Y-m-d H:i:s', strtotime("+{$duration} hours"));
		}

		// Use INSERT ... ON DUPLICATE KEY UPDATE for upsert
		$wpdb->query($wpdb->prepare(
			"INSERT INTO $blocked_table (ip_address, reason, blocked_until, is_permanent) 
			 VALUES (%s, %s, %s, %d) 
			 ON DUPLICATE KEY UPDATE reason = %s, blocked_until = %s, is_permanent = %d",
			$ip, $reason, $blocked_until, $is_permanent,
			$reason, $blocked_until, $is_permanent
		));

		return rest_ensure_response(array('success' => true, 'ip' => $ip));
	}

	/**
	 * Unblock an IP address.
	 *
	 * @since    1.0.0
	 * @param    WP_REST_Request $request
	 * @return   WP_REST_Response
	 */
	public function unblock_ip( $request ) {
		global $wpdb;
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';
		$ip = urldecode( $request->get_param('ip') );

		$result = $wpdb->delete( $blocked_table, array('ip_address' => $ip) );

		if ( $result === false ) {
			return new WP_Error( 'unblock_failed', 'Failed to unblock IP', array( 'status' => 500 ) );
		}

		return rest_ensure_response(array('success' => true));
	}

	/**
	 * Helper: Check if WP Defender is active.
	 */
	private function is_defender_active() {
		return class_exists( 'WP_Defender\WP_Defender' ) || defined( 'DEFENDER_VERSION' ) || file_exists( WP_PLUGIN_DIR . '/wp-defender/wp-defender.php' );
	}

	/**
	 * Get WP Defender overall status & active features.
	 */
	public function get_defender_status() {
		$is_active = $this->is_defender_active();
		$tweaks_settings = get_option( 'wd_security_tweaks_settings', array() );
		$firewall_settings = get_option( 'wd_firewall_settings', array() );
		$scan_settings = get_option( 'wd_scan_settings', array() );

		return rest_ensure_response( array(
			'installed' => $is_active,
			'defender_version' => defined( 'DEFENDER_VERSION' ) ? DEFENDER_VERSION : 'Installed (Standard)',
			'firewall_enabled' => !empty( $firewall_settings ),
			'scan_enabled' => !empty( $scan_settings ),
			'tweaks_resolved_count' => isset( $tweaks_settings['fixed'] ) ? count( (array) $tweaks_settings['fixed'] ) : 0,
			'tweaks_issues_count' => isset( $tweaks_settings['issues'] ) ? count( (array) $tweaks_settings['issues'] ) : 0,
		) );
	}

	/**
	 * Get WP Defender security scan metrics.
	 */
	public function get_defender_scan() {
		global $wpdb;
		$scan_table = $wpdb->prefix . 'defender_scan';
		$scan_item_table = $wpdb->prefix . 'defender_scan_item';

		$last_scan = null;
		$issues = array();

		if ( $wpdb->get_var( "SHOW TABLES LIKE '$scan_table'" ) === $scan_table ) {
			$last_scan = $wpdb->get_row( "SELECT * FROM $scan_table ORDER BY id DESC LIMIT 1" );
			if ( $last_scan && $wpdb->get_var( "SHOW TABLES LIKE '$scan_item_table'" ) === $scan_item_table ) {
				$issues = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $scan_item_table WHERE scan_id = %d AND status != 'ignore'", $last_scan->id ) );
			}
		}

		return rest_ensure_response( array(
			'active' => $this->is_defender_active(),
			'last_scan' => $last_scan,
			'issues_count' => count( $issues ),
			'issues' => $issues,
		) );
	}

	/**
	 * Trigger WP Defender scan.
	 */
	public function trigger_defender_scan() {
		if ( class_exists( 'WP_Defender\Controller\Scan' ) ) {
			try {
				$scan_controller = new \WP_Defender\Controller\Scan();
				if ( method_exists( $scan_controller, 'do_scan' ) ) {
					$scan_controller->do_scan();
				}
			} catch ( \Throwable $e ) {
				// Fallback
			}
		}
		return rest_ensure_response( array( 'success' => true, 'message' => 'Security scan initialized.' ) );
	}

	/**
	 * Get WP Defender hardening security tweaks.
	 */
	public function get_defender_tweaks() {
		$tweaks_option = get_option( 'wd_security_tweaks_settings', array() );
		$fixed = isset( $tweaks_option['fixed'] ) ? (array) $tweaks_option['fixed'] : array();
		$issues = isset( $tweaks_option['issues'] ) ? (array) $tweaks_option['issues'] : array();
		$ignore = isset( $tweaks_option['ignore'] ) ? (array) $tweaks_option['ignore'] : array();

		$available_tweaks = array(
			array( 'slug' => 'disable-xmlrpc', 'title' => 'Disable XML-RPC', 'description' => 'Prevents brute force amplification & pingback DDoS attacks.' ),
			array( 'slug' => 'hide-backend', 'title' => 'Mask Login Area', 'description' => 'Changes default /wp-admin to custom secret URL slug.' ),
			array( 'slug' => 'disable-file-editor', 'title' => 'Disable File Editor', 'description' => 'Blocks theme & plugin PHP code editing via WP Admin.' ),
			array( 'slug' => 'prevent-enum-users', 'title' => 'Prevent User Enumeration', 'description' => 'Blocks author query loops like ?author=1 revealing usernames.' ),
			array( 'slug' => 'security-headers', 'title' => 'Enforce Security Headers', 'description' => 'Applies X-Frame-Options, X-Content-Type-Options, & HSTS headers.' ),
			array( 'slug' => 'protect-information', 'title' => 'Protect Sensitive Files', 'description' => 'Prevents direct web access to .htaccess, wp-config.php, & readme.html.' ),
		);

		foreach ( $available_tweaks as &$tweak ) {
			if ( in_array( $tweak['slug'], $fixed, true ) ) {
				$tweak['status'] = 'resolved';
			} elseif ( in_array( $tweak['slug'], $ignore, true ) ) {
				$tweak['status'] = 'ignored';
			} else {
				$tweak['status'] = 'issue';
			}
		}

		return rest_ensure_response( array(
			'tweaks' => $available_tweaks,
			'total_fixed' => count( $fixed ),
			'total_issues' => count( $issues ),
		) );
	}

	/**
	 * Toggle WP Defender security tweak.
	 */
	public function resolve_defender_tweak( $request ) {
		$slug = sanitize_text_field( $request->get_param( 'slug' ) );
		$action = sanitize_text_field( $request->get_param( 'action' ) ?: 'resolve' ); // resolve or revert

		$tweaks_option = get_option( 'wd_security_tweaks_settings', array() );
		if ( !is_array( $tweaks_option ) ) {
			$tweaks_option = array( 'fixed' => array(), 'issues' => array(), 'ignore' => array() );
		}

		$fixed = isset( $tweaks_option['fixed'] ) ? (array) $tweaks_option['fixed'] : array();

		if ( $action === 'resolve' && !in_array( $slug, $fixed, true ) ) {
			$fixed[] = $slug;
		} elseif ( $action === 'revert' ) {
			$fixed = array_diff( $fixed, array( $slug ) );
		}

		$tweaks_option['fixed'] = array_values( $fixed );
		update_option( 'wd_security_tweaks_settings', $tweaks_option );

		return rest_ensure_response( array( 'success' => true, 'slug' => $slug, 'action' => $action ) );
	}

	/**
	 * Get WP Defender Firewall & Lockout Settings.
	 */
	public function get_defender_firewall() {
		$login_lockout = get_option( 'wd_login_lockout_settings', array() );
		$notfound_lockout = get_option( 'wd_notfound_lockout_settings', array() );
		$blacklist = get_option( 'wd_blacklist_lockout_settings', array() );

		return rest_ensure_response( array(
			'login_lockout_enabled' => !empty( $login_lockout['enabled'] ),
			'login_attempt_threshold' => isset( $login_lockout['attempt'] ) ? (int) $login_lockout['attempt'] : 5,
			'notfound_lockout_enabled' => !empty( $notfound_lockout['enabled'] ),
			'notfound_attempt_threshold' => isset( $notfound_lockout['attempt'] ) ? (int) $notfound_lockout['attempt'] : 10,
			'ip_blacklist' => isset( $blacklist['ip_blacklist'] ) ? (array) $blacklist['ip_blacklist'] : array(),
			'ip_whitelist' => isset( $blacklist['ip_whitelist'] ) ? (array) $blacklist['ip_whitelist'] : array(),
		) );
	}

	/**
	 * Update WP Defender Firewall Settings.
	 */
	public function update_defender_firewall( $request ) {
		if ( $request->get_param( 'login_attempt_threshold' ) !== null ) {
			$login = get_option( 'wd_login_lockout_settings', array() );
			$login['attempt'] = absint( $request->get_param( 'login_attempt_threshold' ) );
			update_option( 'wd_login_lockout_settings', $login );
		}

		if ( $request->get_param( 'ip_blacklist' ) !== null ) {
			$bl = get_option( 'wd_blacklist_lockout_settings', array() );
			$bl['ip_blacklist'] = (array) $request->get_param( 'ip_blacklist' );
			update_option( 'wd_blacklist_lockout_settings', $bl );
		}

		return rest_ensure_response( array( 'success' => true ) );
	}
}

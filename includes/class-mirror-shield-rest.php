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

		// Stats endpoint
		register_rest_route( $this->namespace, '/mirror-shield/stats', array(
			'methods'  => 'GET',
			'callback' => array( $this, 'get_stats' ),
			'permission_callback' => array( $this, 'check_admin_permission' ),
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
}

<?php

/**
 * Mirror Shield Honeypot Handler
 *
 * @link       http://www.mycompassconsulting.com/
 * @since      1.0.0
 *
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/includes
 */

/**
 * Handles honeypot trap detection and logging.
 *
 * Monitors for honeypot triggers and logs/blocks attackers.
 *
 * @since      1.0.0
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/includes
 * @author     Xoph <xoph@midnightnerd.com>
 */
class Xophz_Compass_Mirror_Shield_Honeypot {

	/**
	 * Cached traps from database.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      array
	 */
	private $traps = null;

	/**
	 * Initialize the honeypot system.
	 *
	 * @since    1.0.0
	 */
	public function init() {
		// Check if visitor is blocked first
		add_action( 'init', array( $this, 'check_blocked' ), 1 );
		
		// Check decoy endpoints
		add_action( 'init', array( $this, 'check_decoy_endpoints' ), 5 );
		
		// Check honeypot form fields on submission
		add_action( 'wp_authenticate', array( $this, 'check_login_honeypot' ), 1, 2 );
		add_filter( 'preprocess_comment', array( $this, 'check_comment_honeypot' ), 1 );
		
		// Add honeypot fields to forms
		add_action( 'login_form', array( $this, 'add_login_honeypot_field' ) );
		add_action( 'comment_form_after_fields', array( $this, 'add_comment_honeypot_field' ) );
		add_action( 'comment_form_logged_in_after', array( $this, 'add_comment_honeypot_field' ) );
	}

	/**
	 * Check if current visitor is blocked.
	 *
	 * @since    1.0.0
	 */
	public function check_blocked() {
		// Don't block admin users
		if ( is_admin() && current_user_can('manage_options') ) {
			return;
		}

		global $wpdb;
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';

		// Self-healing: Check if tables exist and recreate if missing
		if ( $wpdb->get_var( "SHOW TABLES LIKE '$blocked_table'" ) != $blocked_table ) {
			if ( ! function_exists( 'is_plugin_active' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			require_once plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-xophz-compass-mirror-shield-activator.php';
			Xophz_Compass_Mirror_Shield_Activator::activate();
		}

		$ip = $this->get_client_ip();
		
		$blocked = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM $blocked_table 
			 WHERE ip_address = %s 
			 AND (is_permanent = 1 OR blocked_until IS NULL OR blocked_until > NOW())",
			$ip
		));

		if ( $blocked ) {
			$this->respond_to_blocked();
		}
	}

	/**
	 * Check for decoy endpoint access.
	 *
	 * @since    1.0.0
	 */
	public function check_decoy_endpoints() {
		$request_uri = $_SERVER['REQUEST_URI'] ?? '';
		$traps = $this->get_active_traps('decoy_endpoint');

		foreach ( $traps as $trap ) {
			if ( strpos($request_uri, $trap->target_url) !== false ) {
				$this->log_attack($trap->trap_type, $trap->id);
				$this->increment_trap_count($trap->id);
				$this->respond_to_trap($trap);
				exit;
			}
		}
	}

	/**
	 * Check login form for honeypot field trigger.
	 *
	 * @since    1.0.0
	 * @param    string $username
	 * @param    string $password
	 */
	public function check_login_honeypot( $username, $password ) {
		$honeypot_value = $_POST['website_url'] ?? '';
		
		if ( !empty($honeypot_value) ) {
			$trap = $this->get_trap_by_field('website_url', 'login');
			$trap_id = $trap ? $trap->id : null;
			
			$this->log_attack('honeypot_field', $trap_id);
			
			if ( $trap ) {
				$this->increment_trap_count($trap->id);
			}
			
			// Block the IP temporarily
			$this->auto_block_ip('Honeypot field triggered on login');
			
			wp_die( 
				'Access denied.', 
				'Forbidden', 
				array('response' => 403)
			);
		}
	}

	/**
	 * Check comment form for honeypot field trigger.
	 *
	 * @since    1.0.0
	 * @param    array $commentdata
	 * @return   array
	 */
	public function check_comment_honeypot( $commentdata ) {
		$honeypot_value = $_POST['website_url'] ?? '';
		
		if ( !empty($honeypot_value) ) {
			$trap = $this->get_trap_by_field('website_url', 'comment');
			$trap_id = $trap ? $trap->id : null;
			
			$this->log_attack('honeypot_field', $trap_id);
			
			if ( $trap ) {
				$this->increment_trap_count($trap->id);
			}
			
			$this->auto_block_ip('Honeypot field triggered on comment');
			
			wp_die( 
				'Your comment could not be posted.', 
				'Error', 
				array('response' => 403)
			);
		}
		
		return $commentdata;
	}

	/**
	 * Add honeypot field to login form.
	 *
	 * @since    1.0.0
	 */
	public function add_login_honeypot_field() {
		$trap = $this->get_trap_by_field('website_url', 'login');
		if ( !$trap || !$trap->is_active ) {
			return;
		}

		echo '<p style="position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;">';
		echo '<label for="website_url">Website</label>';
		echo '<input type="text" name="website_url" id="website_url" value="" tabindex="-1" autocomplete="off" />';
		echo '</p>';
	}

	/**
	 * Add honeypot field to comment form.
	 *
	 * @since    1.0.0
	 */
	public function add_comment_honeypot_field() {
		$trap = $this->get_trap_by_field('website_url', 'comment');
		if ( !$trap || !$trap->is_active ) {
			return;
		}

		echo '<p style="position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;">';
		echo '<label for="website_url">Website</label>';
		echo '<input type="text" name="website_url" id="website_url" value="" tabindex="-1" autocomplete="off" />';
		echo '</p>';
	}

	/**
	 * Get active traps of a specific type.
	 *
	 * @since    1.0.0
	 * @param    string $trap_type
	 * @return   array
	 */
	private function get_active_traps( $trap_type = null ) {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		if ( $trap_type ) {
			return $wpdb->get_results($wpdb->prepare(
				"SELECT * FROM $traps_table WHERE trap_type = %s AND is_active = 1",
				$trap_type
			));
		}

		return $wpdb->get_results(
			"SELECT * FROM $traps_table WHERE is_active = 1"
		);
	}

	/**
	 * Get trap by field name and form type.
	 *
	 * @since    1.0.0
	 * @param    string $field_name
	 * @param    string $form_type
	 * @return   object|null
	 */
	private function get_trap_by_field( $field_name, $form_type ) {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		$traps = $wpdb->get_results(
			"SELECT * FROM $traps_table WHERE trap_type = 'honeypot_field' AND is_active = 1"
		);

		foreach ( $traps as $trap ) {
			$config = json_decode($trap->config, true);
			if ( 
				isset($config['field_name']) && 
				$config['field_name'] === $field_name &&
				isset($config['forms']) &&
				in_array($form_type, $config['forms'])
			) {
				return $trap;
			}
		}

		return null;
	}

	/**
	 * Log an attack attempt.
	 *
	 * @since    1.0.0
	 * @param    string   $trap_type
	 * @param    int|null $trap_id
	 */
	private function log_attack( $trap_type, $trap_id = null ) {
		global $wpdb;
		$logs_table = $wpdb->prefix . 'mirror_shield_logs';

		$wpdb->insert($logs_table, array(
			'ip_address' => $this->get_client_ip(),
			'trap_type' => $trap_type,
			'trap_id' => $trap_id,
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
			'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
			'post_data' => wp_json_encode($_POST),
			'blocked' => 0
		));
	}

	/**
	 * Increment trap hit count.
	 *
	 * @since    1.0.0
	 * @param    int $trap_id
	 */
	private function increment_trap_count( $trap_id ) {
		global $wpdb;
		$traps_table = $wpdb->prefix . 'mirror_shield_traps';

		$wpdb->query($wpdb->prepare(
			"UPDATE $traps_table SET hit_count = hit_count + 1 WHERE id = %d",
			$trap_id
		));
	}

	/**
	 * Auto-block IP for a configurable duration.
	 *
	 * @since    1.0.0
	 * @param    string $reason
	 */
	private function auto_block_ip( $reason ) {
		global $wpdb;
		$blocked_table = $wpdb->prefix . 'mirror_shield_blocked';
		$logs_table = $wpdb->prefix . 'mirror_shield_logs';

		$ip = $this->get_client_ip();
		
		// Check attack frequency - auto-block if more than 3 attacks in 1 hour
		$recent_attacks = $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(*) FROM $logs_table 
			 WHERE ip_address = %s AND created_at >= %s",
			$ip,
			date('Y-m-d H:i:s', strtotime('-1 hour'))
		));

		if ( $recent_attacks >= 3 ) {
			$blocked_until = date('Y-m-d H:i:s', strtotime('+24 hours'));
			
			$wpdb->query($wpdb->prepare(
				"INSERT INTO $blocked_table (ip_address, reason, blocked_until, is_permanent) 
				 VALUES (%s, %s, %s, 0) 
				 ON DUPLICATE KEY UPDATE reason = %s, blocked_until = %s",
				$ip, $reason, $blocked_until,
				$reason, $blocked_until
			));

			// Update log entries as blocked
			$wpdb->update(
				$logs_table,
				array('blocked' => 1),
				array('ip_address' => $ip)
			);
		}
	}

	/**
	 * Respond to blocked visitor.
	 *
	 * @since    1.0.0
	 */
	private function respond_to_blocked() {
		status_header(403);
		nocache_headers();
		
		wp_die(
			'<h1>Access Denied</h1><p>Your IP address has been blocked due to suspicious activity.</p>',
			'Blocked',
			array('response' => 403)
		);
	}

	/**
	 * Respond to trap trigger based on config.
	 *
	 * @since    1.0.0
	 * @param    object $trap
	 */
	private function respond_to_trap( $trap ) {
		$config = json_decode($trap->config, true) ?: array();
		$response_type = $config['response'] ?? 'forbidden';

		switch ( $response_type ) {
			case 'tarpit':
				// Slow response to waste attacker's time
				sleep(10);
				status_header(200);
				echo '<html><head><title>Loading...</title></head><body>Please wait...</body></html>';
				break;
				
			case 'redirect':
				wp_redirect( home_url('/404') );
				break;
				
			case 'forbidden':
			default:
				status_header(403);
				wp_die('Access denied.', 'Forbidden', array('response' => 403));
				break;
		}
	}

	/**
	 * Get client IP address.
	 *
	 * @since    1.0.0
	 * @return   string
	 */
	private function get_client_ip() {
		$ip_keys = array(
			'HTTP_CF_CONNECTING_IP',  // Cloudflare
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR'
		);

		foreach ( $ip_keys as $key ) {
			if ( !empty($_SERVER[$key]) ) {
				$ip = $_SERVER[$key];
				// Handle comma-separated IPs (X-Forwarded-For)
				if ( strpos($ip, ',') !== false ) {
					$ip = trim(explode(',', $ip)[0]);
				}
				if ( filter_var($ip, FILTER_VALIDATE_IP) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}
}

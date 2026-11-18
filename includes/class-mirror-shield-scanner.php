<?php
/**
 * Mirror Shield Malware & Integrity Scanner Engine
 *
 * Implements throttled, low-CPU micro-batch scanning,
 * background scheduling, and WP Defender synthesis.
 *
 * @package Xophz_Compass_Mirror_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once plugin_dir_path( __FILE__ ) . 'class-mirror-shield-heuristics.php';

class Mirror_Shield_Scanner {

	/**
	 * Singleton instance.
	 *
	 * @var Mirror_Shield_Scanner|null
	 */
	private static $instance = null;

	/**
	 * State transient key.
	 */
	const STATE_TRANSIENT = 'mirror_shield_scan_state';

	/**
	 * Max execution time per batch in seconds (prevents CPU spikes & timeouts).
	 */
	const MAX_TIME_SLICE = 0.5;

	/**
	 * Files processed per micro-batch.
	 */
	const BATCH_FILE_LIMIT = 35;

	/**
	 * Microseconds to sleep between file reads (lowers CPU temperature/load).
	 */
	const SLEEP_MICROSECONDS = 15000; // 15ms

	/**
	 * Get singleton instance.
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		add_action( 'mirror_shield_scheduled_scan', array( $this, 'run_scheduled_scan' ) );
	}

	/**
	 * Start a new scan session.
	 *
	 * @param bool   $include_defender Whether to trigger WP Defender scan first.
	 * @param string $mode             'fast' or 'deep'.
	 * @return array Initial state.
	 */
	public function start_scan( $include_defender = true, $mode = 'fast' ) {
		$scan_id = 'scan_' . time() . '_' . wp_generate_password( 6, false );
		$files_manifest = $this->build_files_manifest( $mode );

		$state = array(
			'scan_id'           => $scan_id,
			'status'            => 'running',
			'mode'              => $mode,
			'include_defender'  => (bool) $include_defender,
			'stage'             => $include_defender ? 'defender' : 'core_integrity',
			'stage_index'       => $include_defender ? 1 : 2,
			'total_stages'      => 6,
			'stage_label'       => $include_defender ? 'WP Defender Security Engine' : 'Core WordPress Integrity',
			'files_queue'       => $files_manifest,
			'files_cursor'      => 0,
			'total_files'       => count( $files_manifest ),
			'current_file'      => '',
			'issues'            => array(),
			'defender_scan_id'  => null,
			'defender_complete' => false,
			'started_at'        => time(),
			'updated_at'        => time(),
		);

		if ( $include_defender ) {
			$def_scan_id = $this->trigger_defender_scan();
			$state['defender_scan_id'] = $def_scan_id;
		}

		set_transient( self::STATE_TRANSIENT, $state, HOUR_IN_SECONDS );

		return $this->format_progress_response( $state );
	}

	/**
	 * Execute one micro-batch slice of the active scan.
	 *
	 * @return array Progress snapshot.
	 */
	public function step_scan() {
		$state = get_transient( self::STATE_TRANSIENT );
		if ( ! is_array( $state ) || empty( $state['status'] ) || $state['status'] !== 'running' ) {
			return array(
				'status'  => 'idle',
				'message' => 'No active scan session found.',
			);
		}

		$start_time = microtime( true );
		$batch_processed = 0;

		// Stage 1: Defender Scan Check
		if ( $state['stage'] === 'defender' ) {
			$is_done = $this->check_defender_scan_status( $state );
			if ( $is_done ) {
				$state['stage'] = 'core_integrity';
				$state['stage_index'] = 2;
				$state['stage_label'] = 'Core WordPress Integrity';
			}
			$state['updated_at'] = time();
			set_transient( self::STATE_TRANSIENT, $state, HOUR_IN_SECONDS );
			return $this->format_progress_response( $state );
		}

		// Stage 2: Core Integrity Check
		if ( $state['stage'] === 'core_integrity' ) {
			$core_issues = Mirror_Shield_Heuristics::audit_core_integrity();
			if ( ! empty( $core_issues ) ) {
				$state['issues'] = array_merge( $state['issues'], $core_issues );
			}
			$state['stage'] = 'uploads_traps';
			$state['stage_index'] = 3;
			$state['stage_label'] = 'Uploads Polyglots & Rogue Scripts';
			$state['updated_at'] = time();
			set_transient( self::STATE_TRANSIENT, $state, HOUR_IN_SECONDS );
			return $this->format_progress_response( $state );
		}

		// Stage 3: Uploads Directory Traps & Polyglot Images
		if ( $state['stage'] === 'uploads_traps' ) {
			$upload_issues = Mirror_Shield_Heuristics::audit_uploads_directory();
			if ( ! empty( $upload_issues ) ) {
				$state['issues'] = array_merge( $state['issues'], $upload_issues );
			}
			$state['stage'] = 'db_injections';
			$state['stage_index'] = 4;
			$state['stage_label'] = 'Database Injections & Ghost Admins';
			$state['updated_at'] = time();
			set_transient( self::STATE_TRANSIENT, $state, HOUR_IN_SECONDS );
			return $this->format_progress_response( $state );
		}

		// Stage 4: Database Injections, Ghost Admins & Cron Hooks
		if ( $state['stage'] === 'db_injections' ) {
			$db_issues = Mirror_Shield_Heuristics::audit_database_and_crons();
			if ( ! empty( $db_issues ) ) {
				$state['issues'] = array_merge( $state['issues'], $db_issues );
			}
			$state['stage'] = 'ast_heuristics';
			$state['stage_index'] = 5;
			$state['stage_label'] = 'AST Tokenizer & Shannon Entropy Analysis';
			$state['updated_at'] = time();
			set_transient( self::STATE_TRANSIENT, $state, HOUR_IN_SECONDS );
			return $this->format_progress_response( $state );
		}

		// Stage 5: AST Tokenizer & Heuristics on Target File Queue
		if ( $state['stage'] === 'ast_heuristics' ) {
			$queue = $state['files_queue'];
			$cursor = $state['files_cursor'];
			$total = count( $queue );

			while ( $cursor < $total ) {
				$file_path = $queue[ $cursor ];
				$state['current_file'] = str_replace( ABSPATH, '', $file_path );

				if ( file_exists( $file_path ) && is_readable( $file_path ) ) {
					$findings = Mirror_Shield_Heuristics::inspect_file_ast( $file_path );
					if ( ! empty( $findings ) ) {
						$state['issues'] = array_merge( $state['issues'], $findings );
					}
				}

				$cursor++;
				$batch_processed++;

				if ( self::SLEEP_MICROSECONDS > 0 ) {
					usleep( self::SLEEP_MICROSECONDS );
				}

				$elapsed = microtime( true ) - $start_time;
				if ( $elapsed >= self::MAX_TIME_SLICE || $batch_processed >= self::BATCH_FILE_LIMIT ) {
					break;
				}
			}

			$state['files_cursor'] = $cursor;

			if ( $cursor >= $total ) {
				$state['stage'] = 'completed';
				$state['stage_index'] = 6;
				$state['stage_label'] = 'Scan Complete';
				$state['status'] = 'completed';
				$state['current_file'] = '';
			}
		}

		$state['updated_at'] = time();
		set_transient( self::STATE_TRANSIENT, $state, HOUR_IN_SECONDS );

		return $this->format_progress_response( $state );
	}

	/**
	 * Abort the active scan session.
	 */
	public function cancel_scan() {
		delete_transient( self::STATE_TRANSIENT );
		return array(
			'status'  => 'cancelled',
			'message' => 'Scan cancelled successfully.',
		);
	}

	/**
	 * Get aggregated scan results with Defender synthesis.
	 */
	public function get_results() {
		$state = get_transient( self::STATE_TRANSIENT );
		$native_issues = is_array( $state ) && isset( $state['issues'] ) ? $state['issues'] : array();

		$defender_issues = $this->fetch_defender_scan_issues();

		$defender_file_map = array();
		foreach ( $defender_issues as $def_issue ) {
			if ( ! empty( $def_issue['file'] ) ) {
				$clean = ltrim( str_replace( ABSPATH, '', $def_issue['file'] ), '/' );
				$defender_file_map[ $clean ] = true;
			}
		}

		foreach ( $native_issues as &$issue ) {
			$issue_file = ltrim( str_replace( ABSPATH, '', $issue['file'] ?? '' ), '/' );
			$issue['caught_by'] = 'mirror_shield';
			$issue['missed_by_defender'] = empty( $defender_file_map[ $issue_file ] );
		}
		unset( $issue );

		$all_issues = array_merge( $native_issues, $defender_issues );

		return array(
			'status'                  => is_array( $state ) ? ( $state['status'] ?? 'idle' ) : 'idle',
			'total_issues'            => count( $all_issues ),
			'mirror_shield_issues'    => count( $native_issues ),
			'defender_issues'         => count( $defender_issues ),
			'missed_by_defender_count'=> count( array_filter( $native_issues, fn( $i ) => ! empty( $i['missed_by_defender'] ) ) ),
			'issues'                  => $all_issues,
			'last_scan'               => is_array( $state ) ? ( $state['updated_at'] ?? time() ) : time(),
		);
	}

	/**
	 * Build file queue for AST inspection based on mode.
	 */
	private function build_files_manifest( $mode = 'fast' ) {
		$targets = array();

		$critical_files = array(
			ABSPATH . 'index.php',
			ABSPATH . 'wp-config.php',
			ABSPATH . 'wp-settings.php',
			ABSPATH . 'wp-load.php',
			ABSPATH . 'wp-blog-header.php',
			ABSPATH . '.htaccess',
		);

		foreach ( $critical_files as $cf ) {
			if ( file_exists( $cf ) ) {
				$targets[] = $cf;
			}
		}

		$mu_dir = WPMU_PLUGIN_DIR;
		if ( is_dir( $mu_dir ) ) {
			$targets = array_merge( $targets, Mirror_Shield_Heuristics::collect_php_files( $mu_dir, 2 ) );
		}

		$theme_dir = get_stylesheet_directory();
		if ( is_dir( $theme_dir ) ) {
			$targets = array_merge( $targets, Mirror_Shield_Heuristics::collect_php_files( $theme_dir, 3 ) );
		}

		if ( $mode === 'deep' ) {
			$plugins_dir = WP_PLUGIN_DIR;
			if ( is_dir( $plugins_dir ) ) {
				$targets = array_merge( $targets, Mirror_Shield_Heuristics::collect_php_files( $plugins_dir, 3, 200 ) );
			}
		}

		return array_values( array_unique( $targets ) );
	}

	/**
	 * Programmatically trigger WP Defender's scan mechanism.
	 */
	private function trigger_defender_scan() {
		if ( function_exists( 'wd_di' ) && class_exists( '\WP_Defender\Model\Scan' ) ) {
			try {
				$model = \WP_Defender\Model\Scan::create();
				if ( is_object( $model ) && ! is_wp_error( $model ) ) {
					\WP_Defender\Model\Scan::set_scan_type( 'malware' );
					$scan_controller = wd_di()->get( \WP_Defender\Controller\Scan::class );
					if ( method_exists( $scan_controller, 'run_scan_mechanisms_from' ) ) {
						$scan_controller->run_scan_mechanisms_from( 'scan' );
					}
					return $model->id;
				}
			} catch ( \Throwable $e ) {
				// Fallback
			}
		}
		return null;
	}

	/**
	 * Check if WP Defender scan has concluded.
	 */
	private function check_defender_scan_status( &$state ) {
		global $wpdb;
		$scan_table = $wpdb->prefix . 'defender_scan';

		if ( $wpdb->get_var( "SHOW TABLES LIKE '$scan_table'" ) !== $scan_table ) {
			return true;
		}

		$last_scan = $wpdb->get_row( "SELECT * FROM $scan_table ORDER BY id DESC LIMIT 1" );
		if ( ! $last_scan ) {
			return true;
		}

		if ( in_array( $last_scan->status ?? '', array( 'done', 'error', 'cancelled' ), true ) ) {
			$state['defender_complete'] = true;
			return true;
		}

		return false;
	}

	/**
	 * Fetch WP Defender scan items from database.
	 */
	private function fetch_defender_scan_issues() {
		global $wpdb;
		$scan_table = $wpdb->prefix . 'defender_scan';
		$scan_item_table = $wpdb->prefix . 'defender_scan_item';
		$issues = array();

		if ( $wpdb->get_var( "SHOW TABLES LIKE '$scan_table'" ) !== $scan_table ||
			 $wpdb->get_var( "SHOW TABLES LIKE '$scan_item_table'" ) !== $scan_item_table ) {
			return $issues;
		}

		$last_scan = $wpdb->get_row( "SELECT * FROM $scan_table ORDER BY id DESC LIMIT 1" );
		if ( ! $last_scan ) {
			return $issues;
		}

		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM $scan_item_table WHERE scan_id = %d AND status != 'ignore'",
			$last_scan->id
		) );

		foreach ( $rows as $row ) {
			$raw = maybe_unserialize( $row->raw );
			$file = is_array( $raw ) && ! empty( $raw['file'] ) ? $raw['file'] : ( $row->type ?? 'Integrity Issue' );
			$relative = str_replace( ABSPATH, '', $file );

			$issues[] = array(
				'id'                  => 'def_' . $row->id,
				'category'            => 'defender_engine',
				'severity'            => 'high',
				'file'                => $relative,
				'title'               => 'WP Defender Detected Threat',
				'description'         => is_array( $raw ) && ! empty( $raw['short_desc'] ) ? $raw['short_desc'] : ( $row->detail ?? 'Malware or modified signature detected.' ),
				'caught_by'           => 'defender',
				'missed_by_defender'  => false,
			);
		}

		return $issues;
	}

	/**
	 * Format uniform progress payload.
	 */
	private function format_progress_response( $state ) {
		$total_files = $state['total_files'] > 0 ? $state['total_files'] : 1;
		$cursor = $state['files_cursor'];

		$stage_weights = array(
			'defender'       => array( 'base' => 0,  'span' => 20 ),
			'core_integrity' => array( 'base' => 20, 'span' => 20 ),
			'uploads_traps'  => array( 'base' => 40, 'span' => 20 ),
			'db_injections'  => array( 'base' => 60, 'span' => 20 ),
			'ast_heuristics' => array( 'base' => 80, 'span' => 20 ),
			'completed'      => array( 'base' => 100,'span' => 0 ),
		);

		$current_stage = $state['stage'];
		$weight = $stage_weights[ $current_stage ] ?? array( 'base' => 0, 'span' => 20 );

		if ( $current_stage === 'ast_heuristics' ) {
			$stage_fraction = min( 1, $cursor / $total_files );
			$percent = round( $weight['base'] + ( $weight['span'] * $stage_fraction ) );
		} elseif ( $current_stage === 'completed' ) {
			$percent = 100;
		} else {
			$percent = $weight['base'];
		}

		return array(
			'scan_id'           => $state['scan_id'],
			'status'            => $state['status'],
			'percent'           => min( 100, max( 0, $percent ) ),
			'stage'             => $state['stage'],
			'stage_index'       => $state['stage_index'],
			'total_stages'      => $state['total_stages'],
			'stage_label'       => $state['stage_label'],
			'current_file'      => $state['current_file'],
			'files_scanned'     => $cursor,
			'total_files'       => $state['total_files'],
			'issues_count'      => count( $state['issues'] ),
			'issues'            => $state['issues'],
		);
	}

	/**
	 * Callback for background Action Scheduler / WP-Cron scheduled scans.
	 */
	public function run_scheduled_scan() {
		$this->start_scan( true, 'deep' );
		do {
			$step = $this->step_scan();
		} while ( isset( $step['status'] ) && $step['status'] === 'running' );
	}
}

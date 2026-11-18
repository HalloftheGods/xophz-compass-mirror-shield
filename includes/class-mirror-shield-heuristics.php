<?php
/**
 * Mirror Shield Malware & Integrity Heuristic Checkers
 *
 * Pure heuristic methods for AST token analysis, Shannon entropy,
 * uploads polyglot traps, database injection checks, and core checksums.
 *
 * @package Xophz_Compass_Mirror_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Mirror_Shield_Heuristics {

	const CHECKSUMS_TRANSIENT = 'mirror_shield_core_checksums_';

	/**
	 * Inspect single file via AST Tokenizer and Shannon Entropy.
	 */
	public static function inspect_file_ast( $file_path ) {
		$issues = array();
		$content = @file_get_contents( $file_path );
		if ( empty( $content ) ) {
			return $issues;
		}

		$relative = str_replace( ABSPATH, '', $file_path );
		$tokens = @token_get_all( $content );
		if ( ! is_array( $tokens ) ) {
			return $issues;
		}

		$shell_funcs = array( 'system', 'exec', 'passthru', 'shell_exec', 'proc_open', 'popen' );

		for ( $i = 0; $i < count( $tokens ); $i++ ) {
			$token = $tokens[ $i ];

			if ( is_array( $token ) ) {
				$id = $token[0];
				$text = $token[1];
				$line = $token[2];

				// T_EVAL token
				if ( $id === T_EVAL ) {
					$issues[] = array(
						'id'          => 'ast_eval_' . md5( $file_path . $line ),
						'category'    => 'ast_heuristics',
						'severity'    => 'critical',
						'file'        => $relative,
						'line'        => $line,
						'title'       => 'Arbitrary PHP Execution (eval)',
						'description' => 'Dangerous eval() construct detected.',
					);
				}

				// Dynamic variable execution ($func($args))
				if ( $id === T_VARIABLE && isset( $tokens[ $i + 1 ] ) && $tokens[ $i + 1 ] === '(' ) {
					if ( ! in_array( $text, array( '$callback', '$closure', '$fn' ), true ) ) {
						$issues[] = array(
							'id'          => 'ast_dyn_' . md5( $file_path . $line ),
							'category'    => 'ast_heuristics',
							'severity'    => 'high',
							'file'        => $relative,
							'line'        => $line,
							'title'       => 'Dynamic Variable Execution',
							'description' => "Dynamic function execution ({$text}()) detected, potential obfuscated payload.",
						);
					}
				}

				// Variable variables ($$name)
				if ( $id === T_VARIABLE && isset( $tokens[ $i - 1 ] ) && $tokens[ $i - 1 ] === '$' ) {
					$issues[] = array(
						'id'          => 'ast_varvar_' . md5( $file_path . $line ),
						'category'    => 'ast_heuristics',
						'severity'    => 'high',
						'file'        => $relative,
						'line'        => $line,
						'title'       => 'Variable Variable Injection',
						'description' => 'Dynamic variable resolution ($$' . ltrim( $text, '$' ) . ') detected.',
					);
				}

				// Shell execution functions
				if ( $id === T_STRING && in_array( strtolower( $text ), $shell_funcs, true ) ) {
					$issues[] = array(
						'id'          => 'ast_shell_' . md5( $file_path . $line ),
						'category'    => 'ast_heuristics',
						'severity'    => 'warning',
						'file'        => $relative,
						'line'        => $line,
						'title'       => 'System Command Execution',
						'description' => "Shell execution call ({$text}) found.",
					);
				}

				// High entropy string literal
				if ( $id === T_CONSTANT_ENCAPSED_STRING && strlen( $text ) > 120 ) {
					$clean_str = trim( $text, "'\"" );
					$entropy = self::calculate_shannon_entropy( $clean_str );
					if ( $entropy > 5.5 ) {
						$issues[] = array(
							'id'          => 'ast_entropy_' . md5( $file_path . $line ),
							'category'    => 'ast_heuristics',
							'severity'    => 'high',
							'file'        => $relative,
							'line'        => $line,
							'title'       => 'High-Entropy Packed String Block',
							'description' => "High Shannon Entropy ({$entropy}) detected in string block; possible encrypted or base64 webshell.",
						);
					}
				}
			}
		}

		return $issues;
	}

	/**
	 * Audit uploads directory for executable PHP files, rogue .htaccess, and image polyglots.
	 */
	public static function audit_uploads_directory() {
		$issues = array();
		$upload_dir = wp_upload_dir();
		$basedir = $upload_dir['basedir'];

		if ( ! is_dir( $basedir ) ) {
			return $issues;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $basedir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		$dangerous_exts = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc', 'cgi', 'pl' );
		$checked_images = 0;

		foreach ( $iterator as $item ) {
			if ( $item->isFile() ) {
				$path = $item->getPathname();
				$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
				$relative = str_replace( ABSPATH, '', $path );

				if ( in_array( $ext, $dangerous_exts, true ) ) {
					$issues[] = array(
						'id'          => 'upload_exec_' . md5( $path ),
						'category'    => 'uploads_traps',
						'severity'    => 'critical',
						'file'        => $relative,
						'title'       => 'Executable Script in Uploads Directory',
						'description' => "Executable file with .{$ext} extension detected in public uploads folder.",
					);
				}

				if ( $item->getFilename() === '.htaccess' ) {
					$content = @file_get_contents( $path );
					if ( $content && ( stripos( $content, 'SetHandler' ) !== false || stripos( $content, 'AddType' ) !== false || stripos( $content, 'php_value' ) !== false ) ) {
						$issues[] = array(
							'id'          => 'upload_htaccess_' . md5( $path ),
							'category'    => 'uploads_traps',
							'severity'    => 'critical',
							'file'        => $relative,
							'title'       => 'Malicious .htaccess in Uploads',
							'description' => '.htaccess file in uploads directory attempting to override PHP execution handlers.',
						);
					}
				}

				if ( in_array( $ext, array( 'jpg', 'jpeg', 'png', 'gif', 'webp' ), true ) && $checked_images < 100 ) {
					$checked_images++;
					$head = @file_get_contents( $path, false, null, 0, 1024 );
					if ( $head && ( stripos( $head, '<?php' ) !== false || stripos( $head, '<?=' ) !== false ) ) {
						$issues[] = array(
							'id'          => 'upload_polyglot_' . md5( $path ),
							'category'    => 'uploads_traps',
							'severity'    => 'critical',
							'file'        => $relative,
							'title'       => 'Image Polyglot Webshell',
							'description' => "Image file {$relative} contains embedded PHP code execution headers.",
						);
					}
				}
			}
		}

		return $issues;
	}

	/**
	 * Audit database options, rogue ghost administrators, and WP-Cron hooks.
	 */
	public static function audit_database_and_crons() {
		global $wpdb;
		$issues = array();

		$critical_options = array( 'siteurl', 'home', 'blogname', 'default_role' );
		foreach ( $critical_options as $opt_name ) {
			$val = get_option( $opt_name, '' );
			if ( is_string( $val ) && ( stripos( $val, '<script' ) !== false || stripos( $val, 'javascript:' ) !== false ) ) {
				$issues[] = array(
					'id'          => 'db_opt_' . $opt_name,
					'category'    => 'db_injections',
					'severity'    => 'critical',
					'file'        => "wp_options:{$opt_name}",
					'title'       => "Injected Script in Option ({$opt_name})",
					'description' => "Malicious HTML script tag detected inside core WordPress option {$opt_name}.",
				);
			}
		}

		$admin_users = $wpdb->get_results( $wpdb->prepare(
			"SELECT u.ID, u.user_login, u.user_email, u.user_registered
			FROM {$wpdb->users} u
			INNER JOIN {$wpdb->usermeta} m ON u.ID = m.user_id
			WHERE m.meta_key = %s AND m.meta_value LIKE %s",
			$wpdb->prefix . 'capabilities',
			'%administrator%'
		) );

		foreach ( $admin_users as $admin ) {
			if ( empty( $admin->user_email ) || ! is_email( $admin->user_email ) ) {
				$issues[] = array(
					'id'          => 'db_ghost_admin_' . $admin->ID,
					'category'    => 'db_injections',
					'severity'    => 'critical',
					'file'        => "wp_users:ID={$admin->ID} ({$admin->user_login})",
					'title'       => 'Ghost Administrator Account',
					'description' => "Administrator account '{$admin->user_login}' has no valid registered email address.",
				);
			}
		}

		$crons = _get_cron_array();
		if ( is_array( $crons ) ) {
			foreach ( $crons as $timestamp => $hooks ) {
				foreach ( $hooks as $hook_name => $hook_events ) {
					if ( stripos( $hook_name, 'eval' ) !== false || stripos( $hook_name, 'base64' ) !== false || stripos( $hook_name, 'system' ) !== false ) {
						$issues[] = array(
							'id'          => 'cron_anomaly_' . md5( $hook_name ),
							'category'    => 'db_injections',
							'severity'    => 'high',
							'file'        => "wp_cron:{$hook_name}",
							'title'       => 'Suspicious WP-Cron Scheduled Hook',
							'description' => "Cron hook '{$hook_name}' contains suspicious naming pattern.",
						);
					}
				}
			}
		}

		return $issues;
	}

	/**
	 * Audit WordPress core files against official WordPress.org checksums.
	 */
	public static function audit_core_integrity() {
		global $wp_version, $wp_local_package;
		$issues = array();

		$locale = ! empty( $wp_local_package ) ? $wp_local_package : get_locale();
		$transient_key = self::CHECKSUMS_TRANSIENT . md5( $wp_version . $locale );
		$checksums = get_transient( $transient_key );

		if ( false === $checksums ) {
			$url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
			$response = wp_remote_get( $url, array( 'timeout' => 8 ) );
			if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
				$body = json_decode( wp_remote_retrieve_body( $response ), true );
				if ( ! empty( $body['checksums'] ) && is_array( $body['checksums'] ) ) {
					$checksums = $body['checksums'];
					set_transient( $transient_key, $checksums, DAY_IN_SECONDS );
				}
			}
		}

		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			return $issues;
		}

		$checked = 0;
		foreach ( $checksums as $file => $expected_md5 ) {
			if ( strpos( $file, 'wp-content' ) === 0 || $checked > 40 ) {
				continue;
			}

			$full_path = ABSPATH . $file;
			if ( ! file_exists( $full_path ) ) {
				$issues[] = array(
					'id'          => 'core_missing_' . md5( $file ),
					'category'    => 'core_integrity',
					'severity'    => 'critical',
					'file'        => $file,
					'title'       => 'Missing WordPress Core File',
					'description' => "Essential core file {$file} is missing from the installation.",
				);
			} else {
				$actual_md5 = md5_file( $full_path );
				if ( $actual_md5 !== $expected_md5 ) {
					$issues[] = array(
						'id'          => 'core_modified_' . md5( $file ),
						'category'    => 'core_integrity',
						'severity'    => 'critical',
						'file'        => $file,
						'title'       => 'Modified WordPress Core File',
						'description' => "Checksum mismatch in {$file}. Official core file has been tampered with or modified.",
					);
				}
			}
			$checked++;
		}

		return $issues;
	}

	/**
	 * Compute Shannon Entropy of a string block.
	 */
	public static function calculate_shannon_entropy( $str ) {
		$len = strlen( $str );
		if ( $len === 0 ) {
			return 0.0;
		}

		$frequencies = count_chars( $str, 1 );
		$entropy = 0.0;

		foreach ( $frequencies as $count ) {
			$p = $count / $len;
			$entropy -= $p * log( $p, 2 );
		}

		return round( $entropy, 2 );
	}

	/**
	 * Recursively collect PHP files up to max depth.
	 */
	public static function collect_php_files( $dir, $max_depth = 2, $limit = 100, $current_depth = 0 ) {
		$files = array();
		if ( $current_depth >= $max_depth || ! is_dir( $dir ) || ! is_readable( $dir ) ) {
			return $files;
		}

		$items = scandir( $dir );
		if ( false === $items ) {
			return $files;
		}

		foreach ( $items as $item ) {
			if ( $item === '.' || $item === '..' || $item === '.git' || $item === 'node_modules' || $item === 'vendor' ) {
				continue;
			}

			$path = $dir . '/' . $item;
			if ( is_dir( $path ) ) {
				$sub = self::collect_php_files( $path, $max_depth, $limit, $current_depth + 1 );
				$files = array_merge( $files, $sub );
				if ( count( $files) >= $limit ) {
					break;
				}
			} elseif ( is_file( $path ) && pathinfo( $path, PATHINFO_EXTENSION ) === 'php' ) {
				$files[] = $path;
				if ( count( $files ) >= $limit ) {
					break;
				}
			}
		}

		return $files;
	}
}

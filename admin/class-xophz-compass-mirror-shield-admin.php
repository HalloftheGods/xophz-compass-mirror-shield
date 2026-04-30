<?php

/**
 * The admin-specific functionality of the plugin.
 *
 * @link       http://example.com
 * @since      1.0.0
 *
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/admin
 */

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @package    Xophz_Compass_Mirror_Shield
 * @subpackage Xophz_Compass_Mirror_Shield/admin
 * @author     Your Name <email@example.com>
 */
class Xophz_Compass_Mirror_Shield_Admin {

	/**
	 * The ID of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $plugin_name    The ID of this plugin.
	 */
	private $plugin_name;

	/**
	 * The version of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $version    The current version of this plugin.
	 */
	private $version;

	/**
	 * Initialize the class and set its properties.
	 *
	 * @since    1.0.0
	 * @param      string    $plugin_name       The name of this plugin.
	 * @param      string    $version    The version of this plugin.
	 */
	public function __construct( $plugin_name, $version ) {

		$this->plugin_name = $plugin_name;
		$this->version = $version;

	}

	/**
	 * Register the stylesheets for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_styles() {

		/**
		 * This function is provided for demonstration purposes only.
		 *
		 * An instance of this class should be passed to the run() function
		 * defined in Xophz_Compass_Mirror_Shield_Loader as all of the hooks are defined
		 * in that particular class.
		 *
		 * The Xophz_Compass_Mirror_Shield_Loader will then create the relationship
		 * between the defined hooks and the functions defined in this
		 * class.
		 */

		wp_enqueue_style( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'css/xophz-compass-mirror-shield-admin.css', array(), $this->version, 'all' );

	}

	/**
	 * Register the JavaScript for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_scripts() {

		/**
		 * This function is provided for demonstration purposes only.
		 *
		 * An instance of this class should be passed to the run() function
		 * defined in Xophz_Compass_Mirror_Shield_Loader as all of the hooks are defined
		 * in that particular class.
		 *
		 * The Xophz_Compass_Mirror_Shield_Loader will then create the relationship
		 * between the defined hooks and the functions defined in this
		 * class.
		 */

		wp_enqueue_script( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'js/xophz-compass-mirror-shield-admin.js', array( 'jquery' ), $this->version, false );

	}

	/**
	 * Add menu item 
	 *
	 * @since    1.0.0
	 */
	public function addToMenu(){
        Xophz_Compass::add_submenu($this->plugin_name);
	}

	/**
	 * Register the settings for My Compass handled by Mirror Shield
	 */
	public function register_settings() {
		register_setting( 'xophz_compass_settings_group', 'xophz_compass_members_only_enabled' );
		register_setting( 'xophz_compass_settings_group', 'xophz_compass_members_only_default_tiers', array(
			'type' => 'array',
			'sanitize_callback' => function( $val ) {
				return is_array( $val ) ? array_map( 'sanitize_text_field', $val ) : array();
			}
		) );

		add_settings_section(
			'xophz_compass_members_only_section',
			'Members Only Post Feature (Mirror Shield)',
			function() {
				echo '<p>Configure the default behavior for the Members Only post feature, protected by Mirror Shield.</p>';
			},
			'w4-my-compass'
		);

		add_settings_field(
			'xophz_compass_members_only_enabled',
			'Enable Members Only Feature',
			function() {
				$val = get_option( 'xophz_compass_members_only_enabled', '0' );
				echo '<label><input type="checkbox" name="xophz_compass_members_only_enabled" value="1" ' . checked( 1, $val, false ) . ' /> Turn on the Members Only content restriction feature globally.</label>';
			},
			'w4-my-compass',
			'xophz_compass_members_only_section'
		);

		add_settings_field(
			'xophz_compass_members_only_default_tiers',
			'Default Tiers',
			function() {
				$val = get_option( 'xophz_compass_members_only_default_tiers', array() );
				if ( ! is_array( $val ) ) {
					$val = array();
				}
				global $wp_roles;
				if ( ! isset( $wp_roles ) ) {
					$wp_roles = new WP_Roles();
				}
				$roles = $wp_roles->get_names();
				
				echo '<div style="margin-bottom: 8px; font-size: 13px;">
					<a href="#" style="text-decoration: none;" onclick="event.preventDefault(); var cbs = this.parentElement.nextElementSibling.querySelectorAll(\'input[type=checkbox]\'); cbs.forEach(cb => cb.checked = true);">Select All</a> &nbsp;|&nbsp; 
					<a href="#" style="text-decoration: none;" onclick="event.preventDefault(); var cbs = this.parentElement.nextElementSibling.querySelectorAll(\'input[type=checkbox]\'); cbs.forEach(cb => cb.checked = false);">Clear</a>
				</div>';
				echo '<fieldset style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; background: rgba(0,0,0,0.02); border: 1px solid rgba(0,0,0,0.05); padding: 16px; border-radius: 8px; max-width: 600px;">';
				foreach ( $roles as $role_slug => $role_name ) {
					$role_data = $wp_roles->roles[$role_slug];
					$caps = isset($role_data['capabilities']) ? $role_data['capabilities'] : array();
					
					$summary = 'Read Only';
					if ( ! empty( $caps['manage_options'] ) ) $summary = 'Full Admin Access';
					elseif ( ! empty( $caps['edit_others_posts'] ) ) $summary = 'Manage All Content';
					elseif ( ! empty( $caps['publish_posts'] ) ) $summary = 'Publish Content';
					elseif ( ! empty( $caps['edit_posts'] ) ) $summary = 'Write Content';
					
					$active_caps = array_keys( array_filter( $caps ) );
					$caps_tooltip = implode( ', ', $active_caps );

					echo '<label title="' . esc_attr( $caps_tooltip ) . '" style="display: flex; align-items: flex-start; gap: 8px; cursor: pointer; user-select: none;">';
					echo '<input style="margin-top: 3px;" type="checkbox" name="xophz_compass_members_only_default_tiers[]" value="' . esc_attr( $role_slug ) . '" ' . checked( in_array( $role_slug, $val ), true, false ) . '>';
					echo '<div style="display: flex; flex-direction: column;">';
					echo '<span style="font-weight: 600;">' . esc_html( $role_name ) . '</span>';
					echo '<span style="font-size: 10px; opacity: 0.6; line-height: 1.2;">' . esc_html( $summary ) . '</span>';
					echo '</div>';
					echo '</label>';
				}
				echo '</fieldset>';
				echo '<p class="description">Select the default tiers allowed to view Members Only posts.</p>';
			},
			'w4-my-compass',
			'xophz_compass_members_only_section'
		);
	}

}

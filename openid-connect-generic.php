<?php
/*
Plugin Name: OpenID Connect Generic
Plugin URI: https://github.com/daggerhart/openid-connect-generic
Description:  Connect to an OpenID Connect generic client using Authorization Code Flow - Forked de daggerhard.
Version: 3.5.0-dnc1
Author: bdegoy
Author URI: https://degoy.com
License: GPLv2 Copyright (c) 2019 bdegoy
*/

/*
Notes
  Spec Doc - http://openid.net/specs/openid-connect-basic-1_0-32.html

  Filters
  - openid-connect-generic-alter-request      - 2 args: request array, specific request op
  - openid-connect-generic-settings-fields    - modify the fields provided on the settings page
  - openid-connect-generic-login-button-text  - modify the login button text
  - openid-connect-generic-user-login-test    - (bool) should the user be logged in based on their claim
  - openid-connect-generic-user-creation-test - (bool) should the user be created based on their claim
  - openid-connect-generic-auth-url           - modify the authentication url
  - openid-connect-generic-alter-user-claim   - modify the user_claim before a new user is created
  - openid-connect-generic-alter-user-data    - modify user data before a new user is created

  Actions
  - openid-connect-generic-user-create        - 2 args: fires when a new user is created by this plugin
  - openid-connect-generic-user-update        - 1 arg: user ID, fires when user is updated by this plugin
  - openid-connect-generic-update-user-using-current-claim - 2 args: fires every time an existing user logs
  - openid-connect-generic-redirect-user-back - 2 args: $redirect_url, $user. Allows interruption of redirect during login.

  User Meta
  - openid-connect-generic-subject-identity    - the identity of the user provided by the idp
  - openid-connect-generic-last-id-token-claim - the user's most recent id_token claim, decoded
  - openid-connect-generic-last-user-claim     - the user's most recent user_claim
  - openid-connect-generic-last-token-response - the user's most recent token response

  Options
  - openid_connect_generic_settings     - plugin settings
  - openid-connect-generic-valid-states - locally stored generated states
*/


class OpenID_Connect_Generic {
	// plugin version
	const VERSION = '3.5.0';

	// plugin settings
	private $settings;

	// plugin logs
	private $logger;

	// openid connect generic client
	private $client;

	// settings admin page
	private $settings_page;

	// login form adjustments
	private $login_form;

	/**
	 * Setup the plugin
	 *
	 * @param OpenID_Connect_Generic_Option_Settings $settings
	 * @param OpenID_Connect_Generic_Option_Logger $logger
	 */
	function __construct( OpenID_Connect_Generic_Option_Settings $settings, OpenID_Connect_Generic_Option_Logger $logger ){
		$this->settings = $settings;
		$this->logger = $logger;
	}

	/**
	 * WP Hook 'init'
	 */
	function init(){

		$redirect_uri = admin_url( 'admin-ajax.php?action=openid-connect-authorize' );

		if ( $this->settings->alternate_redirect_uri ){
			$redirect_uri = site_url( '/openid-connect-authorize' );
		}

		$state_time_limit = 180;
		if ($this->settings->state_time_limit) {
			$state_time_limit = intval($this->settings->state_time_limit);
		}

		$this->client = new OpenID_Connect_Generic_Client(
			$this->settings->client_id,
			$this->settings->client_secret,
			$this->settings->scope,
			$this->settings->endpoint_login,
			$this->settings->endpoint_userinfo,
			$this->settings->endpoint_token,
			$redirect_uri,
			$state_time_limit
		);

		$this->client_wrapper = OpenID_Connect_Generic_Client_Wrapper::register( $this->client, $this->settings, $this->logger );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$this->login_form = OpenID_Connect_Generic_Login_Form::register( $this->settings, $this->client_wrapper );

		// add a shortcode to get the auth url
		add_shortcode( 'openid_connect_generic_auth_url', array( $this->client_wrapper, 'get_authentication_url' ) );

		$this->upgrade();

		if ( is_admin() ){
			$this->settings_page = OpenID_Connect_Generic_Settings_Page::register( $this->settings, $this->logger );
		}
	}

	/**
	 * Check if privacy enforcement is enabled, and redirect users that aren't
	 * logged in.
	 */
	function enforce_privacy_redirect() {
		if ( $this->settings->enforce_privacy && ! is_user_logged_in() ) {
			// our client endpoint relies on the wp admind ajax endpoint
			if ( ! defined( 'DOING_AJAX') || ! DOING_AJAX || ! isset( $_GET['action'] ) || $_GET['action'] != 'openid-connect-authorize' ) {
				auth_redirect();
			}
		}
	}

	/**
	 * Enforce privacy settings for rss feeds
	 *
	 * @param $content
	 *
	 * @return mixed
	 */
	function enforce_privacy_feeds( $content ){
		if ( $this->settings->enforce_privacy && ! is_user_logged_in() ) {
			$content = 'Private site';
		}
		return $content;
	}

	/**
	 * Handle plugin upgrades
	 */
	function upgrade(){
		$last_version = get_option( 'openid-connect-generic-plugin-version', 0 );
		$settings = $this->settings;

		if ( version_compare( self::VERSION, $last_version, '>' ) ) {
			// upgrade required

			// @todo move this to another file for upgrade scripts
			if ( isset( $settings->ep_login ) ) {
				$settings->endpoint_login = $settings->ep_login;
				$settings->endpoint_token = $settings->ep_token;
				$settings->endpoint_userinfo = $settings->ep_userinfo;

				unset( $settings->ep_login, $settings->ep_token, $settings->ep_userinfo );
				$settings->save();
			}

			// update the stored version number
			update_option( 'openid-connect-generic-plugin-version', self::VERSION );
		}
	}
    
    
    /**
    * OAuthSD project https://oa.dnc.global
    * OAuthSD OIDC plugin for WordPress
    * Author : bdegoy DnC https://degoy.com
    *
    * Insert monitoring code in footer
    * dnc1
    */
    function insert_monitoring() {
     
        // Enqueue some jQuery UIs
        wp_enqueue_script('jquery-ui-dialog'); // from WP core
        // get registered script object for jquery-ui
        global $wp_scripts;
        $ui = $wp_scripts->query('jquery-ui-core');
        // load the Smoothness theme from Google CDN  
        $protocol = is_ssl() ? 'https' : 'http';
        $url = "$protocol://ajax.googleapis.com/ajax/libs/jqueryui/{$ui->ver}/themes/smoothness/jquery-ui.min.css";
        wp_enqueue_style('jquery-ui-smoothness', $url, false, null);
           
        // OIDC Client Monitoring
        $thisuri = $_SERVER['REQUEST_URI'];
        $absolutepath_this_plugin = plugin_dir_path( __FILE__ );
        $url_this_plugin = plugins_url('', dirname(__FILE__) ) . "/openid-connect-generic";
        $state = md5(wp_get_session_token());
        
        // Server URLs
        $settings = $this->settings;
        $url_endpoint_login = $settings->endpoint_login;
        $url_endpoint_token = $settings->endpoint_token;
        $url_endpoint_userinfo = $settings->endpoint_userinfo;
        $url_endpoint_logout = $settings->endpoint_end_session;
        $parts = parse_url($url_endpoint_login);
        $url_server = $parts['scheme'] . '://' . $parts['host'];
        
        // OIDC user
        $clientID = $settings->client_id;
        // $userID = ??? 
        
        // WP user
        $user = get_user_by('id', get_current_user_id());
        $login = $user->user_login;
        $nom_auteur =$user->display_name;
        
        // for info popup
        $infos =
        '<br/>' . __('oidcclient:serveur_url','openid-connect-generic') . ' : <a href="' . $url_server . '">' . $url_server . '</a>' .
        '<br/>' . __('oidcclient:client_id','openid-connect-generic') . ' : ' . $clientID . 
        '<br/>' . __('oidcclient:login_wp','openid-connect-generic') . ' : ' . $login .
        //'<br/>' . __('oidcclient:login_oidc_court','openid-connect-generic') . ' : ' .  $userID . 
        '<br/>' . __('oidcclient:nom_auteur','openid-connect-generic') . ' : ' .  $nom_auteur; 
        
        // labels and messages
        $msg_session_connected_no = __('oidcclient:session_connected_no','openid-connect-generic');
        $msg_session_connected_yes = __('oidcclient:session_connected_yes','openid-connect-generic');
        $msg_session_connected_error = __('oidcclient:session_connected_error','openid-connect-generic');
        $msg_session_open = __('oidcclient:session_open','openid-connect-generic');
        $msg_session_extend = __('oidcclient:session_extend','openid-connect-generic');
        $msg_session_close = __('oidcclient:session_close','openid-connect-generic');
        $msg_session_expires = __('oidcclient:session_expires','openid-connect-generic');
        $lbl_yes = __('oidcclient:item_yes','openid-connect-generic');
        $lbl_no = __('oidcclient:item_no','openid-connect-generic');
        $lbl_t_session_restant = __('oidcclient:t_session_restant','openid-connect-generic');
        $lbl_delai_reponse = __('oidcclient:delai_reponse','openid-connect-generic');
        $lbl_infos_titre = __('oidcclient:lbl_infos_titre','openid-connect-generic');
        
        // link to OIDC login                                                                                         
        $link_login = $this->client_wrapper->get_authentication_url();
        
        // link to logout page
        $url_logout = esc_url($url_this_plugin . "/oidc_logout.php?url=" . $_SERVER['REQUEST_URI']);
    
        echo <<<JSCODE
            
<script type="text/javascript">
    
(function($) {

    var login = "$login";
    var timeleft = 0;
    var connected = 0;
    var connectionMsg = '';
    var interval = null;
    var pollperiod = 60000;
    var tagappendto = '#content';
    var tagtop = '92px';
    var tagleft = '16px';
    var responseDelay = 'Unk';

    $(document).on('ready',function(){

        // Add OIDC labels
        if($('#oidc').length === 0){
            $('<div id="oidc"><span id="oidctag">&nbsp;OIDC&nbsp;</span><span id="oidcinfo">&nbsp;?&nbsp;</span></div>')
            .appendTo(tagappendto);
            //
            $('#oidc')
            .css('position','absolute')
            .css('top',tagtop)
            .css('left',tagleft);
            //
            $('#oidctag')
            .css('color','white')
            .css('padding','3px')
            .css('z-index','10000')
            .on('click', function(){
                switch (connected) {
                    case 0 :
                        connectionMsg = "$msg_session_connected_no";
                        SessionOpenDialog(connectionMsg);
                        break;
                    case 1 :
                        connectionMsg = "$msg_session_connected_yes";
                        SessionCloseDialog(connectionMsg);
                        break;
                    default :
                    case -1 :
                        connectionMsg = "$msg_session_connected_error";
                        break;
                }; 
            });
            //
            $('#oidcinfo') 
            .css('color','white')
            .css('padding','3px')
            .css('z-index','10001')
            .css('background-color','#09f')
            .on('click', function(){
                $('<div></div>').appendTo('body')
                .html('<div><h6>$infos<br/>$lbl_t_session_restant : ' + timeleft + ' s<br/>$lbl_delai_reponse : ' + responseDelay + ' ms</h6></div>')
                .dialog({
                    modal: true, title: "$lbl_infos_titre", zIndex: 10000, autoOpen: true,
                    width: 'auto', resizable: false,
                    close: function (event, ui) {
                        $(this).remove();
                        interval = setInterval(pollOidc,pollperiod);
                        }
                    });
                } 
            );             
        }

        // If user is logged locally, verify the OIDC session is valid.  
        if ( login !== "" ) {
            pollOidc();
            interval = setInterval(pollOidc,pollperiod);

        } else {
            connected = 0; 
            // Show not OIDC connected. 
            $('#oidctag').css('background-color', 'orange');
            $('#oidctag').text(' OIDC ');
        }

        function SessionCloseDialog(message) {    //[dnc28d]
            clearInterval(interval);
            $('<div></div>').appendTo('body')
            .html('<div><h6>'+message+'?</h6></div>')
            .dialog({
                modal: true, title: "$msg_session_close", zIndex: 10000, autoOpen: true,
                width: 'auto', resizable: false,
                buttons: [
                    {
                        text: "$lbl_yes",
                        click: function () {
                            // Close the OIDC session.
                            window.location.replace("$url_logout");
                            $(this).dialog("close");
                        }
                    },{
                        text: "$lbl_no",
                        click: function () {                                                               
                            $(this).dialog("close");
                            interval = setInterval(pollOidc,pollperiod);
                        }
                    }
                ],
                close: function (event, ui) {
                    $(this).remove();
                    interval = setInterval(pollOidc,pollperiod);
                }
            });
        };

        function SessionOpenDialog(message) {    //[dnc28d]
            clearInterval(interval);
            $('<div></div>').appendTo('body')
            .html('<div><h6>'+message+'?</h6></div>')
            .dialog({
                modal: true, title: "$msg_session_open", zIndex: 10000, autoOpen: true,
                width: 'auto', resizable: false,
                buttons: [
                    {
                        text: "$lbl_yes",
                        click: function () {
                            // Se connecter
                            window.location.replace("$link_login");
                            $(this).dialog("close");
                        }
                    },{
                        text: "$lbl_no",
                        click: function () {                                                                 
                            $(this).dialog("close");
                            interval = setInterval(pollOidc,pollperiod);
                        }
                    }
                ],
                close: function (event, ui) {
                    $(this).remove();
                    interval = setInterval(pollOidc,pollperiod);
                }
            });
        };

        function ExtendDialog(message) {    //[dnc28d]
            clearInterval(interval);
            $('<div></div>').appendTo('body')
            .html('<div><h6>'+message+'?</h6></div>')
            .dialog({
                modal: true, title: "$msg_session_extend", zIndex: 10000, autoOpen: true,
                width: 'auto', resizable: false,
                buttons: [
                    {
                        text: "$lbl_yes",
                        click: function () {
                            // Extend session
                            $.ajax({
                                type : "get",
                                url : "$url_endpoint_login",
                                data : { 'response_type' : 'code',
                                    'client_id' : "$clientID",
                                    'user_id' : login,
                                    'state' :  "$state",
                                    'scope' : 'openid sli',
                                } 
                            });
                            $(this).dialog("close");
                            interval = setInterval(pollOidc,pollperiod);
                        }
                    },{
                        text: "$lbl_no",
                        click: function () {                                                                 
                            $(this).dialog("close");
                            interval = setInterval(pollOidc,pollperiod);
                        },
                    }
                ],
                close: function (event, ui) {
                    $(this).remove();
                    interval = setInterval(pollOidc,pollperiod);
                },
            });
        };

        // Test OIDC connection.
        function pollOidc(){
            connected = -1;
            var d = new Date();
            var timeStart = d.getTime();
            var timeStop = 0;
            $.ajax({
                type : "get",
                url : "$url_endpoint_login",
                data : { 'response_type' : 'code',
                    'client_id' : "$clientID",
                    'user_id' : login,
                    'state' :  "$state",
                    'scope' : 'openid',
                    'prompt' : 'none',
                },
                statusCode : {
                    401 : function(){
                        connected = 0;
                        var d = new Date();
                        timeStop = d.getTime();
                        // Not (or no longer) connected on OIDC, disconnect locally
                        window.location.replace("$url_logout" +"&logout=local");
                    },
                    200 : function ( data, textStatus, jqXHR){
                        connected = 1;
                        var d = new Date();
                        timeStop = d.getTime();
                        // Show OIDC connected 
                        $('#oidctag').css('background-color', '#8f8');
                        $('#oidctag').text(' OIDC ');
                        timeleft = data['timeleft'];
                        if ( timeleft < 600 ) {  //[dnc28d]
                            // Approaching OIDC session end.
                            clearInterval(interval); 
                            ExtendDialog("$msg_session_expires");
                            interval = setInterval(pollOidc,pollperiod);
                        }
                    },
                },
                error : function(obj,textStatus,errorThrown){
                    connected = -1;
                    // Show error (OIDC state is unknown)
                    $('#oidctag').css('background-color', 'red');
                    $('#oidctag').text(textStatus + ' ' + errorThrown);
                },
                complete : function ( data, textStatus, jqXHR){
                    if ( timeStop && timeStart ) {
                        responseDelay = timeStop - timeStart;       
                    } else {
                        responseDelay = 'Unk';
                    }
                },
            });    
        } 

    });
})( jQuery );

</script>

JSCODE
;
    
} //function



	/**
	 * Simple autoloader
	 *
	 * @param $class
	 */
	static public function autoload( $class ) {
		$prefix = 'OpenID_Connect_Generic_';

		if ( stripos($class, $prefix) !== 0 ) {
			return;
		}

		$filename = $class . '.php';

		// internal files are all lowercase and use dashes in filenames
		if ( false === strpos( $filename, '\\' ) ) {
			$filename = strtolower( str_replace( '_', '-', $filename ) );
		}
		else {
			$filename  = str_replace('\\', DIRECTORY_SEPARATOR, $filename);
		}

		$filepath = dirname( __FILE__ ) . '/includes/' . $filename;

		if ( file_exists( $filepath ) ) {
			require_once $filepath;
		}
	}
    

	/**
	 * Instantiate the plugin and hook into WP
	 */
	static public function bootstrap(){
		spl_autoload_register( array( 'OpenID_Connect_Generic', 'autoload' ) );

		$settings = new OpenID_Connect_Generic_Option_Settings(
			'openid_connect_generic_settings',
			// default settings values
			array(
				// oauth client settings
				'login_type'        => 'button',
				'client_id'         => '',
				'client_secret'     => '',
				'scope'             => '',
				'endpoint_login'    => '',
				'endpoint_userinfo' => '',
				'endpoint_token'    => '',
				'endpoint_end_session' => '',

				// non-standard settings
				'no_sslverify'    => 0,
				'http_request_timeout' => 5,
				'identity_key'    => 'preferred_username',
				'nickname_key'    => 'preferred_username',
				'email_format'       => '{email}',
				'displayname_format' => '',
				'identify_with_username' => false,

				// plugin settings
				'enforce_privacy' => 0,
				'alternate_redirect_uri' => 0,
				'link_existing_users' => 0,
				'redirect_user_back' => 0,
				'redirect_on_logout' => 1,
				'enable_logging'  => 0,
				'log_limit'       => 1000,
			)
		);

		$logger = new OpenID_Connect_Generic_Option_Logger( 'openid-connect-generic-logs', 'error', $settings->enable_logging, $settings->log_limit );

		$plugin = new self( $settings, $logger );

		add_action( 'init', array( $plugin, 'init' ) );

		// privacy hooks
		add_action( 'template_redirect', array( $plugin, 'enforce_privacy_redirect' ), 0 );
		add_filter( 'the_content_feed', array( $plugin, 'enforce_privacy_feeds' ), 999 );
		add_filter( 'the_excerpt_rss',  array( $plugin, 'enforce_privacy_feeds' ), 999 );
		add_filter( 'comment_text_rss', array( $plugin, 'enforce_privacy_feeds' ), 999 );
        
        //dnc1 OIDC Monitoring
        wp_enqueue_script("jquery"); 
        add_action('wp_footer', array( $plugin, 'insert_monitoring'), 5);
              
	}
}

OpenID_Connect_Generic::bootstrap();

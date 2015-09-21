<?php

class OpenID_Connect_Generic_Client_Wrapper {
	
	private $client;
	
	// settings object
	private $settings;
	
	// logger object
	private $logger;

	// internal tracking cookie key
	private $cookie_id_key = 'openid-connect-generic-identity';
	
	// WP_Error if there was a problem, or false if no error
	private $error = false;

	
	/**
	 * Inject necessary objects and services into the client
	 * 
	 * @param \WP_Option_Settings $settings
	 * @param \WP_Option_Logger $logger
	 */
	function __construct( OpenID_Connect_Generic_Client $client, WP_Option_Settings $settings, WP_Option_Logger $logger ){
		$this->client = $client;
		$this->settings = $settings;
		$this->logger = $logger;
	}

	/**
	 * Hook the client into WP
	 * 
	 * @param \OpenID_Connect_Generic_Client $client
	 * @param \WP_Option_Settings $settings
	 * @param \WP_Option_Logger $logger
	 */
	static public function register( OpenID_Connect_Generic_Client $client, WP_Option_Settings $settings, WP_Option_Logger $logger ){
		$client_wrapper  = new self( $client, $settings, $logger );
		
		// remove cookies on logout
		add_action( 'wp_logout', array( $client_wrapper, 'wp_logout' ) );

		// verify legitimacy of user token on admin pages
		add_action( 'admin_init', array( $client_wrapper, 'check_user_token' ) );

		// alter the requests according to settings
		add_filter( 'openid-connect-generic-alter-request', array( $client_wrapper, 'alter_request' ), 10, 3 );

		if ( is_admin() ) {
			// use the ajax url to handle processing authorization without any html output
			// this callback will occur when then IDP returns with an authenticated value
			add_action( 'wp_ajax_openid-connect-authorize', array( $client_wrapper, 'authentication_request_callback' ) );
			add_action( 'wp_ajax_nopriv_openid-connect-authorize', array( $client_wrapper, 'authentication_request_callback' ) );
		}
		
		$client_wrapper->startup();
		
		return $client_wrapper;
	}

	/**
	 * Handle the initial validation that should occur on each page load
	 */
	function startup(){
		$this->handle_privacy();

		// verify token for any logged in user
		if ( is_user_logged_in() ) {
			$this->check_user_token();
		}
	}

	/**
	 * Get the authentication url from the client
	 * 
	 * @return string
	 */
	function get_authentication_url(){
		return $this->client->make_authentication_url();
	}
	
	/**
	 * Handle the privacy settings
	 */
	function handle_privacy() {
		// check if privacy enforcement is enabled
		if ( $this->settings->enforce_privacy &&
		     ! is_user_logged_in() &&
		     // avoid redirects on cron or ajax
		     ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) &&
		     ( ! defined( 'DOING_CRON' ) || ! DOING_CRON )
		) {
			global $pagenow;

			// avoid redirect loop
			if ( $pagenow != 'wp-login.php' && ! isset( $_GET['loggedout'] ) && ! isset( $_GET['login-error'] ) ) {
				$this->error_redirect( new WP_Error( 'privacy', __( 'This site requires login.' ), $_GET ) );
			}
		}
	}

	/**
	 * Check the user's cookie
	 */
	function check_user_token() {
		$is_openid_connect_user = get_user_meta( wp_get_current_user()->ID, 'openid-connect-generic-user', TRUE );

		if ( is_user_logged_in() && ! empty( $is_openid_connect_user ) && ! isset( $_COOKIE[ $this->cookie_id_key ] ) ) {
			wp_logout();
			$this->error_redirect( new WP_Error( 'mismatch-identity', __( 'Mismatch identity' ), $_COOKIE ) );
		}
	}

	/**
	 * Handle errors by redirecting the user to the login form
	 *  along with an error code
	 *
	 * @param $error WP_Error
	 */
	function error_redirect( $error ) {
		$this->logger->log( $error );
		
		// redirect user back to login page
		wp_redirect(  
			wp_login_url() . 
			'?login-error=' . $error->get_error_code() .
		    '&message=' . urlencode( $error->get_error_message() )
		);
		exit;
	}

	/**
	 * Get the current error state
	 *
	 * @return bool | WP_Error
	 */
	function get_error(){
		return $this->error;
	}
	
	/**
	 * Implements hook wp_logout
	 *
	 * Remove cookies
	 */
	function wp_logout() {
		setcookie( $this->cookie_id_key, '1', 0, COOKIEPATH, COOKIE_DOMAIN, TRUE );
	}

	/**
	 * Modify outgoing requests according to settings
	 *
	 * @param $request
	 * @param $op
	 *
	 * @return mixed
	 */
	function alter_request( $request, $op ) {
		if ( $this->settings->no_sslverify ) {
			$request['sslverify'] = FALSE;
		}

		return $request;
	}
	
	/**
	 * Control the authentication and subsequent authorization of the user when
	 *  returning from the IDP.
	 */
	function authentication_request_callback() {
		$settings = $this->settings;
		$client = $this->client;
		
		// 
		$authentication_request = $client->validate_authentication_request( $_GET );
		
		if ( is_wp_error( $authentication_request ) ){
			$this->error_redirect( $authentication_request );
		}
		
		// retrieve the authentication code from the authentication request
		$code = $client->get_authentication_code( $authentication_request );
		
		if ( is_wp_error( $code ) ){
			$this->error_redirect( $code );
		}

		// attempting to exchange an authorization code for an authentication token
		$token_result = $client->request_authentication_token( $code );
		
		if ( is_wp_error( $token_result ) ) {
			$this->error_redirect( $token_result );
		}

		// get the decoded response from the authentication request result
		$token_response = $client->get_token_response( $token_result );

		if ( is_wp_error( $token_response ) ){
			$this->error_redirect( $token_response );
		}

		// ensure the that response contains required information
		$valid = $client->validate_token_response( $token_response );
		
		if ( is_wp_error( $valid ) ) {
			$this->error_redirect( $valid );
		}
		
		// - end authentication
		
		// - start authorization

		// The id_token is used to identify the authenticated user, e.g. for SSO.
		// The access_token must be used to prove access rights to protected resources
		// e.g. for the userinfo endpoint
		
		//
		$id_token_claim = $client->get_id_token_claim( $token_response );
		
		if ( is_wp_error( $id_token_claim ) ){
			$this->error_redirect( $id_token_claim );
		}
		
		//
		$valid = $client->validate_id_token_claim( $id_token_claim );
		
		if ( is_wp_error( $valid ) ){
			$this->error_redirect( $valid );
		}


//
//		// if desired, admins can use regex to determine if the identity value is valid
//		// according to their own standards expectations  
//		if ( ! empty( $settings->allowed_regex ) &&
//		     preg_match( $settings->allowed_regex, $id_token_claim[ $settings->identity_key ] ) !== 1
//		) {
//	    	return new WP_Error( 'no-subject-identity', __( 'No subject identity' ), $id_token_claim );
//		}

		
		//
		$user_claim = $client->get_user_claim( $token_response );
		
		if ( is_wp_error( $user_claim ) ){
			$this->error_redirect( $user_claim );
		}
		
		//
		$valid = $client->validate_user_claim( $user_claim, $id_token_claim );
		
		if ( is_wp_error( $valid ) ){
			$this->error_redirect( $valid );
		}

		// - end authorization
		
		
		
		// request is authenticated and authorized
		// - start user handling
		$user_identity = $client->get_user_identity( $id_token_claim );
		$user = $this->get_user_by_identity( $user_identity );

		// if we didn't find an existing user, we'll need to create it
		if ( ! $user ) {
			$user = $this->create_new_user( $user_identity, $user_claim );
		}

		//
		$valid = $this->validate_user( $user );
		
		if ( is_wp_error( $valid ) ){
			$this->error_redirect( $valid );
		}

		$this->login_user( $user, $token_response, $id_token_claim, $user_claim, $user_identity  );
		
		$this->logger->log( "Successful login for: {$user->user_login} ({$user->ID})", 'login-success' );

		wp_redirect( home_url() );
	}

	/**
	 * Validate the potential WP_User 
	 * 
	 * @param $user
	 *
	 * @return \WP_Error
	 */
	function validate_user( $user ){
		// ensure our found user is a real WP_User
		if ( ! is_a( $user, 'WP_User' ) || ! $user->exists() ) {
			return new WP_Error( 'invalid-user', __( 'Invalid user' ), $user );
		}
		
		return true;
	}

	/**
	 * 
	 * 
	 * @param $user
	 */
	function login_user( $user, $token_response, $id_token_claim, $user_claim, $user_identity ){
		// hey, we made it!
		// let's remember the tokens for future reference
		update_user_meta( $user->ID, 'openid-connect-generic-last-token-response', $token_response );
		update_user_meta( $user->ID, 'openid-connect-generic-last-id-token-claim', $id_token_claim );
		update_user_meta( $user->ID, 'openid-connect-generic-last-user-claim', $user_claim );

		// save our authorization cookie for the response expiration
		$oauth_expiry = $token_response['expires_in'] + current_time( 'timestamp', TRUE );
		setcookie( $this->cookie_id_key, $user_identity, $oauth_expiry, COOKIEPATH, COOKIE_DOMAIN, TRUE );

		// get a cookie and go home!
		wp_set_auth_cookie( $user->ID, FALSE );
	}
	
	/**
	 * 
	 * 
	 * @param $user_identity
	 *
	 * @return false|\WP_User
	 */
	function get_user_by_identity( $user_identity ){
		// look for user by their openid-connect-generic-user-identity value
		$user_query = new WP_User_Query( array(
			'meta_query' => array(
				array(
					'key'   => 'openid-connect-generic-user-identity',
					'value' => $user_identity,
				)
			)
		) );

		// if we found an existing users, grab the first one returned
		if ( $user_query->get_total() > 0 ) {
			$users = $user_query->get_results();
			return $users[0];
		}
		
		return false;
	}

	/**
	 * Avoid user_login collisions by incrementing
	 *
	 * @param $user_claim array
	 *
	 * @return string
	 */
	private function get_username_from_claim( $user_claim ) {
		if ( isset( $user_claim['preferred_username'] ) && ! empty( $user_claim['preferred_username'] ) ) {
			$desired_username = $user_claim['preferred_username'];
		}
		else if ( isset( $user_claim['name'] ) && ! empty( $user_claim['name'] ) ) {
			$desired_username = $user_claim['name'];
		}
		else if ( isset( $user_claim['email'] ) && ! empty( $user_claim['email'] ) ) {
			$tmp = explode( '@', $user_claim['email'] );
			$desired_username = $tmp[0];
		}
		else {
			// nothing to build a name from
			return new WP_Error( 'no-username', __( 'No appropriate username found' ), $user_claim );
		}

		// normalize the data a bit
		$desired_username = strtolower( preg_replace( '/[^a-zA-Z\_0-9]/', '', $desired_username ) );

		// copy the username for incrementing
		$username = $desired_username;

		// original user gets "name"
		// second user gets "name2"
		// etc
		$count = 1;
		while ( username_exists( $username ) ) {
			$count ++;
			$username = $desired_name . $count;
		}

		return $username;
	}
	
	/**
	 * 
	 * 
	 * @param $user_identity
	 * @param $user_claim
	 *
	 * @return \WP_Error | \WP_User
	 */
	function create_new_user( $user_identity, $user_claim){
		// default username & email to the user identity, since that is the only
		// thing we can be sure to have 
		$username = $user_identity;
		$email    = $user_identity;

		// allow claim details to determine username
		if ( isset( $user_claim['email'] ) ) {
			$email    = $user_claim['email'];
			$username = $this->get_username_from_claim( $user_claim );
		}
		// if no name exists, attempt another request for userinfo
		else if ( isset( $token_response['access_token'] ) ) {
			$user_claim_result = $this->client->request_userinfo( $token_response['access_token'] );

			// make sure we didn't get an error
			if ( is_wp_error( $user_claim_result ) ) {
				return new WP_Error( 'bad-user-claim-result', __( 'Bad user claim result' ), $user_claim_result );
			}

			$user_claim = json_decode( $user_claim_result['body'], TRUE );

			if ( isset( $user_claim['email'] ) ) {
				$email    = $user_claim['email'];
				$username = $this->get_username_from_claim( $user_claim );
			}
		}

		// allow other plugins / themes to determine authorization 
		// of new accounts based on the returned user claim
		$create_user = apply_filters( 'openid-connect-generic-user-creation-test', TRUE, $user_claim );

		if ( ! $create_user ) {
			return new WP_Error( 'cannot-authorize', __( 'Can not authorize.' ), $create_user );
		}

		// create the new user
		$uid = wp_create_user( $username, wp_generate_password( 32, TRUE, TRUE ), $email );

		// make sure we didn't fail in creating the user
		if ( is_wp_error( $uid ) ) {
			return new WP_Error( 'failed-user-creation', __( 'Failed user creation.' ), $uid );
		}

		$user = get_user_by( 'id', $uid );

		$this->log( "New user created: {$user->user_login} ($uid)", 'success' );

		// save some meta data about this new user for the future
		add_user_meta( $user->ID, 'openid-connect-generic-user', TRUE, TRUE );
		add_user_meta( $user->ID, 'openid-connect-generic-user-identity', (string) $user_identity, TRUE );

		// allow plugins / themes to take action on new user creation
		do_action( 'openid-connect-generic-user-create', $user, $user_claim );
		
		return $user;
	}
}
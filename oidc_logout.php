<?php
/*
OAuthSD project https://oa.dnc.global
OAuthSD OIDC plugin for WordPress

Perform OIDC Logout server-side. 
We must not disclose the token ID by issuing the disconnect request from a JS script.
The JS script must call this script to generate a server side disconnect request.

Author : bdegoy DnC https://degoy.com
License: GPLv2
License URI: http://www.gnu.org/licenses/gpl-2.0.html
*/

define( 'SHORTINIT', 1 );
require '/home/wpdnc/public_html/wp-load.php'; //TODO
require ABSPATH . WPINC . '/class-wp-user.php';   // WP_user
require ABSPATH . WPINC . '/class-wp-roles.php';   // WP_roles
require ABSPATH . WPINC . '/class-wp-role.php';   // WP_role
require ABSPATH . WPINC . '/class-wp-session-tokens.php';
require ABSPATH . WPINC . '/class-wp-user-meta-session-tokens.php';
require ABSPATH . WPINC . '/rest-api.php';
require ABSPATH . WPINC . '/kses.php';
require ABSPATH . WPINC . '/formatting.php';
require ABSPATH . WPINC . '/capabilities.php';
require ABSPATH . WPINC . '/user.php';
require ABSPATH . WPINC . '/meta.php';
require ABSPATH . WPINC . '/post.php';
require ABSPATH . WPINC . '/pluggable.php';
wp_plugin_directory_constants();
wp_cookie_constants();

$options = get_option('openid_connect_generic_settings', array() );
$user = wp_get_current_user();

if ( empty($url) ) $url = '/';

if ( !empty($user) ) {

    if ( isset($_GET['logout']) AND 'local' == $_GET['logout'] ) {
        // Local logout only. 
        // We arrived here because OIDC session is closed, so there is no neeed to globally logout.
        wp_logout();

    } else {
        // OIDC (global) logout
        $token_response = $user->get('openid-connect-generic-last-token-response');

        if ( !empty($token_response) ) {
            // $token response is null string if user was not logged through OIDC.   
            $id_token = $token_response['id_token'];

            if ( !empty($id_token) ) {

                // OIDC logout
                $data = array(
                    'token' => $id_token,
                );
                $h = curl_init($options['endpoint_end_session']);
                curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($h, CURLOPT_TIMEOUT, 10);
                curl_setopt($h, CURLOPT_POST, true);   // Post Methode
                curl_setopt($h, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded'));   
                curl_setopt($h, CURLOPT_POSTFIELDS, http_build_query($data));
                $res = curl_exec($h);
                $status = curl_getinfo($h, CURLINFO_HTTP_CODE);
                curl_close($h);
            }

        }
        // Should we logout locally right now? (it will be done later resulting from global logout). 

    }
}

// Whatever happened, we go back to calling page
if ( isset($_GET['url']) ) {
    if ( !empty($status) ) $url = add_query_arg( 'status', $status, $_GET['url'] ); 
    wp_redirect( esc_url($url) );
}

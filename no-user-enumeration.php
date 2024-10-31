<?php
/*
 * Plugin Name: No User Enumeration
 * Description: Disallow user enumeration for security. Also, in administrators posts hide the username unless it have a nickname.
 * Version: 1.3.2
 * Author: Carlos Montiers Aguilera
 */
require_once(trailingslashit(ABSPATH) . 'wp-includes/pluggable.php');

class No_User_Enumeration_Plugin
{

    private static $_instance = null;

    private function __construct()
    {
        // No constructor
    }

    public static function _get_instance()
    {
        if (self::$_instance === null) {
            self::$_instance = new self();
        }
        return self::$_instance;
    }

    public function filtro_ocultar_desactivacion($actions, $plugin_file, $plugin_data, $context)
    {
        if ($plugin_file === plugin_basename(__FILE__)) {
            unset($actions['deactivate']);
            unset($actions['delete']);
            unset($actions['edit']);
        }
        return $actions;
    }

    public function filtro_autor_ocultar_admin_username($display_name)
    {
        $user = self::traer_usuario_por_login($display_name);
        if (user_can($user, 'administrator')) { // admin without nickname
            if (strcasecmp($user->display_name, $display_name) !== 0) {
                return $user->display_name; // display username that is not equal user_login
            } else {
                return '';
            }
        } else {
            return $display_name;
        }
    }

    public function filtro_autor_ocultar_admin_url($link)
    {
        $nicename = ltrim(strrchr(rtrim($link, '/'), '/'), '/');

        $user = self::traer_usuario_por_nicename($nicename);
        if (user_can($user, 'administrator')) { // admin url page
            return '';
        } else {
            return $link;
        }
    }

    public function filtro_remover_autor_de_clases($classes)
    {
        $some_removed = false;
        reset($classes);
        while (($k = key($classes)) !== null) {
            if (strpos($classes[$k], 'comment-author-') === 0) {
                unset($classes[$k]);
                $some_removed = true;
            }
            next($classes);
        }
        if ($some_removed) {
            $classes = array_values($classes);
        }
        return $classes;
    }

    public function filtro_remover_autor_de_boton_responder($link, $args, $comment, $post)
    {
        $link = preg_replace('/aria-label=\'.+\'/', 'aria-label=\'\'', $link);
        return $link;
    }

    public function traer_usuario_por_nicename($nicename)
    {
        global $wpdb;

        if (!$user = $wpdb->get_row($wpdb->prepare("SELECT `ID` FROM $wpdb->users WHERE `user_nicename` = %s", $nicename))) {
            return false;
        }

        return get_user_by('id', $user->ID);
    }

    public function traer_usuario_por_login($login)
    {
        return get_user_by('login', $login);
    }

    public function string_from($array, $key)
    {
        if (array_key_exists($key, $array)) {
            $value = $array[$key];
            if (is_string($value)) {
                return $value;
            }
        }
        return '';
    }

    public function from_archives()
    {
        if ($this->string_from($_REQUEST, 'author') !== '') {
            wp_die('Forbidden', 403);
        }
    }

    public function from_posts()
    {
        add_filter('the_author', array(
            $this,
            'filtro_autor_ocultar_admin_username'
        ), 10, 1);
        add_filter('get_comment_author', array(
            $this,
            'filtro_autor_ocultar_admin_username'
        ), 10, 1);
        add_filter('author_link', array(
            $this,
            'filtro_autor_ocultar_admin_url'
        ), 10, 1);
        add_filter('comment_class', array(
            $this,
            'filtro_remover_autor_de_clases'
        ), 10, 1);
        add_filter('comment_reply_link', array(
            $this,
            'filtro_remover_autor_de_boton_responder'
        ), 10, 4);
    }

    public function from_rest_api()
    {
        $header_error_403 = 'HTTP/1.1 403 Forbidden';
        $header_content_type_json = 'Content-Type: application/json; charset=UTF-8';

        $regex_api_v2 = '@/wp/v2/users\b@';
        $regex_api_v1 = '@/wp-json/users\b@';

        $request_uri = $this->string_from($_SERVER, 'REQUEST_URI');
        $rest_route = $this->string_from($_REQUEST, 'rest_route');

        $call_rest_api_v2 = preg_match($regex_api_v2, $request_uri) || preg_match($regex_api_v2, $rest_route);
        $call_rest_api_v1 = preg_match($regex_api_v1, $request_uri) || preg_match($regex_api_v1, $rest_route);

        // rest api v2 merged since v4.7
        if ($call_rest_api_v2) {
            header($header_error_403);
            header($header_content_type_json);
            die('{"code":"rest_user_cannot_view","message":"Sorry, you are not allowed to list users.","data":{"status":403}}');
        }
        // rest api v1 deprecated
        if ($call_rest_api_v1) {
            header($header_error_403);
            header($header_content_type_json);
            die('[{"code":"json_user_cannot_list","message":"Sorry, you are not allowed to list users."}]');
        }
    }

    public function hide_desactivation()
    {
        add_filter('plugin_action_links', array(
            $this,
            'filtro_ocultar_desactivacion'
        ), 10, 4);
    }

    public static function init()
    {
        $no_user_enumeration = self::_get_instance();
        $no_user_enumeration->from_archives();
        $no_user_enumeration->from_posts();
        $no_user_enumeration->from_rest_api();
        $no_user_enumeration->hide_desactivation();

    }

}

No_User_Enumeration_Plugin::init();

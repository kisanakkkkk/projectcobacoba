<?php
error_reporting(0);
session_start();

require_once("./geoip2.phar");
use GeoIp2\Database\Reader;

$reader = new Reader('./GeoLite2-City.mmdb');
$record = $reader->city($_SERVER['HTTP_X_FORWARDED_FOR']);
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$last_login = time();
$location = $record->postal->code . $record->city->name;
function checkSessionValidity($ip, $user_agent, $last_login, $location) {

    if(isset($_SESSION['is_login']) && $_SESSION['is_login'] == true){
        if(!isset($_SESSION['ip']) || $ip !== $_SESSION['ip']){
            return false;
        }
        if(!isset($_SESSION['user_agent']) || $user_agent !== $_SESSION['user_agent']){
            return false;
        }
        if(!isset($_SESSION['location']) || $location !== $_SESSION['location']){
            return false;
        }
        if(!isset($_SESSION['last_login']) || $last_login - $_SESSION['last_login'] > 43200){
            return false;
        }
        return true;
    }
    else{
        return false;
    }
}


if(checkSessionValidity($ip, $user_agent, $last_login, $location) === true){
    echo 'success';
}
else{
    session_destroy();
    header("location:../login.php");;
}
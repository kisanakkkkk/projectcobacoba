<?php
    error_reporting(0);
    $config = [
        'server' => '127.0.0.1',
        'username' => 'root',
        'password' => '',
        'database' => 'databasebuatuts',
    ];

    $connection = new mysqli(
        $config['server'],
        $config['username'],
        $config['password'],
        $config['database'],
    );

    session_start();

    if ($_SERVER['REQUEST_METHOD'] == "POST"){
        if(isset($_POST['username']) && isset($_POST['password'])){
           $username = $_POST['username'];
           $password = $_POST['password'];
            $hash = sha1($password);
           $query = "SELECT * FROM users WHERE username = '$username' AND password = '$hash';";

           $result = $connection->query($query);
           if ($result !== false && $result->num_rows > 0){
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
            $user_agent = $_SERVER['HTTP_USER_AGENT'];
            $last_login = time();
            $location = $record->postal->code . $record->city->name;

            $_SESSION['is_login'] = true;
            $_SESSION['ip'] = $ip;
            $_SESSION['user_agent'] = $user_agent;
            $_SESSION['last_login'] = $last_login;
            $_SESSION['location'] = $location;

            header("location:../resume.php");
           }
           else{
            echo 'password keknya salah si ya';
           }
        }
        else {
            echo 'keknya param kurang si ya';
        }
    } elseif ($_SERVER['REQUEST_METHOD'] == "GET") {
        echo 'bisa get';
    }

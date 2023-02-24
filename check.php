<?php
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

    function secureInput($input, $attack_mode, $should_strip, $validate_only){
        $flagSql = false;
        $flagXss = false;
        $flagCij = false;
        if($attack_mode === "SQLI"){
            $flagSql = true;
        }
        else if($attack_mode === "XSS"){
            $flagXss = true;
        }
        else if($attack_mode === "RCE"){
            $flagCij = true;
        }
        else if($attack_mode === "ALL"){
            $flagSql = true;
            $flagXss = true;
            $flagCij = true;
        }
        else{
            echo "ada kesalahan";
            return null;
        }
        try{
            if($flagSql===true){
                $sqldanger = array("\\",  "\x00", "\n",  "\r",  "'",  '"', "\x1a", "/", "*", "=", "-", "%", "|", "@", "#");
                $sqlswitch = array("\\\\","\\0","\\n", "\\r", "\'", '\"', "\\Z", "\/", "\*", "\=", "\-", "\%", "\|", "\@", "\,", "\#");
                $old = $input;
                if($should_strip === true){
                    $input = str_replace($sqldanger, "", $input);
                }
                else if($should_strip === false){
                    $input = str_replace($sqldanger, $sqlswitch, $input);

                }
                else{
                    echo "ada kesalahan";
                    return null;
                }
                if($validate_only===true){
                    if($old!==$input){
                        throw new Exception('SQL token detected');
                    }
                }
            }
            if($flagXss===true){
                $xssdanger = array("&", "<", ">", "'", '"');
                $xssswitch = array("&amp;", "&lt;", "&gt;", "&#39;", "&quot;");
                $blacklistxss = array("eval", "write", "document", "innerhtml", "function", "alert", "confirm", "prompt", "window", "open");
                $regexxss = '/\b('.implode('|', $blacklistxss).')\b/i';
                $old = $input;
                if($should_strip === true){
                    do
                    {
                        $old_input = $input;
                        $input = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $input);
                        $input = preg_replace($regexxss, "", $input);
                    }
                    while ($old_input !== $input);
                    $input = str_replace($xssdanger, "", $input);
                }
                else if($should_strip === false){
                    $input = str_replace($xssdanger, $xssswitch, $input);

                }
                else{
                    echo "ada kesalahan";
                    return null;
                }
                if($validate_only===true){
                    if($old!==$input){
                        throw new Exception('XSS token detected');
                    }
                }
            }
            if($flagCij===true){
                $rcedanger = array("(", "~", "=", "\"", "&", "@", "{", "/", "$", "-", "*", "#", "!", ")", "?", "|", "'", "}", "\\", "]", "[", "^", "<", "`", ".", "+", ",", ";", ":", "%", ">");
                $rceswitch = array("\(", "\~", "\=", "\\\"", "\&", "\@", "\{", "\/", "\$", "\-", "\*", "\#", "\!", "\)", "\?", "\|", "\'", "\}", "\\\\", "\]", "\[", "\^", "\<", "\`", "\.", "\+", "\,", "\;", "\:", "\%", "\>");
                $old = $input;
                if($should_strip === true){
                    $blacklistrce = array("pcntl_alarm","pcntl_fork","pcntl_waitpid","pcntl_wait","pcntl_wifexited","pcntl_wifstopped","pcntl_wifsignaled","pcntl_wifcontinued","pcntl_wexitstatus","pcntl_wtermsig","pcntl_wstopsig","pcntl_signal","pcntl_signal_get_handler","pcntl_signal_dispatch","pcntl_get_last_error","pcntl_strerror","pcntl_sigprocmask","pcntl_sigwaitinfo","pcntl_sigtimedwait","pcntl_exec","pcntl_getpriority","pcntl_setpriority","stream_socket_sendto","stream_socket_client","pcntl_async_signals","error_log","system","exec","shell_exec","popen","proc_open","passthru","link","symlink","syslog","imap_open","ld","mail","file_put_contents","scandir","file_get_contents","readfile","fread","fopen","chdir", "phpinfo");
                    $regexrce = '/\b('.implode('|', $blacklistrce).')\b/i';
                    do
                    {
                            $old_input = $input;
                            $input = preg_replace($regexrce, "", $input);
                    }
                    while ($old_input !== $input);
                    $input = str_replace($rcedanger, "", $input);
                }
                else if($should_strip === false){
                    $input = str_replace($rcedanger, $rceswitch, $input);
                }
                else{
                    echo "ada kesalahan";
                    return null;
                }
                if($validate_only===true){
                    if($old!==$input){
                        throw new Exception('Command injection token detected');
                    }
                }
            }
        }catch (Exception $e) {
            echo 'Caught exception: ',  $e->getMessage(), "\n";
            exit();
        }

        return $input;
    }
    if($_SERVER['REQUEST_METHOD'] == "POST"){
        $input = $_POST['message'];
        $mode = "ALL";
        if(isset($_POST['mode'])){
            $mode = $_POST['mode'];
        }
        $strip = false;
        if(isset($_POST['strip'])){
            $strip = true;
        }
        $validate = false;
        if(isset($_POST['validate'])){
            $validate = true;
        }

        $input = secureInput($input, $mode, $strip, $validate);
        // $input = secureInput($input, "XSS", true, false);
    }
    else{
        $input = null;
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <form action="" method="post">
        <input type="text" name="message" style="width: 500px">
        <br>
        <label for="xss">sqli</label>
        <input type="checkbox" name="mode" value="SQLI">
        <br>
        <label for="sql">xss</label>
        <input type="checkbox" name="mode" value="XSS">
        <br>
        <label for="rce">rce</label>
        <input type="checkbox" name="mode" value="RCE">
        <br>
        <label for="all">all</label>
        <input type="checkbox" name="mode" value="ALL">
        <br>
        <label for="all">strip?</label>
        <input type="checkbox" name="strip" value="test">
        <br>
        <label for="all">validate?</label>
        <input type="checkbox" name="validate" value="test">
        <br>
        <button>send</button>
    </form>
    <?php echo $input;    ?>
    <label for="">xss test</label>
    <hr>
    <?php
        $query = "SELECT * FROM users WHERE username = '$input';";
        $result = $connection->query($query);
        if ($result->num_rows > 0) {
            while($row = $result->fetch_assoc()) {
            echo 'id: ' . $row['id'] . '<br>';         
            echo 'username: ' . $row['username'] . '<br>';         
            echo 'password: ' . $row['password'] . '<br>';
            }
        } else {
            echo "empty";
        }
    ?>
    <label for="">sqli test</label>
    <hr>
    <?php
        echo "input";
    ?>
    <label for="">command injection test</label>
    <hr>
</body>

</html>
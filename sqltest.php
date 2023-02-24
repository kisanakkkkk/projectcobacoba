<?php
	$config = [
        'server' => '127.0.0.1',
        'username' => 'root',
        'password' => '',
        'database' => 'databasebuatuas',
    ];
    
    $connection = new mysqli(
        $config['server'],
        $config['username'],
        $config['password'],
        $config['database'],
    );
    
	if ($_SERVER['REQUEST_METHOD'] === "POST"){
		$filter_query = $connection -> real_escape_string(strip_tags($_POST['query']));
		$filter_column = $connection -> real_escape_string(strip_tags($_POST['column']));

        $predefined_column = array("product_id", "product_name", "price");
        if(in_array($filter_column, $predefined_column) == false){
            echo "column does not exists!";
            die();
        }

		$query = "SELECT * FROM products WHERE $filter_column = ?;";
		$stmt = $connection->prepare($query);
		$stmt->bind_param("s", $filter_query);
		$stmt->execute();
		
		$result = $stmt->get_result();
        if ($result->num_rows > 0) {
            while($row = $result->fetch_assoc()) {
            echo 'product id: ' . $row['product_id'] . '<br>';         
            echo 'product name: ' . $row['product_name'] . '<br>';         
            echo 'priec: ' . $row['price'] . '<br>';
            }
        } else {
            echo "empty";
        }
	}
    else{
        echo 'sqltesting';
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
        <label for="">query</label>
        <input type="text" name="query" id="">
        <br>
        <label for="">column</label>
        <input type="text" name="column" id="">
        <br>
        <button>send</button>
    </form>
</body>
</html>
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
$link = mysqli_connect('db', 'user', 'test', 'myDb', 3306);
mysqli_set_charset($link, "utf8");
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>

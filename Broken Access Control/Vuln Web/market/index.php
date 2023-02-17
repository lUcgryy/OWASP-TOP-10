<?php
$file = $_GET['page'];

if(!isset($file) || ($file=="index.php")) {
   include("/var/www/html/home.html");
}
else{
	include("/var/www/html/".str_replace("../","",$file));
}
?>
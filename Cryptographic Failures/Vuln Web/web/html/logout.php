<?php
  $site = "CompanyDev &rarrow;";
  require 'classes/db.php';
  require 'classes/phpfix.php';
  require 'classes/user.php';
  User::logout();
  header("Location: /index.php");
  die();
?>



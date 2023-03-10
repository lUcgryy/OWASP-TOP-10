<?php 
  require 'classes/db.php';
  require 'classes/phpfix.php';
  require 'classes/user.php';
  if (isset($_COOKIE['auth'])){
    $user = User::getuserfromcookie($_COOKIE['auth']);
  }
?>
<html>
    <head>
        <title>CompanyDev</title>
        <link rel="stylesheet" media="screen" href="/css/bootstrap.css" />
        <link rel="stylesheet" media="screen" href="/css/companydev.css" />
    </head>
    <body>
      <div class="container-narrow">
        <div class="header">
          <div class="navbar navbar-fixed-top">
            <div class="nav-collapse collapse">
              <ul class="nav navbar-nav">
                <?php if (!isset($user)) { ?>
                  <li><a href="/login.php">Login</a></li>
                  <li><a href="/register.php">Register</a></li>
                <?php } else { ?>
                  <li><a href="/logout.php">Logout</a></li>
                <?php } ?>
              </ul>
            </div>
          </div>
        </div>
      </div>
      <div class="container">
        <div class="body-content">


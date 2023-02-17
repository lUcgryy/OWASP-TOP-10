<?php
  $site = "CompanyDev &rarrow; Padding Oracle";
  require "header.php";
?>

<div class="row">
  <div class="col-lg-12">
  <?php if (isset($user)) { ?>
      <?php  if ($user === 'admin' ) { ?>
      <center><img src="images/maxresdefault.jpg" alt="banner2"></center>
      <p>
      <p>
      <center><p>Tasos this is my ssh key, just in case, if you ever want to login and check something out.</p></center>
      <center><p><a href="mysshkeywithnamemitsos">My Key</a></p></center>
      <p>
      <p>
      <?php } else { ?> 
      <?php } ?>
	<center><img src="images/banner.png" alt="banner"></center>
        <p>
	<p>
	<center>You are currently logged in as <?php echo h($user); ?>!</center>
        <p>
        <p>
      </span>
  <?php } else { ?>
      <center><img src="images/banner.png" alt"banner"></center>
      <p><center>To start, you will need to create a user <a href="/register.php">register</a> and then <a href="/login.php">log in</a> to check this company's projects and potential.</center></p>
  <?php } ?>

  </div>
</div>



<?php


  require "footer.php";
?>


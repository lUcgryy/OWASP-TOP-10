<?php

class User {
  public static function logout() {
    setcookie("auth", NULL ,time()-10);  
  }


  public static function createcookie($user, $password) {
    $string = "user=".$user; 
    $passphrase = 'pntstrlb'; 
    return encryptString($string, $passphrase); 

  } 

  public static function getuserfromcookie($auth) {
    $passphrase = 'pntstrlb';
    $data = decryptString($auth, $passphrase);
    list($a, $user) = explode("=", $data);
    $sql = "SELECT * FROM users where login=\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\"";
    $result = mysql_query($sql);
    if ($result) {
      if ($row = mysql_fetch_assoc($result)) {
        return $row['login'];
      }
      else {
        echo "User not found: ".htmlentities($user);
        return NULL;
      }
    }
    return NULL;
  }
  public static function login($user, $password) {
    $sql = "SELECT * FROM users where login=\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\" and password=md5(\"myseedgoeshere";
    $sql.= mysql_real_escape_string($password);
    $sql.= "\")";
    $result = mysql_query($sql);
    if ($result) {
      $row = mysql_fetch_assoc($result);
      if ($user === $row['login']) {
        return TRUE;
      }
    }
    return FALSE;
  }
  public static function register($user, $password) {
    $sql = "INSERT INTO  users (login,password) values (\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\", md5(\"myseedgoeshere";
    $sql.= mysql_real_escape_string($password);
    $sql.= "\"))";
    $result = mysql_query($sql);
    if ($result) {
      return TRUE;
    }
    else 
      echo mysql_error();
    return FALSE;
  }
}

function encryptString($unencryptedText, $passphrase) { 
  $iv = mcrypt_create_iv( mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC), MCRYPT_RAND);
  $text = pkcs5_pad($unencryptedText,8);
  $enc = mcrypt_encrypt(MCRYPT_DES, $passphrase, $text, MCRYPT_MODE_CBC, $iv); 
  return base64_encode($iv.$enc); 
}

function decryptString($encryptedText, $passphrase) {
  $encrypted = base64_decode($encryptedText);
  $iv_size =  mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC);
  $iv = substr($encrypted,0,$iv_size);
  $dec = mcrypt_decrypt(MCRYPT_DES, $passphrase, substr($encrypted,$iv_size), MCRYPT_MODE_CBC, $iv);
  $str = pkcs5_unpad($dec); 
  if ($str === false) {
    echo "Invalid padding";
    die(); 
  }
  else {
    return $str; 
  }
}
function pkcs5_pad ($text, $blocksize) 
{ 
    $pad = $blocksize - (strlen($text) % $blocksize); 
    return $text . str_repeat(chr($pad), $pad); 
} 

function pkcs5_unpad($text) 
{ 
    $pad = ord($text{strlen($text)-1}); 
    if ($pad === 0) return false;
    if ($pad > strlen($text)) return false; 
    if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false; 
    return substr($text, 0, -1 * $pad); 
} 

?>

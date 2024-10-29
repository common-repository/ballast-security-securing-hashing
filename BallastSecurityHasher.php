<?php
/*
Plugin Name: Ballast Security Hashing
Plugin URI:  http://wordpress.org/extend/plugins/ballast-security-securing-hashing/
Description: Replaces the login hash of the WordPress with 2048 iterations of a modified PBKDF2 using SHA-256 and 16 bytes of salt the SHA1'd to be shortened
Author: <a href="https://www.twitter.com/bwallHatesTwits/" target="_blank">@bwallHatesTwits</a>
Version: 1.2.1
License: GPLv2
Colaborator: HacKan (<a href="https://www.twitter.com/HacKanCuBa/" target="_blank">@hackancuba</a>) solved issue when php v < 5.3.0 and problem with line 358
*/

//My own modification of ARC4
class ARC4bwall
{
	protected $state;
	protected $i = 0;
	protected $j = 0;
	protected $k = 0;
	
	//Swaps i, j, k
	function Swap()
	{
		$temp = $this->state[$this->i];
		$this->state[$this->i] = $this->state[$this->j];
		$this->state[$this->j] = $this->state[$this->k];
		$this->state[$this->k] = $temp;
	}
	
	function Init($data)
	{
		$this->state = array();
		for($this->i = 0; $this->i < 256; $this->i++)
		{
			$this->state[$this->i] = $this->i;
		}
		$this->j = 0;
		$this->k = 0;
		for($this->i = 0; $this->i < 256; $this->i++)
		{
			$this->j = ($this->j + $this->state[$this->i] + ord($data[$this->i % strlen($data)])) % 256;
			$this->k = pow($this->k + $this->j, 2) % 256;
			$this->Swap();
		}
		$this->i = 0;
		$this->j = 0;
		$this->k = 0;
	}
	
	function GetByte()
	{
		$this->i = ($this->i + 1) % 256;
		$this->j = ($this->j + $this->state[$this->i]) % 256;
		$this->k = pow($this->k + $this->j, 2) % 256;
		$this->Swap();
		return $this->state[($this->i + $this->j + $this->k) % 256];
	}
	
	public function Crypt($data)
	{
		$ret = "";
		for($x = 0; $x < strlen($data); $x++)
		{
			$ret .= chr(ord($data[$x]) ^ $this->GetByte());
		}
		return $ret;
	}
	
	public function __construct($key = "bwallRocks")
	{
		$this->Init($key);
	}
}

class BallastPHPHash
{
	function ARC4PBKDF2($plain, $salt, $iterations = 2048, $algo = 'sha256')
	{
		$rc4 = new ARC4bwall($plain);
		$derivedkey = $b = $rc4->Crypt(hash_hmac($algo, $salt, $plain, true));
		for ( $i = 0; $i < $iterations; $i++ )
		{
			$derivedkey ^= ($b = $rc4->Crypt(hash_hmac($algo, $b, $plain, true)));
		}
		return sha1($derivedkey, true);
	}
	
	function PBKDF2($plain, $salt, $iterations = 2048, $algo = 'sha256' ) 
	{
		$derivedkey = $b = hash_hmac($algo, $salt, $plain, true);
		for ( $i = 0; $i < $iterations; $i++ )
		{
			$derivedkey ^= ($b = hash_hmac($algo, $b, $plain, true));
		}
		return sha1($derivedkey, true);
	}
	
	function BSPBKDF2($plain, $salt, $iterations = 2048, $algo = 'sha256' ) 
	{
		$derivedkey = $b = hash_hmac($algo, $salt, $plain, true);
		for ( $i = 0; $i < $iterations; $i++ )
		{
			$derivedkey = hash_hmac($algo, $b, $plain, true);
		}
		return sha1($derivedkey, true);
	}
	
	function rstrstr($haystack,$needle, $start=0)
	{	
		// Added by HacKan, replacement for strstr() compat php v < 5.3.0
		// http://www.php.net/manual/es/function.strstr.php#103577
		// credits to gruessle at gmail dot com for the idea
		return substr($haystack, $start,strpos($haystack, $needle));
	}

	//Hash Format - $BPBK$Iterations$Salt$Hash
	public function HashUpToDate($hash)
	{
		$type = get_option("BallastSecurityHashType");
		if($type === false)
		{
			//option is not defined
			add_option("BallastSecurityHashType", '$BPBK$2048$', "", "yes");
			$type = get_option("BallastSecurityHashType");
		}
		//Default WordPress is '$P$'
		return (substr($hash, 0, strlen($type)) == $type);
	}
	
	function StartsWith($hash, $type)
	{
		return (substr($hash, 0, strlen($type)) == $type);
	}
	
	public function CheckPassword($password, $hash)
	{
		if($this->StartsWith($hash, '$BPBK$2048$'))
		{
			$saltAndhash = substr($hash, 11);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->BSPBKDF2($password, base64_decode($salt)));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$BPBK$10k$'))
		{
			$saltAndhash = substr($hash, 10);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->BSPBKDF2($password, base64_decode($salt), 10000));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$BPBK$100k$'))
		{
			$saltAndhash = substr($hash, 11);
			//$salt = strstr("$saltAndhash", '$');
			$salt = $this->rstrstr($saltAndhash, '$');
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->BSPBKDF2($password, base64_decode($salt), 100000));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$PBK$2048$'))
		{
			$saltAndhash = substr($hash, 10);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->PBKDF2($password, base64_decode($salt)));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$PBK$10k$'))
		{
			$saltAndhash = substr($hash, 9);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->PBKDF2($password, base64_decode($salt), 10000));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$PBK$100k$'))
		{
			$saltAndhash = substr($hash, 10);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->PBKDF2($password, base64_decode($salt), 100000));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$APBK$2048$'))
		{
			$saltAndhash = substr($hash, 11);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->ARC4PBKDF2($password, base64_decode($salt)));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$APBK$10k$'))
		{
			$saltAndhash = substr($hash, 10);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->ARC4PBKDF2($password, base64_decode($salt), 10000));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$APBK$100k$'))
		{
			$saltAndhash = substr($hash, 11);
			//$salt = strstr($saltAndhash, '$', true);
			$salt = $this->rstrstr($saltAndhash, '$');
			$hash = substr(strstr($saltAndhash, '$'), 1);
			$realHash = base64_encode($this->ARC4PBKDF2($password, base64_decode($salt), 100000));
			return ($hash == $realHash);
		}
		else if($this->StartsWith($hash, '$P$'))
		{
			require_once(ABSPATH.'wp-includes/class-phpass.php');
			$ph = new PasswordHash(8, TRUE);
			return $ph->CheckPassword($password, $hash);
		}
	}
	
	public function HashPassword($password)
	{
		$type = get_option("BallastSecurityHashType");
		if($type === false)
		{
			//option is not defined
			add_option("BallastSecurityHashType", '$BPBK$2048$', "", "yes");
			$type = get_option("BallastSecurityHashType");
		}
		if($type === '$BPBK$2048$')
		{
			$hash = '$BPBK$2048$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->BSPBKDF2($password, $salt));
			return $hash;
		}
		else if($type === '$BPBK$10k$')
		{
			$hash = '$BPBK$10k$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->BSPBKDF2($password, $salt, 10000));
			return $hash;
		}
		else if($type === '$BPBK$100k$')
		{
			$hash = '$BPBK$100k$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->BSPBKDF2($password, $salt, 100000));
			return $hash;
		}
		else if($type === '$PBK$2048$')
		{
			$hash = '$PBK$2048$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->PBKDF2($password, $salt));
			return $hash;
		}
		else if($type === '$PBK$10k$')
		{
			$hash = '$PBK$10k$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->PBKDF2($password, $salt, 10000));
			return $hash;
		}
		else if($type === '$PBK$100k$')
		{
			$hash = '$PBK$100k$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->PBKDF2($password, $salt, 100000));
			return $hash;
		}
		else if($type === '$APBK$2048$')
		{
			$hash = '$APBK$2048$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->ARC4PBKDF2($password, $salt));
			return $hash;
		}
		else if($type === '$APBK$10k$')
		{
			$hash = '$APBK$10k$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->ARC4PBKDF2($password, $salt, 10000));
			return $hash;
		}
		else if($type === '$APBK$100k$')
		{
			$hash = '$APBK$100k$';
			$salt = "";
			for($i = 0; $i < 16; $i++)
			{
				$salt .= chr(rand(0, 256));
			}
			$hash .= base64_encode($salt).'$'.base64_encode($this->ARC4PBKDF2($password, $salt, 100000));
			return $hash;
		}
		else if($type === '$P$')
		{
			require_once(ABSPATH.'wp-includes/class-phpass.php');
			$ph = new PasswordHash(8, TRUE);
			return $ph->HashPassword($password);
		}
	}
}
if (!function_exists('wp_hash_password'))
{
	function wp_hash_password($password) 
	{
		global $wp_hasher;
		if ( empty($wp_hasher) ) 
		{
			$wp_hasher = new BallastPHPHash();
		}
		return $wp_hasher->HashPassword($password);
	}
}

if (!function_exists('wp_check_password'))
{
	function wp_check_password($password, $hash, $user_id = '') 
	{
		//file_put_contents("/var/www/wordpress/hashBWALL", "hash = $hash\n", FILE_APPEND);
		// commented out by HacKan, seems to be no use; please check if correct
		// yeah, its a debugging line I use to verify the hash hash changed, good catch - bwall
		global $wp_hasher;
		$wp_hasher = new BallastPHPHash();	
		if ( strlen($hash) <= 32 ) 
		{
			$check = ( $hash == md5($password) );
			if ( $check && $user_id ) 
			{
				wp_set_password($password, $user_id);
				$hash = wp_hash_password($password);
			}
			return apply_filters('check_password', $check, $password, $hash, $user_id);
		}
		
		if(!$wp_hasher->HashUpToDate($hash))
		{
			$check = $wp_hasher->CheckPassword($password, $hash);
			if($check && $user_id)
			{
				wp_set_password($password, $user_id);
				$hash = wp_hash_password($password);
			}
			return apply_filters('check_password', $check, $password, $hash, $user_id);
		}
		$check = $wp_hasher->CheckPassword($password, $hash);	
		return apply_filters('check_password', $check, $password, $hash, $user_id); 
	}
}

function ballastsec_hash_menu() 
{
	add_menu_page('Ballast Security Secure Hasher', 'Secure Hasher Configuration', 'add_users','bssh_config', 'display_bssh_config' );
}

add_action('admin_menu', 'ballastsec_hash_menu');

function display_bssh_config() 
{	
	if(isset($_POST['hashtype']) && check_admin_referer('ballastsec_hash-change-type'))
	{
		$type = get_option("BallastSecurityHashType");
		if($_POST['hashtype'] == "1")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$BPBK$2048$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$BPBK$2048$');
			}
		}
		else if($_POST['hashtype'] == "2")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$P$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$P$');
			}
		}
		else if($_POST['hashtype'] == "3")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$BPBK$10k$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$BPBK$10k$');
			}
		}
		else if($_POST['hashtype'] == "4")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$BPBK$100k$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$BPBK$100k$');
			}
		}
		else if($_POST['hashtype'] == "5")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$PBK$2048$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$PBK$2048$');
			}
		}
		else if($_POST['hashtype'] == "6")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$PBK$10k$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$PBK$10k$');
			}
		}
		else if($_POST['hashtype'] == "7")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$PBK$100k$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$PBK$100k$');
			}
		}
		else if($_POST['hashtype'] == "8")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$APBK$2048$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$APBK$2048$');
			}
		}
		else if($_POST['hashtype'] == "9")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$APBK$10k$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$APBK$10k$');
			}
		}
		else if($_POST['hashtype'] == "10")
		{
			if($type === false)
			{
				add_option("BallastSecurityHashType", '$APBK$100k$', "", "yes");
			}
			else
			{
				update_option("BallastSecurityHashType", '$APBK$100k$');
			}
		}
	}
	$type = get_option("BallastSecurityHashType");
	if($type === false)
	{
		//option is not defined
		add_option("BallastSecurityHashType", '$BPBK$2048$', "", "yes");
		$type = get_option("BallastSecurityHashType");
	}
	$bpk = "";
	$bpk10k = "";
	$bpk100k = "";
	$apk = "";
	$apk10k = "";
	$apk100k = "";
	$pk = "";
	$pk10k = "";
	$pk100k = "";
	$wp = "";
	if($type == '$BPBK$2048$')
	{
		$bpk = "checked=\"true\"";
	}
	else if($type == '$BPBK$10k$')
	{
		$bpk10k = "checked=\"true\"";
	}
	else if($type == '$BPBK$100k$')
	{
		$bpk100k = "checked=\"true\"";
	}
	else if($type == '$PBK$2048$')
	{
		$pk = "checked=\"true\"";
	}
	else if($type == '$PBK$10k$')
	{
		$pk10k = "checked=\"true\"";
	}
	else if($type == '$PBK$100k$')
	{
		$pk100k = "checked=\"true\"";
	}
	else if($type == '$APBK$2048$')
	{
		$apk = "checked=\"true\"";
	}
	else if($type == '$APBK$10k$')
	{
		$apk10k = "checked=\"true\"";
	}
	else if($type == '$APBK$100k$')
	{
		$apk100k = "checked=\"true\"";
	}
	else if($type == '$P$')
	{
		$wp = "checked=\"true\"";
	}
	
	echo "<h2>Pick your hash type</h2><br />";
	echo "<p>The larger number of iterations means the longer it will take to process your login credentials, but also mean increased security.  The ARC4PBKDF2 with 100000 iterations is the strongest hash here but can take a while to run.</p><br/>";
	echo "<form method='POST'>";
	if ( function_exists('wp_nonce_field') ) 
		wp_nonce_field('ballastsec_hash-change-type');
	echo "<input type=\"radio\" name=\"hashtype\" value=\"1\" ".$bpk."/> Use Ballast Security's modified PBKDF2 with 2048 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"3\" ".$bpk10k."/> Use Ballast Security's modified PBKDF2 with 10000 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"4\" ".$bpk100k."/> Use Ballast Security's modified PBKDF2 with 100000 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"5\" ".$pk."/> Use the classic PBKDF2 with 2048 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"6\" ".$pk10k."/> Use the classic PBKDF2 with 10000 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"7\" ".$pk100k."/> Use the classic PBKDF2 with 100000 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"8\" ".$apk."/> Use the Ballast Security original ARC4PBKDF2 with 2048 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"9\" ".$apk10k."/> Use the Ballast Security original ARC4PBKDF2 with 10000 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"10\" ".$apk100k."/> Use the Ballast Security original ARC4PBKDF2 with 100000 iterations<br />";
	echo "<input type=\"radio\" name=\"hashtype\" value=\"2\" ".$wp."/> Use default that comes with WordPress<br />";
	echo "<input type=\"submit\" value=\"Save Hash Type\" /><br /></form>";
	echo "<br />Note: If you want to deactive this plugin, you must change your settings over to use the default, and make sure all your users login in again so their hashes can be converted back.<br />";
	echo "Follow me at <a href='https://twitter.com/bwallHatesTwits'>bwallHatesTwits</a> or <a href='https://twitter.com/BallastSec'>BallastSec</a>";
}
?>

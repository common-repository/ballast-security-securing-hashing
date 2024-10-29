=== ballast-security-securing-hashing ===
Contributors: BallastSecurity
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=KCHYQRCBZEWML
Tags: password,hash,security,ballast security,plugin,pbkdf2
Requires at least: 2.0.2
Tested up to: 3.4.1
Stable tag: 1.2.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

This plugin drastically increases the security of the hash used to store passwords

== Description ==

This plugin seamlessly changes your stored password hash to a far stronger one. The hash that it is changed to is 
generated with a variety of variations on PBKDF2, including my own ARC4PBKDF2 which adds custom ARC4 encryption 
during the hashing processs, then a SHA-1 to meet size constraints. This plugin exponentially increases the strength 
of your stored password.

== Installation ==

1. Upload `BallastSecurityHasher.zip` through the plugin upload interface
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Choose the hash you want to convert to from the Secure Hasher Configuration Menu
4. Log out and log back in, and your hash will be recomputed

== Frequently Asked Questions ==

= How will this affect my login time? =

The difference to login time is negligable, but to someone trying to crack your password, it can add years to the cracking time.

= How can I change my password hashes back? =

As of version 0.2b, you are able to start converting all logins back to the original hash.  In order to deactive this plugin without
locking yourself out of your WordPress, you need to have all your users login after reverting the hashing methods to the original.

== Screenshots ==

1. No screenshots at this time.

== Changelog ==
= 1.2.1 =
* Colaborator: HacKan (<a href="https://www.twitter.com/HacKanCuBa/" target="_blank">@hackancuba</a>) solved issue when php v < 5.3.0 and problem with line 358

= 1.2 =
* Added nonce

= 1.1 =
* Added ARC4PBKDF2 along with a custom version of ARC4 developed by me.

= 1.0 =
* Added 3 configurations of the classic PBKDF2 key derivation

= 0.3b =
* Added the option to use 10000 or 100000 iterations instead of 2048

= 0.2b =
* Added the option to convert hashes back to the original Wordpress generated hashes
* Added a configuration screen page

= 0.1b =
* Initial version set with SHA-256 with 2048 iterations as the configuration static

== Upgrade Notice ==
* The hashing methods can now be switched between seamlessly
* More hashing methods implemented

== Arbitrary section ==


# php-form-encryption
This package can encrypt and decrypt forms with AES-256 by JavaScript and PHP using RSA key interchange.

SSL encryption provides a secure mechanism to protect information over public networks, but 
it is not always available: A small business private network with Wi-Fi can expose sensitive 
information, for example. There are many situations where the technical infrastructure or 
economic resources do not allow the installation of secure communication protocols.

Some times the application level encryption may be sufficient, or can even complement the 
session and/or transport level security. PHP Form Encryption  offers a application level 
encryption solution to implement in  PHP and Javascript apps development.

How does it works:

1. Server receives a client request of a web page that contains a form.

2. Server generates a session RSA key pair, and send the public key included in the html 
response.

3. Client fills out the form and generate a AES-256 key that is returned to server encrypted 
with the received public key and the AES encrypted form data. Client saves this AES key using 
browser local storage.

4. Server receives the RSA-encrypted AES key and decrypt it using the RSA private key. Then 
this AES key will be used to decrypt the received form data and to encrypt/decrypt future forms 
until it's changed or session expires.

PHP Implementation:

Session must be started before using EncryptPost class. Then, let's intercept an encrypted form:

session_start(); 

require_once './EncryptPost.class.php'; 
$crypto = new EncryptPost(1024, './openssl.cnf');

if (isset($_POST['EncryptPost'])){
	$formId = $crypto->decodeForm();
}

So, now we know the id of the submited form and $_POST superglobal contains the decrypted data. 
Before that $_POST will only contain somethig like:

var_dump($_POST) result:
array(2) {
  ["EncryptPost_key"]=>
  string(256) "5df90b95ec4fab45d50d34c917c6578f939ccbfadf9486f133850d47a3d6b2c82a277a3468ca11fc7
  b9163c385eacc2a3a4d091cf8797e55d681b0279058a9f3e334092fb03791931d22ca3847f4f9d4dec0d0a47936f01
  2b6be9723981088d0b049cff46a8e81ec93e2b4f7c3a387d36e2033754d1420a8dc800a4eec6cd0e9"
  ["EncryptPost"]=>
  string(242) "U2FsdGVkX1/53Ut6KFi36Ou/e3lIJz/5pf8FuPb1Yh//WdefKb0iyCke2/g0QPD5
BeknGV4L8dveRDbQ4kXm5YNi3nyG+/F8JWKDipA9ygHPf5KdFr6pYcfzNQjwwfd8
rIC19cl9IOJcs171tm0OBVknaloQWDwpLM/KjISdwwPiRGCtcBhkYrcdsgv6JcwD
aVuU4VunXdWJji9WAKD+1bJrThq2VLjEHhELl26y4vI="
}
Note that "EncryptPost_key" will be received only once at first time that server receives a coded 
form. Following posts will include only the "EncryptPost" value unless keys are reset.

To send the form encrypted to the server, simply include a call to the javascript crytopost class:

<form id="form1" method="POST" action="test.php" onsubmit="return EncryptPost.encrypt('form1')">

Client may need an encrypted record to edit. Server can send it in this way:

$record = array(
	"name" => $name,
	"address" => $address,
	"zipCode" => $zip
);
$encrypted = $crypto->encodeData($record, $formId);

... and then, at the bottom of the html code:

<script>EncryptPost.decrypt('<?php echo $encrypted;?>')</script>


That's a simple and easy way to protect your data even with no SSL.

PHP Form Encryption requires openssl extension and PHP 5.4+

Thanks to:

- Tom Wu, author of jsbn/RSA javascript library.
- Mark Percival, author of Gibberish-AES javascript library.

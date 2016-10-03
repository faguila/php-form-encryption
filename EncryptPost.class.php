<?php
if (!extension_loaded('openssl')) die('ERROR: Openssl PHP extension not loaded.'); 

/**
* @name EncryptPost.class.php
* @author Francisco del Aguila <faguila@alboran.net>
* @version 1.01
* @license MIT https://opensource.org/licenses/MIT
* 
* Requires PHP 5.4+
* Requires openssl extension
* 
* V. 1.01:  - If no RSA private key is present in session when EncryptPost_key is
*             received, the script will exit with error.
*           - Detect failure in new RSA key creation.
*       
*/

class EncryptPost
{   
    const SEPARATOR1 = ' /=/ ';
    const SEPARATOR2 = ' /~/ ';
    
    protected $opensslCnf; // Filename of the openssl.cnf config file.
    protected $RSAkeyLength;
    
    public function __construct($RSAkeyLength = 1024, $opensslCnf = './openssl.cnf')
    {
        // Create the session RSA key pair if doesn't exists.
        $this->RSAkeyLength = $RSAkeyLength;
        $this->opensslCnf = $opensslCnf;
        if (!isset($_SESSION['RSA_Private_key'])) $this->createSessionKeys();
    }
    
    /**
    * Create new RSA public and private session keys
    * 
    * @return array
    */
    public function createKeys()
    {
        $config = array(
            "config" => $this->opensslCnf,
            "private_key_bits" => $this->RSAkeyLength,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
        );
        
        $privatekey = '';
        $keydetails = false;
        
        $pkey = openssl_pkey_new($config);
        if ($pkey) $pkeyCreated = openssl_pkey_export($pkey, $privatekey, null, $config);
        if ($pkeyCreated) $keydetails = openssl_pkey_get_details($pkey);
        
        if (!$keydetails) die("RSA key creation failed");
        
        return array(
            "rsaPrivateKey" => $privatekey,
            "rsaPublicKeyHex" => bin2hex($keydetails['rsa']['n'])
        );
    }
    
    /**
    * Set session RSA keys
    * 
    * @param int $keyLength
    */
    public function createSessionKeys()
    {
        $keyArray = $this->createKeys();
        $_SESSION['RSA_Private_key'] = $keyArray['rsaPrivateKey'];
        $_SESSION['RSA_Public_key'] = $keyArray['rsaPublicKeyHex'];
    }
    
    /**
    * Generates a gibberish-aes compatible hash whith 32 bytes key and iv.
    * $salt length must be 8 bytes.
    * 
    * @param string $salt
    * @param string $key
    * 
    * @return string
    */
    protected function getHash($salt, $key)
    {
        $hash1 = md5($key . $salt, true);
        $hash2 = md5($hash1 . $key . $salt, true);
        $hash3 = md5($hash2 . $key . $salt, true);
        $hash4 = $hash1 . $hash2 . $hash3;

        $hash['key'] = substr($hash4, 0, 32);
        $hash['iv'] = substr($hash4, 32, 16);
        
        return $hash;
    }
    
    /**
    * Encrypt a string using AES 256 bits cbc mode.
    * 
    * @param string $decrypted
    * @param string $key
    * 
    * @return string base64 encoded
    */
    public function aes256cbc_encrypt($decrypted, $key)
    {
        $salt = openssl_random_pseudo_bytes(8);
        $hash = $this->getHash($salt, $key);
        $encrypted = openssl_encrypt($decrypted, "aes-256-cbc", $hash['key'], true, $hash['iv']);

        return base64_encode('Salted__' . $salt . $encrypted);
    }
    
    /**
    * Decrypt a string with AES 256 bits cbc.
    * 
    * @param string $encrypted Base64 encoded
    * @param string $key
    * 
    * @return string 
    */
    public function aes256cbc_decrypt($encrypted, $key)
    {
        $encrypted = base64_decode($encrypted);
        $salt = substr($encrypted, 8, 8);
        $encrypted = substr($encrypted, 16);
        $hash = $this->getHash($salt, $key);
        return openssl_decrypt($encrypted, "aes-256-cbc", $hash['key'], true, $hash['iv']);
    }
    
    /**
    * Delete session AES key and regenerate RSA keys
    */
    public function reset()
    {
        unset($_SESSION['aesKey']);
        $this->createSessionKeys();    
    }
    
    /**
    * Decode a submitted FORM ($_POST)
    * 
    * $_POST must contain two keys when first time executed in a session:
    * 'EncryptPost' : With the AES 256 encrypted serialized form data.
    * 'EncryptPost_key': Whith the RSA encrypted (with public key) AES 256 key.
    * 
    * Next times in that session 'EncryptPost_key' is not needed.
    * 
    * The form id must be serialized inside the 'EncryptPost' content assigned to
    * the 'EncryptPost_form' key.
    * 
    * The decrypted values are assigned to the $_POST superglobal.
    * 
    * @return string Form id
    */
    public function decodeForm()
    {   
        if (!isset($_POST['EncryptPost'])) return false; // Nothing to decrypt
        
        // Get and decrypt EncryptPost_key if present
        if (isset($_POST['EncryptPost_key'])){
            if (!isset($_SESSION['RSA_Private_key'])) die("RSA key not found");
            $rsaPrivateKey = openssl_pkey_get_private($_SESSION['RSA_Private_key']);
            $encrypted = pack('H*', $_POST['EncryptPost_key']);
            $aesKey = '';
            if (!openssl_private_decrypt($encrypted, $aesKey, $rsaPrivateKey)) return false;
            $_SESSION['aesKey'] = $aesKey;
            unset($_POST['EncryptPost_key']);
        }
        
        if (!isset($_SESSION['aesKey'])) die("Decrypt: AES key not found");
        
        $aesKey = $_SESSION['aesKey'];

        // Decrypt post
        $encrypted = $_POST['EncryptPost'];
        $decrypted = $this->aes256cbc_decrypt($encrypted, $aesKey);
        
        $pairs = explode(self::SEPARATOR2, $decrypted);
        foreach ($pairs as $pair){
            list($key, $value) = explode(self::SEPARATOR1, $pair);
            $_POST[$key] = $value;
        }
        
        $formId = $_POST['EncryptPost_form'];
        
        unset($_POST['EncryptPost'], $_POST['EncryptPost_form']);
        
        return $formId;
    }
    
    /**
    * Encrypt the $data key/values array of formId
    * 
    * @param array $data
    * @param string $form Form id.
    * 
    * @return array
    */
    public function encodeData($data, $formId)
    {
        if (!$data || !$formId) return false;
        
        if (!isset($_SESSION['aesKey'])) die("Encrypt: AES key not found");
        
        // Serialize data and form id
        $union = '';
        foreach ($data as $key=>$value){
            $union .= $key . self::SEPARATOR1 . $value . self::SEPARATOR2;    
        }
        $union .= 'EncryptPost_form' . self::SEPARATOR1 . $formId;
        
        // Encrypt the serialized data
        $encrypted = $this->aes256cbc_encrypt($union, $_SESSION['aesKey']);
        
        // Return array of encripted key and data with formId
        return $encrypted;
    }    
}
?>
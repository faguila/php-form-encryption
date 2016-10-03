<?php
/**
* Test script for EncryptPost PHP class
*/                                
session_start();
if (isset($_GET['destroySession'])){
    session_destroy();
    session_start();
}

require_once './EncryptPost.class.php';
$crypto = new EncryptPost(1024, './openssl.cnf'); // Session MUST be started.

if (isset($_GET['resetKeys'])) $crypto->reset();

// Check for FORM encrypted data
if (isset($_POST['EncryptPost'])){
    $cryptedPost = $_POST;              // Save crypted data for debug
    $formId = $crypto->decodeForm();    // Decrypt $_POST contents
    
    // Do stuff here (database record, etc). 
    // Dont forget to secure filter $_POST values.
    //
    // DON'T USE received $_POST values in the HTML code! This will transmit
    // data as clear text to the browser: Use javascript 'EncryptPost.decrypt()' 
    // method to fill your form, so data is decrypted locally at client's browser.
    if (isset($_POST['data1'])){
        $data['data1'] = filter_var($_POST['data1'], FILTER_VALIDATE_INT);
        /* ... etc ... */
    }
    
    // Encrypt processed data if you need to fill form again:
    $encrypted = $crypto->encodeData($_POST, $formId);
}
?>
<!DOCTYPE html>
<html lang="en-EN">
    <head>
        <meta charset="UTF-8">
        <title>EncryptPost</title>
        <meta name="sessionkey" content="<?php echo $_SESSION['RSA_Public_key'];?>">
        <script src="./javascript/rsa_jsbn.js"></script>
        <script src="./javascript/gibberish-aes.js"></script>
        <script src="./javascript/encryptpost.js"></script>
    </head>
    <body>

        <h1>Testing PHP Form Encryption class</h1>
        <form id="form1" method="POST" action="test.php" onsubmit="return EncryptPost.encrypt('form1')">
            Data 1: <input type="text" name="data1" value="" /><br />
            Data 2: <input type="text" name="data2" value="" /><br />
            Data 3: <input type="text" name="data3" value="" /><br />
            Data 4: <textarea cols="40" rows="5" name="data4"></textarea>
            <br />
            <input type="submit" name="submit" value="Submit" /> &nbsp;
            <input type="reset" name="reset" value="Reset" /> &nbsp;
            <a href="test.php?resetKeys=1" onclick="EncryptPost.reset();">Reset keys</a> &nbsp;
            <a href="test.php?destroySession=1">Destroy session</a>
        </form>                                           
        <!-- Fill form input fields -->
        <?php if (isset($encrypted)) { ?>
        <script>EncryptPost.decrypt('<?php echo $encrypted;?>');</script>
        <?php } ?>
        <br />
        <br />
        <?php
            // Debug
            echo '<h2>Session keys:</h2>';
            if (isset($_SESSION['RSA_Public_key'])){
                echo 'RSA public key (hex) = '. $_SESSION['RSA_Public_key'];
                echo '<br /><br />';
            }
            if (isset($_SESSION['aesKey'])){
                echo 'AES key (hex) = '. bin2hex($_SESSION['aesKey']);
                echo '<br />';
            }
            if (isset($cryptedPost)){
                echo '<h2>Received POST data:</h2><pre>';
                var_dump($cryptedPost);
                echo '</pre><br />';
                echo '<h2>Decrypted POST data:</h2><pre>';
                var_dump($_POST);
                echo '</pre><br />';
            }
        ?>
        <br /><hr />
        This class is available at <strong><a href="http://www.phpclasses.org/package/9912-PHP-Encrypt-and-decrypt-forms-with-AES-and-RSA.html">PHPClasses.org</a></strong><br />
    </body>
</html>

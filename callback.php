<?php
/*
Copyright 2014 Daniel Esteban

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

require_once dirname(__FILE__) . "/BitID.php";
require_once dirname(__FILE__) . "/DAO.php";
$bitid = new BitID();
$dao = new DAO();

$variables = $_POST;

$post_data = json_decode(file_get_contents('php://input'), true);
// SIGNED VIA PHONE WALLET (data is send as payload)
if($post_data!==null) {
    $variables = $post_data;
}

// ALL THOSE VARIABLES HAVE TO BE SANITIZED !

$signValid = $bitid->isMessageSignatureValidSafe(@$variables['address'], @$variables['signature'], @$variables['uri'], true);
$nonce = $bitid->extractNonce($variables['uri']);
if($signValid && $dao->checkNonce($nonce) && ($bitid->buildURI(SERVER_URL . 'callback.php', $nonce) === $variables['uri'])) {
    $dao->update($nonce, $variables['address']);


    // SIGNED VIA PHONE WALLET (data is send as payload)
    if($post_data!==null) {
        //DO NOTHING
    } else {
        // SIGNED MANUALLY (data is stored in $_POST+$_REQUEST vs payload)
        // SHOW SOMETHING PRETTY TO THE USER
        session_start();
        $_SESSION['user_id'] = $variables['address'];
        header("Location: user.php");
    }


}

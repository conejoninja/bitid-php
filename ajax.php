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
require_once dirname(__FILE__) . "/DAO.php";
$dao = new DAO();
// check if this nonce is logged or not
$address = $dao->address($_POST['nonce'], @$_SERVER['REMOTE_ADDR']);
if($address!==false) {
    // Create session so the user could log in
    session_start();
    $_SESSION['user_id'] = $address;
}
//return address/false to tell the VIEW it could log in now or not
echo json_encode($address);
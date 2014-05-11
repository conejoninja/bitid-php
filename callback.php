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

require_once dirname(__FILE__) . "/BitId.php";
$bitid = new BitId();
?>
<!DOCTYPE html>
<html>
<head>
    <title>BitID Open Protocol - Demonstration site</title>
</head>
<body>

<div class="container">
    <div class="tab-content">
        <div class="tab-pane">
            <div class="spacer40"></div>
            <h3>This is the callback page</h3>
            <ul>
                <?php foreach($_POST as $k => $v) { ?>
                    <li><?php echo $k . ' => ' . $v; ?></li>
                <?php }; ?>
            </ul>
            <div class="spacer40"></div>
            <h3>Is signature valid?</h3>
            <p><?php echo $bitid->isMessageSignatureValidSafe($_POST['address'], $_POST['signature'], $_POST['message'])?'YES :D':'NO :('; ?></p>
            <div class="spacer40"></div>
            <h3>Extract nonce</h3>
            <p><b><?php echo $bitid->extractNonce($_POST['message']); ?></b></p>
            <div class="spacer40"></div>
        </div>
    </div>
</div>

</body>
</html>
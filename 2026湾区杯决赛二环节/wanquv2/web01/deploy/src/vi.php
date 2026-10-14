<?php
// round2 web01 - /var/www/html/vi.php
// This is the file "Xiao Ming" edited directly on the server. After vim exited
// abnormally, the raw bytes of this file stayed behind in the sibling swap file
// .vi.php.swp -- which is how this source got leaked.
//
// Hidden backdoor branch (the real flag exit of this challenge):
//     POST flag=ok  ->  echo file_get_contents('/flag');
if (@$_POST['flag'] == 'ok') {
    $flag_content = file_get_contents('/flag');
    echo $flag_content;
} else {
    echo "Invalid request";
}

<?php
// round2 web01 - /var/www/html/index.php
// The visible landing page: just a placeholder (the real backdoor lives in vi.php).
// Note: "Xiao Ming" also had index.php open when the environment died, so this
// directory carries a .index.php.swp as well.
header('Content-Type: text/html; charset=utf-8');
echo "<!doctype html><title>web01</title><h1>hello</h1><p>nothing to see here</p>";

<?php
require 'index.php';

$testCases = [
    [
        "id" => 1,
        "desc" => "Direct SQL Injection",
        "code" => "mysqli_query(\$conn, 'SELECT * FROM users WHERE id = ' . \$_GET['id']);",
        "mode" => "sql"
    ],
    [
        "id" => 2,
        "desc" => "Safe Constant Query (No Issues)",
        "code" => "mysqli_query(\$conn, 'SELECT * FROM users WHERE id = 5');",
        "mode" => "sql"
    ],
    [
        "id" => 3,
        "desc" => "Intermediate Variable Injection (Taint Propagation)",
        "code" => "\$id = \$_GET['id'];\n\$query = \"SELECT * FROM users WHERE id = \$id\";\nmysqli_query(\$conn, \$query);",
        "mode" => "sql"
    ],
    [
        "id" => 4,
        "desc" => "Deep Variable Taint Propagation",
        "code" => "\$a = \$_POST['data'];\n\$b = \$a;\n\$c = \$b;\necho \$c;",
        "mode" => "xss"
    ],
    [
        "id" => 5,
        "desc" => "Command Injection Vulnerability",
        "code" => "\$target = \$input;\nsystem('ping -c 3 ' . \$target);",
        "mode" => "command"
    ],
    [
        "id" => 6,
        "desc" => "Select All Mode (SQL + XSS)",
        "code" => "\$input = \$_GET['data'];\nmysqli_query(\$conn, \$input);\necho \$input;",
        "mode" => "all"
    ]
];

echo "=== 🛡️ Start PHP AST & Taint Analysis Local Testing ===\n\n";

foreach ($testCases as $t) {
    $rawResults = phpAnalyze($t['code'], $t['mode']);
    $formattedString = formatPhpOutput($rawResults);

    echo "--------------------------------------------------\n";
    echo "ID: " . $t['id'] . " | Mode: [" . $t['mode'] . "] | Desc: " . $t['desc'] . "\n";
    echo $formattedString . "\n";
}
echo "--------------------------------------------------\n";
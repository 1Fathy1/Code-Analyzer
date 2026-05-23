<?php
require 'vendor/autoload.php';

use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

// تفعيل الـ CORS عشان الفرونت إند (React) يقدر يكلم السيرفر براحته
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// معالجة ريكويست الـ Preflight لـ CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// استقبال البيانات كـ JSON من الفرونت إند
$input = json_decode(file_get_contents("php://input"), true);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($input['code'])) {
    $code = $input['code'];
    $vuln = isset($input['vuln']) ? strtolower($input['vuln']) : 'all';

    $rawFindings = phpAnalyze($code, $vuln);
    $finalOutput = formatPhpOutput($rawFindings);

    // الرد النصي الصارم المطلوب لتجنب مشاكل فك ترميز النصوص بالـ Single Quotes
    header("Content-Type: text/plain; charset=utf-8");
    echo $finalOutput;
    exit;
}

// ========================================================
// زائر شجرة الـ AST المخصص لتتبع تلوث الكود (Taint Analysis)
// ========================================================
class SecurityTaintVisitor extends NodeVisitorAbstract {
    public $findings = [];
    private $mode;
    private $taintedVars = []; // مصفوفة لحفظ أسماء المتغيرات الملوثة

    public function __construct($mode) {
        $this->mode = $mode;
    }

    // دالة تفحص لو العقدة تحتوي على مصدر تلوث أو متغير ملوث سابقاً
    private function isNodeTainted(Node $node) {
        // 1. مصادر التلوث الصريحة في PHP (تغطية الـ False Negatives)
        if ($node instanceof Node\Expr\Variable) {
            if (in_array($node->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', 'input'])) {
                return true;
            }
            if (isset($this->taintedVars[$node->name])) {
                return true;
            }
        }
        
        // فحص مصفوفات المدخلات مثل $_GET['id']
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            return $this->isNodeTainted($node->var);
        }

        // فحص دمج النصوص عبر الـ Binary Expressions (. أو +)
        if ($node instanceof Node\Expr\BinaryOp) {
            return $this->isNodeTainted($node->left) || $this->isNodeTainted($node->right);
        }

        // فحص المتغيرات الممررة بداخل نصوص مزدوجة "SELECT * FROM users WHERE id = $id"
        if ($node instanceof Node\Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                if ($part instanceof Node\Expr && $this->isNodeTainted($part)) {
                    return true;
                }
            }
        }

        return false;
    }

    public function enterNode(Node $node) {
        // 1. تتبع الإسناد (Assignment) مثل: $x = $_GET['id']; أو $y = $x;
        if ($node instanceof Node\Expr\Assign) {
            if ($node->var instanceof Node\Expr\Variable) {
                if ($this->isNodeTainted($node->expr)) {
                    $this->taintedVars[$node->var->name] = true;
                }
            }
        }

        // 2. فحص استدعاء الدوال ومصادر الخطورة (Sinks)
        if ($node instanceof Node\Expr\FuncCall) {
            if ($node->name instanceof Node\Name) {
                $funcName = $node->name->toString();

                // فحص SQL Injection
                if ($this->mode === 'sql' && in_array($funcName, ['mysqli_query', 'query', 'db_query', 'exec'])) {
                    foreach ($node->args as $arg) {
                        if ($this->isNodeTainted($arg->value)) {
                            $this->findings[] = [
                                'type' => 'SQL Injection',
                                'line' => $node->getStartLine(),
                                'severity' => 'HIGH'
                            ];
                            break;
                        }
                    }
                }

                // فحص Command Injection
                if ($this->mode === 'command' && in_array($funcName, ['system', 'exec', 'shell_exec', 'passthru'])) {
                    foreach ($node->args as $arg) {
                        if ($this->isNodeTainted($arg->value)) {
                            $this->findings[] = [
                                'type' => 'Command Injection',
                                'line' => $node->getStartLine(),
                                'severity' => 'HIGH'
                            ];
                            break;
                        }
                    }
                }
            }
        }

        // 3. فحص ثغرة الـ XSS (عبر الـ Echo والـ Print البنيوية وليست دالة عادية)
        if ($this->mode === 'xss' && ($node instanceof Node\Stmt\Echo_ || $node instanceof Node\Expr\Print_)) {
            $exprs = $node instanceof Node\Stmt\Echo_ ? $node->exprs : [$node->expr];
            foreach ($exprs as $expr) {
                if ($this->isNodeTainted($expr)) {
                    $this->findings[] = [
                        'type' => 'XSS',
                        'line' => $node->getStartLine(),
                        'severity' => 'HIGH'
                    ];
                    break;
                }
            }
        }
    }
}

// الدالة الأساسية للمحرك
function phpAnalyze($code, $mode) {
    // تصحيح الكود لو اليوزر مبعتش علامة الـ <?php عشان البارسر ميضربش
    if (strpos($code, '<?php') === false) {
        $code = '<?php ' . $code;
    }

    $parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
    try {
        $ast = $parser->parse($code);
    } catch (\Exception $error) {
        return [];
    }

    $availableModes = ['sql', 'xss', 'command'];
    $allFindings = [];

    if ($mode === 'all') {
        foreach ($availableModes as $m) {
            $traverser = new NodeTraverser();
            $visitor = new SecurityTaintVisitor($m);
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);
            $allFindings = array_merge($allFindings, $visitor->findings);
        }
    } else {
        $traverser = new NodeTraverser();
        $visitor = new SecurityTaintVisitor($mode);
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);
        $allFindings = $visitor->findings;
    }

    // تنظيف النتائج وإزالة أي تكرار
    $uniqueFindings = [];
    foreach ($allFindings as $f) {
        $key = $f['type'] . '_' . $f['line'];
        if (!isset($uniqueFindings[$key])) {
            $uniqueFindings[$key] = $f;
        }
    }

    usort($uniqueFindings, function($a, $b) { return $a['line'] - $b['line']; });
    return array_values($uniqueFindings);
}

// دالة الفورمات السحرية لإخراج الـ Single Quotes بالملّي
function formatPhpOutput($findings) {
    if (empty($findings)) return "[]";

    $output = "[\n";
    foreach ($findings as $index => $item) {
        $output .= "    {\n";
        $output .= "        'type': '" . $item['type'] . "',\n";
        $output .= "        'line': " . $item['line'] . ",\n";
        $output .= "        'severity': '" . $item['severity'] . "'\n";
        $output .= "    }";
        if ($index < count($findings) - 1) {
            $output .= ",\n";
        } else {
            $output .= "\n";
        }
    }
    $output .= "]";
    return $output;
}
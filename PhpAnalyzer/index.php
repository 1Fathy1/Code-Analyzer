<?php
use PhpParser\Error;
use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\NodeTraverser;

class SecurityTaintVisitor extends NodeVisitorAbstract {
    public $findings = [];
    private $mode;
    private $taintedVars = [];
    private $hasCsrfCheck = false;

    public function __construct($mode) {
        $this->mode = $mode;
    }

    private function isNodeTainted(Node $node) {
        if ($node instanceof Node\Expr\Variable) {
            if (in_array($node->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', 'input'])) return true;
            if (isset($this->taintedVars[$node->name])) return true;
        }
        if ($node instanceof Node\Expr\ArrayDimFetch) return $this->isNodeTainted($node->var);
        if ($node instanceof Node\Expr\BinaryOp) return $this->isNodeTainted($node->left) || $this->isNodeTainted($node->right);
        if ($node instanceof Node\Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                if ($part instanceof Node\Expr && $this->isNodeTainted($part)) return true;
            }
        }
        return false;
    }

    public function enterNode(Node $node) {
        // تتبع انتقال التلوث
        if ($node instanceof Node\Expr\Assign) {
            if ($node->var instanceof Node\Expr\Variable && $this->isNodeTainted($node->expr)) {
                $this->taintedVars[$node->var->name] = true;
            }
        }

        // كشف حماية الـ CSRF
        if ($node instanceof Node\Expr\ArrayDimFetch) {
            if ($node->var instanceof Node\Expr\Variable && $node->var->name === '_SESSION') {
                if ($node->dim instanceof Node\Scalar\String_ && strpos(strtolower($node->dim->value), 'csrf') !== false) {
                    $this->hasCsrfCheck = true; 
                }
            }
        }

        // فحص الـ Sinks (الدوال والميثودز)
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $funcName = $node->name->toString();

            if ($this->mode === 'sql' && in_array($funcName, ['mysqli_query', 'query', 'db_query', 'exec'])) {
                if ($this->isNodeTainted($node->args[0]->value)) $this->addFinding('SQL Injection', $node->getStartLine(), 'CRITICAL');
            }
            if ($this->mode === 'command' && in_array($funcName, ['system', 'exec', 'shell_exec', 'passthru'])) {
                if ($this->isNodeTainted($node->args[0]->value)) $this->addFinding('Command Injection', $node->getStartLine(), 'CRITICAL');
            }
            if ($this->mode === 'exposure' && in_array($funcName, ['md5', 'sha1'])) {
                $this->addFinding('Sensitive Data Exposure (Weak Hashing)', $node->getStartLine(), 'MEDIUM');
            }
        }

        // فحص الـ PDO (SQLi)
        if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
            if ($this->mode === 'sql' && in_array($node->name->toString(), ['query', 'exec', 'prepare', 'execute'])) {
                if ($this->isNodeTainted($node->args[0]->value)) $this->addFinding('SQL Injection (PDO)', $node->getStartLine(), 'CRITICAL');
            }
        }

        // XSS (Echo / Print / Short Tags)
        if ($this->mode === 'xss') {
            if ($node instanceof Node\Stmt\Echo_ || $node instanceof Node\Expr\Print_) {
                $exprs = $node instanceof Node\Stmt\Echo_ ? $node->exprs : [$node->expr];
                foreach ($exprs as $expr) {
                    if ($this->isNodeTainted($expr)) $this->addFinding('Cross-Site Scripting (XSS)', $node->getStartLine(), 'HIGH');
                }
            }
            if ($node instanceof Node\Stmt\InlineHTML && strpos($node->value, '<?=') !== false) {
                if (strpos($node->value, '_GET') !== false || strpos($node->value, '_POST') !== false) {
                    $this->addFinding('Cross-Site Scripting (XSS Short Tag)', $node->getStartLine(), 'HIGH');
                }
            }
        }
    }

    public function afterTraverse(array $nodes) {
        if ($this->mode === 'csrf' && !$this->hasCsrfCheck) {
            $this->addFinding('Missing CSRF Protection', 1, 'HIGH');
        }
    }

    private function addFinding($type, $line, $severity) {
        $this->findings[] = ['vulnerability' => $type, 'line' => $line, 'severity' => $severity];
    }
}

class AwareXPHPAnalyzer {
    private $parser;
    public function __construct() { $this->parser = (new ParserFactory())->createForNewerVersion(); }

    // 🔥 الدالة المطلوبة: تستقبل كود اليوزر ونوع الثغرة ديناميكياً
    public function analyze($userCode, $userMode) {
        try {
            $ast = $this->parser->parse($userCode);
            if ($ast === null) return ['status' => 'success', 'total_findings' => 0, 'findings' => []];

            $traverser = new NodeTraverser();
            $visitor = new SecurityTaintVisitor(strtolower(trim($userMode)));
            $traverser->addVisitor($visitor);
            $traverser->traverse($ast);

            return ['status' => 'success', 'mode' => $userMode, 'total_findings' => count($visitor->findings), 'findings' => $visitor->findings];
        } catch (Error $error) {
            return ['status' => 'error', 'message' => $error->getMessage()];
        }
    }
}
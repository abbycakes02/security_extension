import * as vscode from 'vscode';

export interface SecurityIssue {
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    severity: vscode.DiagnosticSeverity;
    message: string;
    code: string;
    category: string;
    suggestion?: string;
    fixable: boolean;
}

// Fixed security patterns that actually work with real code
export class SecurityAnalyzer {
    private patterns: SecurityPattern[] = [
        // SQL Injection patterns - FIXED to catch real cases
        {
            id: 'sql-injection-concat',
            category: 'SQL Injection',
            pattern: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*[\+\$\{].*[\+\$\}]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential SQL injection - string concatenation in SQL query',
            suggestion: 'Use parameterized queries or prepared statements'
        },
        {
            id: 'sql-injection-template',
            category: 'SQL Injection',
            pattern: /`.*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\$\{[^}]+\}.*`/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential SQL injection - template literal with variables in SQL',
            suggestion: 'Use parameterized queries instead of template literals'
        },
        {
            id: 'sql-injection-quotes',
            category: 'SQL Injection',
            pattern: /(['"`]).*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*['"`]\s*\+/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential SQL injection - string concatenation in SQL query',
            suggestion: 'Use parameterized queries or prepared statements'
        },
        
        // Hardcoded secrets - IMPROVED patterns
        {
            id: 'hardcoded-password',
            category: 'Secrets',
            pattern: /(password|pwd|secret|key|token)\s*[:=]\s*(['"`])[a-zA-Z0-9@#$%^&*!]{6,}\2/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Hardcoded secret detected',
            suggestion: 'Move secrets to environment variables or secure configuration'
        },
        {
            id: 'api-key-pattern',
            category: 'Secrets',
            pattern: /(['"`])(sk-[a-zA-Z0-9]{20,}|pk_[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{32,})\1/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential API key or secret token detected',
            suggestion: 'Move API keys to environment variables'
        },
        
        // XSS vulnerabilities - FIXED patterns
        {
            id: 'xss-innerHTML',
            category: 'XSS',
            pattern: /\.innerHTML\s*[=+]\s*(?!['"`][^'"`<>]*['"`]$)[^;]*[\+\$\{]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Potential XSS vulnerability with innerHTML and dynamic content',
            suggestion: 'Use textContent, or sanitize input before using innerHTML'
        },
        {
            id: 'xss-outerHTML',
            category: 'XSS',
            pattern: /\.outerHTML\s*[=+]\s*(?!['"`][^'"`<>]*['"`]$)[^;]*[\+\$\{]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Potential XSS vulnerability with outerHTML and dynamic content',
            suggestion: 'Sanitize input before using outerHTML'
        },
        {
            id: 'xss-document-write',
            category: 'XSS',
            pattern: /document\.write\s*\(\s*(?!['"`][^'"`<>]*['"`]\s*\))[^)]*[\+\$\{]/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Potential XSS vulnerability with document.write and dynamic content',
            suggestion: 'Avoid document.write or sanitize input'
        },
        
        // Command injection - FIXED patterns
        {
            id: 'command-injection-exec',
            category: 'Command Injection',
            pattern: /(?:exec|spawn|system)\s*\(\s*(?!['"`][^'"`]*['"`]\s*\))[^)]*[\+\$\{]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential command injection with exec/spawn and dynamic input',
            suggestion: 'Validate input and use parameterized commands or allowlists'
        },
        {
            id: 'command-injection-shell',
            category: 'Command Injection',
            pattern: /child_process\.(exec|spawn)\s*\(\s*(?!['"`][^'"`]*['"`]\s*,)[^,)]*[\+\$\{]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential command injection in child_process execution',
            suggestion: 'Use spawn with array arguments instead of shell commands'
        },
        
        // Weak crypto - IMPROVED
        {
            id: 'weak-crypto-md5',
            category: 'Cryptography',
            pattern: /\.createHash\s*\(\s*['"`]md5['"`]\s*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'MD5 is cryptographically broken',
            suggestion: 'Use SHA-256 or stronger hash algorithms'
        },
        {
            id: 'weak-crypto-sha1',
            category: 'Cryptography',
            pattern: /\.createHash\s*\(\s*['"`]sha1['"`]\s*\)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'SHA1 is cryptographically weak',
            suggestion: 'Use SHA-256 or stronger hash algorithms'
        },
        {
            id: 'weak-crypto-des',
            category: 'Cryptography',
            pattern: /\.createCipher\s*\(\s*['"`]des['"`]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'DES encryption is extremely weak',
            suggestion: 'Use AES-256 or other strong encryption algorithms'
        },
        
        // Insecure random - SPECIFIC contexts
        {
            id: 'insecure-random-security',
            category: 'Randomness',
            pattern: /Math\.random\(\).*(?:token|session|id|key|nonce|salt)/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Math.random() is not cryptographically secure for security purposes',
            suggestion: 'Use crypto.randomBytes() or crypto.getRandomValues() for security'
        },
        
        // Path traversal
        {
            id: 'path-traversal',
            category: 'Path Traversal',
            pattern: /(?:fs\.readFile|fs\.writeFile|fs\.open|path\.join)\s*\([^)]*[\+\$\{][^)]*\.\./gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential path traversal vulnerability',
            suggestion: 'Validate and sanitize file paths, use path.resolve()'
        },
        
        // Prototype pollution
        {
            id: 'prototype-pollution',
            category: 'Prototype Pollution',
            pattern: /\[\s*['"`]__proto__['"`]\s*\]|\[\s*['"`]constructor['"`]\s*\]|\[\s*['"`]prototype['"`]\s*\]/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential prototype pollution vulnerability',
            suggestion: 'Avoid modifying __proto__, constructor, or prototype properties'
        }
    ];

    // Test method to verify patterns work
    public testPatterns(): void {
        const testCases = [
            // SQL Injection tests
            'const query = "SELECT * FROM users WHERE id = " + userId;',
            "const sql = `SELECT * FROM products WHERE name = '${productName}'`;",
            'db.query("UPDATE users SET name = \'" + userName + "\' WHERE id = " + id);',
            
            // XSS tests
            'element.innerHTML = "<div>" + userInput + "</div>";',
            'div.innerHTML = `<span>${data}</span>`;',
            'document.write("<script>" + code + "</script>");',
            
            // Command injection tests
            'exec("ls -la " + directory);',
            'spawn("rm", ["-rf", userPath]);',
            'child_process.exec(`find ${searchPath} -name "*.txt"`);',
            
            // Secrets tests
            'const apiKey = "sk-1234567890abcdefghijklmnop";',
            'password: "mySecretPassword123"',
            'const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";',
            
            // Crypto tests
            'crypto.createHash("md5").update(data).digest("hex");',
            'const hash = crypto.createHash("sha1");',
            'crypto.createCipher("des", key);',
            
            // Random tests
            'const sessionId = Math.random().toString(36);',
            'const token = Math.random() * 1000000;'
        ];

        console.log('=== TESTING SECURITY PATTERNS ===');
        
        testCases.forEach((testCode, index) => {
            console.log(`\nTest ${index + 1}: ${testCode}`);
            
            let foundIssues = 0;
            this.patterns.forEach(pattern => {
                pattern.pattern.lastIndex = 0; // Reset regex
                if (pattern.pattern.test(testCode)) {
                    console.log(`  ✓ DETECTED: ${pattern.message}`);
                    foundIssues++;
                }
            });
            
            if (foundIssues === 0) {
                console.log('  ✗ NO ISSUES DETECTED');
            }
        });
    }

    async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        const text = document.getText();
        const issues: SecurityIssue[] = [];
        
        console.log(`=== ANALYZING DOCUMENT: ${document.fileName} ===`);
        console.log(`Language: ${document.languageId}, Lines: ${document.lineCount}`);
        
        // Run pattern-based analysis
        const patternIssues = this.analyzeWithPatterns(text, document);
        console.log(`Pattern analysis found ${patternIssues.length} issues`);
        issues.push(...patternIssues);
        
        // AI analysis (if configured)
        try {
            const config = vscode.workspace.getConfiguration('securityAnalyzer');
            if (config.get<string>('aiProvider') === 'letta') {
                const { LettaClient } = await import('./lettaClient');
                const lettaConfig = {
                    apiKey: config.get<string>('letta.apiKey') || '',
                    baseUrl: config.get<string>('letta.baseUrl') || 'https://api.letta.com/v1',
                    agentId: config.get<string>('letta.agentId')
                };
                
                if (lettaConfig.apiKey) {
                    const client = new LettaClient(lettaConfig);
                    const fileName = document.fileName.split('/').pop() || 'unknown';
                    const aiIssues = await client.analyzeCode(text, fileName, document.languageId);
                    console.log(`AI analysis found ${aiIssues.length} additional issues`);
                    issues.push(...aiIssues);
                }
            }
        } catch (error) {
            console.error('AI analysis failed:', error);
        }
        
        console.log(`=== TOTAL ISSUES FOUND: ${issues.length} ===`);
        return issues;
    }
    
    private analyzeWithPatterns(text: string, document: vscode.TextDocument): SecurityIssue[] {
        const issues: SecurityIssue[] = [];
        const lines = text.split('\n');
        
        console.log('Running pattern analysis...');
        
        for (const pattern of this.patterns) {
            let patternMatches = 0;
            
            for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
                const line = lines[lineIndex];
                
                // Reset regex lastIndex for global patterns
                pattern.pattern.lastIndex = 0;
                
                let match;
                while ((match = pattern.pattern.exec(line)) !== null) {
                    patternMatches++;
                    
                    console.log(`  Found ${pattern.id} on line ${lineIndex + 1}: "${match[0]}"`);
                    
                    issues.push({
                        line: lineIndex,
                        column: match.index,
                        endLine: lineIndex,
                        endColumn: match.index + match[0].length,
                        severity: pattern.severity,
                        message: pattern.message,
                        code: pattern.id,
                        category: pattern.category,
                        suggestion: pattern.suggestion,
                        fixable: this.isFixable(pattern.id)
                    });
                    
                    // Prevent infinite loops with zero-width matches
                    if (match[0].length === 0) {
                        pattern.pattern.lastIndex++;
                    }
                }
            }
            
            if (patternMatches > 0) {
                console.log(`Pattern ${pattern.id} found ${patternMatches} matches`);
            }
        }
        
        return issues;
    }
    
    private isFixable(patternId: string): boolean {
        const fixablePatterns = [
            'xss-innerHTML', 'xss-outerHTML', 'hardcoded-password', 'api-key-pattern',
            'insecure-random-security', 'weak-crypto-md5', 'weak-crypto-sha1'
        ];
        return fixablePatterns.includes(patternId);
    }
}

interface SecurityPattern {
    id: string;
    category: string;
    pattern: RegExp;
    severity: vscode.DiagnosticSeverity;
    message: string;
    suggestion?: string;
}
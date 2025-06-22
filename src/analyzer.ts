import * as vscode from 'vscode';
import { LettaClient } from './lettaClient';
import { AIAnalysisResponse } from './lettaClient';

interface AIAnalysisIssue {
    line?: number;
    lineEnd?: number;
    severity?: string;
    type?: string;
    message?: string;
    explanation?: string;
    fix?: string;
    codeExample?: string;
    originalCode?: string;
    revisedCode?: string;
    revisionExplanation?: string;
}

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

export class SecurityAnalyzer {
    private patterns: SecurityPattern[] = [
        // SQL Injection patterns
        {
            id: 'sql-injection',
            category: 'SQL Injection',
            pattern: /query\s*=\s*["`'].*\+.*["`']|execute\s*\(\s*["`'].*\+.*["`']/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential SQL injection vulnerability detected',
            suggestion: 'Use parameterized queries or prepared statements'
        },
        
        // Hardcoded secrets
        {
            id: 'hardcoded-password',
            category: 'Secrets',
            pattern: /(password|pwd|secret|key|token)\s*[:=]\s*["`'][^"`'\s]{8,}["`']/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Hardcoded secret detected',
            suggestion: 'Move secrets to environment variables or secure configuration'
        },
        
        // XSS vulnerabilities
        {
            id: 'xss-innerHTML',
            category: 'XSS',
            pattern: /\.innerHTML\s*=\s*.*\+|\.innerHTML\s*=\s*[^"`']*\$\{/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Potential XSS vulnerability with innerHTML',
            suggestion: 'Use textContent or sanitize user input'
        },
        
        // Weak crypto
        {
            id: 'weak-crypto',
            category: 'Cryptography',
            pattern: /md5|sha1(?!sha1)|des|rc4/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: 'Weak cryptographic algorithm detected',
            suggestion: 'Use stronger algorithms like SHA-256, AES, or bcrypt'
        },
        
        // Command injection
        {
            id: 'command-injection',
            category: 'Command Injection',
            pattern: /exec\s*\(\s*["`'].*\+.*["`']|system\s*\(\s*["`'].*\+.*["`']/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: 'Potential command injection vulnerability',
            suggestion: 'Validate and sanitize input, use safer alternatives'
        },
        
        // Insecure random
        {
            id: 'insecure-random',
            category: 'Randomness',
            pattern: /Math\.random\(\)|Random\(\)\.next/gi,
            severity: vscode.DiagnosticSeverity.Information,
            message: 'Insecure random number generation',
            suggestion: 'Use cryptographically secure random generators for security purposes'
        }
    ];

    async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
        const text = document.getText();
        const issues: SecurityIssue[] = [];
        
        // Run pattern-based analysis
        const patternIssues = this.analyzeWithPatterns(text, document);
        issues.push(...patternIssues);
        
        // TODO: Add AI-based analysis here
        // const aiIssues = await this.analyzeWithAI(text, document);
        // issues.push(...aiIssues);
        
        return issues;
    }
    
    private analyzeWithPatterns(text: string, document: vscode.TextDocument): SecurityIssue[] {
        const issues: SecurityIssue[] = [];
        const lines = text.split('\n');
        
        for (const pattern of this.patterns) {
            for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
                const line = lines[lineIndex];
                let match;
                
                // Reset regex lastIndex for global patterns
                pattern.pattern.lastIndex = 0;
                
                while ((match = pattern.pattern.exec(line)) !== null) {
                    const startPos = new vscode.Position(lineIndex, match.index);
                    const endPos = new vscode.Position(lineIndex, match.index + match[0].length);
                    
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
        }
        
        return issues;
    }
    
    private isFixable(patternId: string): boolean {
        const fixablePatterns = ['xss-innerHTML', 'hardcoded-password', 'insecure-random'];
        return fixablePatterns.includes(patternId);
    }
    
    // Placeholder for AI analysis
    private async analyzeWithAI(text: string, document: vscode.TextDocument): Promise<SecurityIssue[]> {
        try {
            const client = new LettaClient();
            const response = await client.analyzeCode(text);
            
            if (!response || !response.issues) {
                throw new Error('No response from AI service');
            }

            const issues = response.issues.map((issue: AIAnalysisIssue) => ({
                line: issue.line || 0,
                column: 0,
                endLine: issue.lineEnd || issue.line || 0,
                endColumn: 0,
                severity: this.mapSeverity(issue.severity || 'error'),
                message: issue.message || 'Security issue detected',
                code: issue.type || 'unknown',
                category: issue.type || 'Unknown',
                suggestion: issue.explanation || issue.fix || issue.codeExample,
                fixable: true
            }));

            return issues;
        } catch (error) {
            console.error('AI analysis failed:', error);
            vscode.window.showWarningMessage('AI analysis failed. Falling back to pattern-based analysis.');
            return this.analyzeWithPatterns(text, document);
        }
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        const severityMap: { [key: string]: vscode.DiagnosticSeverity } = {
            'error': vscode.DiagnosticSeverity.Error,
            'warning': vscode.DiagnosticSeverity.Warning,
            'info': vscode.DiagnosticSeverity.Information,
            'hint': vscode.DiagnosticSeverity.Hint
        };
        
        return severityMap[severity.toLowerCase()] || vscode.DiagnosticSeverity.Error;
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
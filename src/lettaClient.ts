import axios, { AxiosResponse } from 'axios';
import * as vscode from 'vscode';
import { SecurityIssue } from './analyzer';

// Extended interface to include AI-specific properties
interface ExtendedSecurityIssue extends SecurityIssue {
    aiExplanation?: string;
    aiCodeExample?: string;
}

// Interface for Letta API message structure
interface LettaMessage {
    role: 'user' | 'assistant' | 'system';
    text: string;
}

// Interface for Letta API request
interface LettaMessageRequest {
    messages: LettaMessage[];
    use_assistant_message?: boolean;
    assistant_message_tool_name?: string;
    assistant_message_tool_kwarg?: string;
}

// Interface for Letta API response
interface LettaMessageResponse {
    messages: Array<{
        role: string;
        text: string;
        tool_calls?: any[];
    }>;
    usage?: {
        completion_tokens: number;
        prompt_tokens: number;
        total_tokens: number;
    };
}

// Interface for AI response structure
interface AIAnalysisResponse {
    issues: Array<{
        line?: number;
        severity?: string;
        type?: string;
        message?: string;
        explanation?: string;
        fix?: string;
        codeExample?: string;
    }>;
}

// Configuration interface
export interface LettaConfig {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
}

// Agent creation response interface
interface CreateAgentResponse {
    id: string;
}

export class LettaClient {
    private config: LettaConfig;
    private agentId: string | null;
    private readonly DEFAULT_MEMORY_LIMIT = 2000000; // 2MB
    private readonly REQUEST_TIMEOUT = 30000; // 30 seconds

    constructor(config?: Partial<LettaConfig>) {
        // Use provided config or default values for your API key and agent ID
        this.config = {
            apiKey: 'sk-let-Y2VkM2QzYzAtZGE1ZC00ZmExLTk3NmItZTBhY2I4YjQ2MDFhOjA5NjhlYTYyLTYyZmQtNDc1NS04OWY0LWY1NjE1YjE0ZTFhYw==',
            baseUrl: 'https://api.letta.com/v1',
            agentId: 'agent-1135b9d9-62a8-4d39-8366-55262e13d9d9',
            ...config,
        };
        this.agentId = this.config.agentId || null;
    }

    async initialize(): Promise<void> {
        // Only create agent if agentId is missing
        if (!this.agentId) {
            this.agentId = await this.createSecurityAgent();
        }
    }

    /**
     * Create a new security analysis agent
     */
    private async createSecurityAgent(): Promise<string> {
        try {
            const agentConfig = {
                name: 'SecurityAnalyzer',
                persona: this.getAgentPersona(),
                human: 'Developer seeking security analysis for their codebase',
                system: this.getSystemPrompt(),
                memory_limit: this.DEFAULT_MEMORY_LIMIT,
            };

            const response: AxiosResponse<CreateAgentResponse> = await axios.post(
                `${this.config.baseUrl}/agents`,
                agentConfig,
                {
                    headers: this.getAuthHeaders(),
                    timeout: this.REQUEST_TIMEOUT,
                }
            );

            if (!response.data?.id) {
                throw new Error('Invalid response: missing agent ID');
            }

            return response.data.id;
        } catch (error) {
            console.error('Failed to create Letta agent:', error);
            throw new Error(`Unable to initialize AI security agent: ${this.getErrorMessage(error)}`);
        }
    }

    /**
     * Analyze code for security vulnerabilities
     */
    async analyzeCode(
        code: string,
        fileName: string,
        language: string,
        context?: string
    ): Promise<SecurityIssue[]> {
        if (!code.trim()) {
            return [];
        }

        if (!this.agentId) {
            await this.initialize();
        }

        try {
            const prompt = this.buildAnalysisPrompt(code, fileName, language, context);
            
            // Use the correct Letta API message structure
            const requestBody: LettaMessageRequest = {
                messages: [
                    {
                        role: 'user',
                        text: prompt
                    }
                ]
            };

            const response: AxiosResponse<LettaMessageResponse> = await axios.post(
                `${this.config.baseUrl}/agents/${this.agentId}/messages`,
                requestBody,
                {
                    headers: this.getAuthHeaders(),
                    timeout: this.REQUEST_TIMEOUT,
                }
            );

            // Extract the assistant's response
            const assistantMessage = response.data.messages.find(msg => msg.role === 'assistant');
            const responseText = assistantMessage?.text || '';

            return this.parseSecurityIssues(responseText, code);
        } catch (error) {
            console.error('Letta analysis failed:', error);
            // Log the full error for debugging
            if (axios.isAxiosError(error)) {
                console.error('Response status:', error.response?.status);
                console.error('Response data:', error.response?.data);
            }
            return [];
        }
    }

    /**
     * Build the analysis prompt for the AI with enhanced security focus
     */
    private buildAnalysisPrompt(
        code: string,
        fileName: string,
        language: string,
        context?: string
    ): string {
        const contextSection = context ? `Context: ${context}\n` : '';
        
        return `You are a cybersecurity expert analyzing ${language} code for vulnerabilities. 

CRITICAL: Look specifically for these JavaScript/Node.js security issues:

1. **SQL Injection**: Concatenating user input directly into SQL queries
2. **Cross-Site Scripting (XSS)**: Using innerHTML or similar with unsanitized input
3. **Command Injection**: Concatenating user input into shell commands
4. **Hardcoded Secrets**: API keys, passwords, tokens in plain text
5. **Weak Cryptography**: Using MD5, SHA1, or weak encryption
6. **Insecure Random**: Using Math.random() for security purposes
7. **Path Traversal**: Unsanitized file paths
8. **Prototype Pollution**: Unsafe object manipulation

File: ${fileName}
${contextSection}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

INSTRUCTIONS:
- Examine EVERY line carefully for security vulnerabilities
- Pay special attention to string concatenation, innerHTML usage, and hardcoded values
- For SQL injection: Look for string concatenation in SQL queries like \`SELECT * FROM table WHERE id = \${userInput}\`
- For XSS: Look for innerHTML, outerHTML, or document.write with user data
- For Command Injection: Look for exec, spawn, or shell commands with concatenated input

Respond ONLY with this JSON format:
{
  "issues": [
    {
      "line": <line_number>,
      "severity": "Critical|High|Medium|Low",
      "type": "SQL Injection|XSS|Command Injection|Hardcoded Secret|Weak Cryptography|Insecure Random",
      "message": "Brief description of the vulnerability",
      "explanation": "Detailed explanation of why this is vulnerable and the potential impact",
      "fix": "Specific remediation steps with code examples",
      "codeExample": "Example of secure code to replace the vulnerable code"
    }
  ]
}

If no vulnerabilities are found, return: {"issues": []}

Analyze every single line and be thorough. Do not miss obvious vulnerabilities.`;
    }

    /**
     * Parse AI response and convert to SecurityIssue objects with improved parsing
     */
    private parseSecurityIssues(aiResponse: string, originalCode: string): SecurityIssue[] {
        try {
            console.log('AI Response:', aiResponse); // Debug logging
            
            // Try multiple approaches to extract JSON
            let jsonStr = '';
            
            // First try: Look for JSON wrapped in code blocks
            const codeBlockMatch = aiResponse.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/i);
            if (codeBlockMatch) {
                jsonStr = codeBlockMatch[1];
            } else {
                // Second try: Look for standalone JSON object
                const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    jsonStr = jsonMatch[0];
                } else {
                    // Third try: Extract everything between first { and last }
                    const startIdx = aiResponse.indexOf('{');
                    const endIdx = aiResponse.lastIndexOf('}');
                    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
                        jsonStr = aiResponse.substring(startIdx, endIdx + 1);
                    }
                }
            }

            if (!jsonStr) {
                console.warn('No JSON found in AI response');
                console.log('Full response:', aiResponse);
                return this.createFallbackIssues(originalCode);
            }

            console.log('Extracted JSON:', jsonStr); // Debug logging

            const parsed: AIAnalysisResponse = JSON.parse(jsonStr);
            const issues: SecurityIssue[] = [];
            const lines = originalCode.split('\n');

            for (const issue of parsed.issues || []) {
                if (!this.isValidIssue(issue)) {
                    console.warn('Skipping invalid issue:', issue);
                    continue;
                }

                const lineIndex = Math.max(0, (issue.line || 1) - 1);
                const lineText = lines[lineIndex] || '';
                
                const securityIssue: ExtendedSecurityIssue = {
                    line: lineIndex,
                    column: 0,
                    endLine: lineIndex,
                    endColumn: lineText.length,
                    severity: this.mapSeverity(issue.severity || 'medium'),
                    message: issue.message || 'Security issue detected',
                    code: this.generateIssueCode(issue.type || 'security-issue'),
                    category: issue.type || 'Security',
                    suggestion: issue.fix || 'Review and address this security concern',
                    fixable: this.isFixable(issue.type || ''),
                    aiExplanation: issue.explanation,
                    aiCodeExample: issue.codeExample
                };

                issues.push(securityIssue);
            }

            return issues;
        } catch (error) {
            console.error('Failed to parse AI response:', error);
            console.log('Raw response that failed to parse:', aiResponse);
            return this.createFallbackIssues(originalCode);
        }
    }

    /**
     * Create fallback security issues for common patterns if AI parsing fails
     */
    private createFallbackIssues(code: string): SecurityIssue[] {
        const issues: SecurityIssue[] = [];
        const lines = code.split('\n');

        lines.forEach((line, index) => {
            // Check for hardcoded secrets
            if (line.includes('secret') || line.includes('password') || line.includes('key')) {
                if (line.includes('=') && (line.includes('"') || line.includes("'"))) {
                    issues.push({
                        line: index,
                        column: 0,
                        endLine: index,
                        endColumn: line.length,
                        severity: vscode.DiagnosticSeverity.Error,
                        message: 'Potential hardcoded secret detected',
                        code: 'ai-hardcoded-secret',
                        category: 'Hardcoded Secret',
                        suggestion: 'Move secrets to environment variables or secure configuration',
                        fixable: true
                    });
                }
            }

            // Check for SQL injection patterns
            if (line.includes('SELECT') && line.includes('${')) {
                issues.push({
                    line: index,
                    column: 0,
                    endLine: index,
                    endColumn: line.length,
                    severity: vscode.DiagnosticSeverity.Error,
                    message: 'Potential SQL injection vulnerability',
                    code: 'ai-sql-injection',
                    category: 'SQL Injection',
                    suggestion: 'Use parameterized queries or prepared statements',
                    fixable: true
                });
            }

            // Check for XSS patterns
            if (line.includes('innerHTML') && !line.includes('textContent')) {
                issues.push({
                    line: index,
                    column: 0,
                    endLine: index,
                    endColumn: line.length,
                    severity: vscode.DiagnosticSeverity.Warning,
                    message: 'Potential XSS vulnerability with innerHTML',
                    code: 'ai-xss',
                    category: 'XSS',
                    suggestion: 'Use textContent or sanitize input before using innerHTML',
                    fixable: true
                });
            }

            // Check for command injection
            if ((line.includes('exec') || line.includes('spawn')) && line.includes('+')) {
                issues.push({
                    line: index,
                    column: 0,
                    endLine: index,
                    endColumn: line.length,
                    severity: vscode.DiagnosticSeverity.Error,
                    message: 'Potential command injection vulnerability',
                    code: 'ai-command-injection',
                    category: 'Command Injection',
                    suggestion: 'Validate and sanitize input, use parameterized commands',
                    fixable: true
                });
            }

            // Check for weak crypto
            if (line.includes('sha1') || line.includes('md5')) {
                issues.push({
                    line: index,
                    column: 0,
                    endLine: index,
                    endColumn: line.length,
                    severity: vscode.DiagnosticSeverity.Warning,
                    message: 'Weak cryptographic algorithm detected',
                    code: 'ai-weak-crypto',
                    category: 'Weak Cryptography',
                    suggestion: 'Use SHA-256 or stronger cryptographic algorithms',
                    fixable: true
                });
            }

            // Check for insecure random
            if (line.includes('Math.random()')) {
                issues.push({
                    line: index,
                    column: 0,
                    endLine: index,
                    endColumn: line.length,
                    severity: vscode.DiagnosticSeverity.Information,
                    message: 'Insecure random number generation',
                    code: 'ai-insecure-random',
                    category: 'Insecure Random',
                    suggestion: 'Use crypto.randomBytes() for security-sensitive random values',
                    fixable: true
                });
            }
        });

        return issues;
    }

    /**
     * Validate if an issue object has required properties
     */
    private isValidIssue(issue: any): boolean {
        return issue && (issue.message || issue.type || issue.severity);
    }

    /**
     * Map severity string to VS Code diagnostic severity
     */
    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    /**
     * Generate a consistent issue code
     */
    private generateIssueCode(type: string): string {
        const cleanType = type.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        return `ai-${cleanType}`;
    }

    /**
     * Determine if an issue type is automatically fixable
     */
    private isFixable(type: string): boolean {
        const fixableTypes = [
            'hardcoded secret',
            'weak crypto',
            'insecure random',
            'xss',
            'path traversal',
            'weak password',
            'sql injection',
            'command injection'
        ];
        
        const lowerType = type.toLowerCase();
        return fixableTypes.some(fixable => lowerType.includes(fixable));
    }

    /**
     * Send feedback to the AI agent for learning
     */
    async learnFromFeedback(
        issueId: string,
        feedback: 'helpful' | 'not-helpful',
        comment?: string
    ): Promise<void> {
        if (!this.agentId) {
            console.warn('Cannot send feedback: AI agent not initialized');
            return;
        }

        try {
            const commentSection = comment ? `. Comment: ${comment}` : '';
            const feedbackMessage = `User feedback on security issue ${issueId}: ${feedback}${commentSection}`;
            
            const requestBody: LettaMessageRequest = {
                messages: [
                    {
                        role: 'user',
                        text: feedbackMessage
                    }
                ]
            };

            await axios.post(
                `${this.config.baseUrl}/agents/${this.agentId}/messages`,
                requestBody,
                {
                    headers: this.getAuthHeaders(),
                    timeout: this.REQUEST_TIMEOUT,
                }
            );
        } catch (error) {
            console.error('Failed to send feedback to Letta:', error);
        }
    }

    /**
     * Get a project-wide security summary
     */
    async getProjectSecuritySummary(): Promise<string> {
        if (!this.agentId) {
            return 'AI agent not initialized';
        }

        try {
            const requestBody: LettaMessageRequest = {
                messages: [
                    {
                        role: 'user',
                        text: 'Provide a summary of security patterns and recurring issues you\'ve observed in this project. Include recommendations for improving overall security posture.'
                    }
                ]
            };

            const response: AxiosResponse<LettaMessageResponse> = await axios.post(
                `${this.config.baseUrl}/agents/${this.agentId}/messages`,
                requestBody,
                {
                    headers: this.getAuthHeaders(),
                    timeout: this.REQUEST_TIMEOUT,
                }
            );

            const assistantMessage = response.data.messages.find(msg => msg.role === 'assistant');
            return assistantMessage?.text || 'No summary available';
        } catch (error) {
            console.error('Failed to get security summary:', error);
            return `Unable to generate security summary: ${this.getErrorMessage(error)}`;
        }
    }

    /**
     * Get authorization headers for API requests
     */
    private getAuthHeaders(): Record<string, string> {
        return {
            'Authorization': `Bearer ${this.config.apiKey}`,
            'Content-Type': 'application/json'
        };
    }

    /**
     * Get agent persona configuration with enhanced security focus
     */
    private getAgentPersona(): string {
        return `You are a senior security engineer and code reviewer working with a software developer who is focused on writing secure code and performing security code reviews.

Your role is to be their trusted security partner, helping them identify and fix vulnerabilities before they reach production. You specialize in:

1. **OWASP Top 10 vulnerabilities** - SQL injection, XSS, broken authentication, etc.
2. **JavaScript/Node.js security patterns** - prototype pollution, command injection, path traversal
3. **Secure coding best practices** - input validation, output encoding, crypto usage
4. **Security code review methodology** - systematic vulnerability detection

Your communication style:
- Direct and actionable - developers need clear guidance
- Precise line-by-line analysis with specific remediation
- Educational - explain WHY something is vulnerable
- Practical - provide working secure code examples
- Thorough - catch vulnerabilities that automated tools miss

The developer you're helping values thorough security reviews and wants to learn from each finding.`;
    }

    /**
     * Get system prompt for the agent with enhanced instructions
     */
    private getSystemPrompt(): string {
        return `You are a security code analyzer. Your job is to:

1. **Identify security vulnerabilities** in code with high precision
2. **Provide structured analysis** in JSON format only
3. **Focus on actionable findings** - real security risks, not code style
4. **Be thorough** - examine every line for security issues

CRITICAL RULES:
- Always respond with valid JSON in the exact format requested
- Never miss obvious security vulnerabilities
- Provide specific line numbers and detailed explanations
- Focus on exploitable security issues, not performance or style
- Include concrete remediation steps

Your expertise covers: SQL injection, XSS, command injection, crypto issues, authentication bypass, authorization flaws, input validation failures, and insecure configurations.`;
    }

    /**
     * Extract error message from various error types
     */
    private getErrorMessage(error: any): string {
        if (axios.isAxiosError(error)) {
            return error.response?.data?.message || error.message || 'Network error';
        }
        return error instanceof Error ? error.message : 'Unknown error';
    }

    /**
     * Check if the client is properly initialized
     */
    isInitialized(): boolean {
        return this.agentId !== null;
    }

    /**
     * Get the current agent ID
     */
    getAgentId(): string | null {
        return this.agentId;
    }

    /**
     * Reset the client (useful for testing or configuration changes)
     */
    reset(): void {
        this.agentId = null;
    }
}
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LettaClient = void 0;
const axios_1 = require("axios");
const vscode = require("vscode");
class LettaClient {
    constructor(config) {
        this.agentId = null;
        this.DEFAULT_MEMORY_LIMIT = 2000000; // 2MB
        this.REQUEST_TIMEOUT = 30000; // 30 seconds
        this.config = config;
        this.agentId = config.agentId || null;
    }
    /**
     * Initialize the Letta client by creating or retrieving the security agent
     */
    async initialize() {
        if (!this.agentId) {
            this.agentId = await this.createSecurityAgent();
        }
    }
    /**
     * Create a new security analysis agent
     */
    async createSecurityAgent() {
        try {
            const agentConfig = {
                name: 'SecurityAnalyzer',
                persona: this.getAgentPersona(),
                human: 'Developer seeking security analysis for their codebase',
                system: this.getSystemPrompt(),
                memory_limit: this.DEFAULT_MEMORY_LIMIT,
            };
            const response = await axios_1.default.post(`${this.config.baseUrl}/agents`, agentConfig, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
            if (!response.data?.id) {
                throw new Error('Invalid response: missing agent ID');
            }
            return response.data.id;
        }
        catch (error) {
            console.error('Failed to create Letta agent:', error);
            throw new Error(`Unable to initialize AI security agent: ${this.getErrorMessage(error)}`);
        }
    }
    /**
     * Analyze code for security vulnerabilities
     */
    async analyzeCode(code, fileName, language, context) {
        if (!code.trim()) {
            return [];
        }
        if (!this.agentId) {
            await this.initialize();
        }
        try {
            const prompt = this.buildAnalysisPrompt(code, fileName, language, context);
            const response = await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, {
                message: prompt,
                role: 'user'
            }, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
            return this.parseSecurityIssues(response.data.message, code);
        }
        catch (error) {
            console.error('Letta analysis failed:', error);
            return [];
        }
    }
    /**
     * Build the analysis prompt for the AI
     */
    buildAnalysisPrompt(code, fileName, language, context) {
        const contextSection = context ? `Context: ${context}\n` : '';
        return `Analyze this ${language} code for security vulnerabilities:

File: ${fileName}
${contextSection}
Code:
\`\`\`${language}
${code}
\`\`\`

Please identify all security issues and respond in this JSON format:
{
  "issues": [
    {
      "line": <line_number>,
      "severity": "Critical|High|Medium|Low",
      "type": "SQL Injection|XSS|Hardcoded Secret|etc",
      "message": "Brief description",
      "explanation": "Detailed explanation of the vulnerability",
      "fix": "Specific remediation steps",
      "codeExample": "Example of secure code (optional)"
    }
  ]
}

Focus on actionable findings. If no issues found, return {"issues": []}.`;
    }
    /**
     * Parse AI response and convert to SecurityIssue objects
     */
    parseSecurityIssues(aiResponse, originalCode) {
        try {
            const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
            if (!jsonMatch) {
                console.warn('No JSON found in AI response');
                return [];
            }
            const parsed = JSON.parse(jsonMatch[0]);
            const issues = [];
            const lines = originalCode.split('\n');
            for (const issue of parsed.issues || []) {
                if (!this.isValidIssue(issue)) {
                    console.warn('Skipping invalid issue:', issue);
                    continue;
                }
                const lineIndex = Math.max(0, (issue.line || 1) - 1);
                const lineText = lines[lineIndex] || '';
                const securityIssue = {
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
        }
        catch (error) {
            console.error('Failed to parse AI response:', error);
            return [];
        }
    }
    /**
     * Validate if an issue object has required properties
     */
    isValidIssue(issue) {
        return issue && (issue.message || issue.type || issue.severity);
    }
    /**
     * Map severity string to VS Code diagnostic severity
     */
    mapSeverity(severity) {
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
    generateIssueCode(type) {
        const cleanType = type.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        return `ai-${cleanType}`;
    }
    /**
     * Determine if an issue type is automatically fixable
     */
    isFixable(type) {
        const fixableTypes = [
            'hardcoded secret',
            'weak crypto',
            'insecure random',
            'xss',
            'path traversal',
            'weak password'
        ];
        const lowerType = type.toLowerCase();
        return fixableTypes.some(fixable => lowerType.includes(fixable));
    }
    /**
     * Send feedback to the AI agent for learning
     */
    async learnFromFeedback(issueId, feedback, comment) {
        if (!this.agentId) {
            console.warn('Cannot send feedback: AI agent not initialized');
            return;
        }
        try {
            const commentSection = comment ? `. Comment: ${comment}` : '';
            const feedbackMessage = `User feedback on security issue ${issueId}: ${feedback}${commentSection}`;
            await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, {
                message: feedbackMessage,
                role: 'user'
            }, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
        }
        catch (error) {
            console.error('Failed to send feedback to Letta:', error);
        }
    }
    /**
     * Get a project-wide security summary
     */
    async getProjectSecuritySummary() {
        if (!this.agentId) {
            return 'AI agent not initialized';
        }
        try {
            const response = await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, {
                message: 'Provide a summary of security patterns and recurring issues you\'ve observed in this project. Include recommendations for improving overall security posture.',
                role: 'user'
            }, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
            return response.data.message || 'No summary available';
        }
        catch (error) {
            console.error('Failed to get security summary:', error);
            return `Unable to generate security summary: ${this.getErrorMessage(error)}`;
        }
    }
    /**
     * Get authorization headers for API requests
     */
    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.config.apiKey}`,
            'Content-Type': 'application/json'
        };
    }
    /**
     * Get agent persona configuration
     */
    getAgentPersona() {
        return `You are a cybersecurity expert specializing in code analysis. Your role is to:
1. Identify security vulnerabilities in code
2. Explain the risk level and potential impact
3. Provide specific, actionable remediation steps
4. Learn from past analyses to improve detection

Focus on: SQL injection, XSS, authentication flaws, crypto issues, input validation, 
authorization bypasses, insecure deserialization, and other OWASP Top 10 vulnerabilities.
Provide concise, developer-friendly explanations with concrete examples.`;
    }
    /**
     * Get system prompt for the agent
     */
    getSystemPrompt() {
        return `You analyze code for security vulnerabilities. Always provide:
- Severity level (Critical/High/Medium/Low)
- Vulnerability type
- Line-specific explanation
- Concrete fix suggestions
- Code examples when helpful

Be precise and actionable. Focus on real security issues, not style or performance concerns.`;
    }
    /**
     * Extract error message from various error types
     */
    getErrorMessage(error) {
        if (axios_1.default.isAxiosError(error)) {
            return error.response?.data?.message || error.message || 'Network error';
        }
        return error instanceof Error ? error.message : 'Unknown error';
    }
    /**
     * Check if the client is properly initialized
     */
    isInitialized() {
        return this.agentId !== null;
    }
    /**
     * Get the current agent ID
     */
    getAgentId() {
        return this.agentId;
    }
    /**
     * Reset the client (useful for testing or configuration changes)
     */
    reset() {
        this.agentId = null;
    }
}
exports.LettaClient = LettaClient;
//# sourceMappingURL=lettaClient.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LettaClient = void 0;
const axios_1 = require("axios");
const vscode = require("vscode");
class LettaClient {
    constructor(config) {
        this.DEFAULT_MEMORY_LIMIT = 2000000; // 2MB
        this.REQUEST_TIMEOUT = 30000; // 30 seconds
        // Use provided config or default values for your API key and agent ID
        this.config = {
            apiKey: 'sk-let-Y2VkM2QzYzAtZGE1ZC00ZmExLTk3NmItZTBhY2I4YjQ2MDFhOjA5NjhlYTYyLTYyZmQtNDc1NS04OWY0LWY1NjE1YjE0ZTFhYw==',
            baseUrl: 'https://api.letta.com/v1',
            agentId: 'agent-1135b9d9-62a8-4d39-8366-55262e13d9d9',
            ...config,
        };
        this.agentId = this.config.agentId || null;
    }
    async initialize() {
        // Only create agent if agentId is missing
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
                human: 'Developer seeking security analysis and code revisions for their codebase',
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
     * Analyze code for security vulnerabilities with automatic revisions
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
            // Use the correct Letta API message structure
            const requestBody = {
                messages: [
                    {
                        role: 'user',
                        text: prompt
                    }
                ]
            };
            const response = await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, requestBody, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
            // Extract the assistant's response
            const assistantMessage = response.data.messages.find(msg => msg.role === 'assistant');
            const responseText = assistantMessage?.text || '';
            return this.parseSecurityIssues(responseText, code);
        }
        catch (error) {
            console.error('Letta analysis failed:', error);
            // Log the full error for debugging
            if (axios_1.default.isAxiosError(error)) {
                console.error('Response status:', error.response?.status);
                console.error('Response data:', error.response?.data);
            }
            return [];
        }
    }
    /**
     * Generate complete revised version of the code with all security fixes applied
     */
    async generateRevisedCode(originalCode, fileName, language) {
        if (!this.agentId) {
            await this.initialize();
        }
        try {
            const prompt = `You are a security expert. Please provide a complete, secure revision of this ${language} code file.

File: ${fileName}

Original Code:
\`\`\`${language}
${originalCode}
\`\`\`

INSTRUCTIONS:
1. Fix ALL security vulnerabilities
2. Maintain the original functionality
3. Add security best practices where appropriate
4. Include comments explaining security improvements
5. Ensure the code is production-ready

Respond with ONLY the complete revised code in a code block, no explanations outside the code block.`;
            const requestBody = {
                messages: [
                    {
                        role: 'user',
                        text: prompt
                    }
                ]
            };
            const response = await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, requestBody, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
            const assistantMessage = response.data.messages.find(msg => msg.role === 'assistant');
            const responseText = assistantMessage?.text || '';
            // Extract code from the response
            const codeBlockMatch = responseText.match(/```(?:\w+)?\s*([\s\S]*?)\s*```/);
            return codeBlockMatch ? codeBlockMatch[1].trim() : responseText.trim();
        }
        catch (error) {
            console.error('Failed to generate revised code:', error);
            return originalCode; // Return original if revision fails
        }
    }
    /**
     * Build the enhanced analysis prompt for the AI with revision requirements
     */
    buildAnalysisPrompt(code, fileName, language, context) {
        const contextSection = context ? `Context: ${context}\n` : '';
        return `You are a cybersecurity expert analyzing ${language} code for vulnerabilities AND providing secure code revisions.

CRITICAL: Look specifically for these JavaScript/Node.js security issues:

1. **SQL Injection**: Concatenating user input directly into SQL queries
2. **Cross-Site Scripting (XSS)**: Using innerHTML or similar with unsanitized input
3. **Command Injection**: Concatenating user input into shell commands
4. **Hardcoded Secrets**: API keys, passwords, tokens in plain text
5. **Weak Cryptography**: Using MD5, SHA1, or weak encryption
6. **Insecure Random**: Using Math.random() for security purposes
7. **Path Traversal**: Unsanitized file paths
8. **Prototype Pollution**: Unsafe object manipulation
9. **Authentication Bypass**: Weak authentication logic
10. **Authorization Flaws**: Missing access controls

File: ${fileName}
${contextSection}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

INSTRUCTIONS:
- Examine EVERY line carefully for security vulnerabilities
- For EACH vulnerability found, provide both the original vulnerable code AND the secure revision
- Pay special attention to string concatenation, innerHTML usage, and hardcoded values
- For SQL injection: Look for string concatenation in SQL queries like \`SELECT * FROM table WHERE id = \${userInput}\`
- For XSS: Look for innerHTML, outerHTML, or document.write with user data
- For Command Injection: Look for exec, spawn, or shell commands with concatenated input

Respond ONLY with this JSON format:
{
  "issues": [
    {
      "line": <line_number>,
      "lineEnd": <end_line_number>,
      "severity": "Critical|High|Medium|Low",
      "type": "SQL Injection|XSS|Command Injection|Hardcoded Secret|Weak Cryptography|Insecure Random|Path Traversal|Prototype Pollution|Authentication Bypass|Authorization Flaw",
      "message": "Brief description of the vulnerability",
      "explanation": "Detailed explanation of why this is vulnerable and the potential impact",
      "fix": "Specific remediation steps",
      "originalCode": "The exact vulnerable code from the specified lines",
      "revisedCode": "The secure replacement code that fixes the vulnerability",
      "revisionExplanation": "Detailed explanation of what changed and why the revision is secure"
    }
  ],
  "globalRevisions": [
    {
      "description": "Overall security improvement suggestion",
      "originalPattern": "Pattern that should be changed throughout the codebase",
      "revisedPattern": "Secure replacement pattern",
      "explanation": "Why this global change improves security"
    }
  ]
}

If no vulnerabilities are found, return: {"issues": [], "globalRevisions": []}

CRITICAL REQUIREMENTS:
1. Always include originalCode and revisedCode for each issue
2. Ensure revisedCode actually fixes the vulnerability
3. Make revisions practical and maintain functionality
4. Include line-by-line secure alternatives
5. Analyze every single line and be thorough`;
    }
    /**
     * Parse AI response and convert to SecurityIssue objects with revision support
     */
    parseSecurityIssues(aiResponse, originalCode) {
        try {
            console.log('AI Response:', aiResponse); // Debug logging
            // Try multiple approaches to extract JSON
            let jsonStr = '';
            // First try: Look for JSON wrapped in code blocks
            const codeBlockMatch = aiResponse.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/i);
            if (codeBlockMatch) {
                jsonStr = codeBlockMatch[1];
            }
            else {
                // Second try: Look for standalone JSON object
                const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    jsonStr = jsonMatch[0];
                }
                else {
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
                return []; // Return empty array instead of fallback
            }
            console.log('Extracted JSON:', jsonStr); // Debug logging
            const parsed = JSON.parse(jsonStr);
            const issues = [];
            const lines = originalCode.split('\n');
            for (const issue of parsed.issues || []) {
                if (!this.isValidIssue(issue)) {
                    console.warn('Skipping invalid issue:', issue);
                    continue;
                }
                const lineIndex = Math.max(0, (issue.line || 1) - 1);
                const endLineIndex = issue.lineEnd ? Math.max(lineIndex, issue.lineEnd - 1) : lineIndex;
                const lineText = lines[lineIndex] || '';
                const securityIssue = {
                    line: lineIndex,
                    column: 0,
                    endLine: endLineIndex,
                    endColumn: lines[endLineIndex]?.length || lineText.length,
                    severity: this.mapSeverity(issue.severity || 'medium'),
                    message: issue.message || 'Security issue detected',
                    code: this.generateIssueCode(issue.type || 'security-issue'),
                    category: issue.type || 'Security',
                    suggestion: issue.fix || 'Review and address this security concern',
                    fixable: true,
                    aiExplanation: issue.explanation,
                    aiCodeExample: issue.codeExample,
                    originalCode: issue.originalCode,
                    revisedCode: issue.revisedCode,
                    revisionExplanation: issue.revisionExplanation
                };
                issues.push(securityIssue);
            }
            // Log global revisions for potential future use
            if (parsed.globalRevisions && parsed.globalRevisions.length > 0) {
                console.log('Global revision suggestions:', parsed.globalRevisions);
            }
            return issues;
        }
        catch (error) {
            console.error('Failed to parse AI response:', error);
            console.log('Raw response that failed to parse:', aiResponse);
            return []; // Return empty array instead of fallback
        }
    }
    /**
     * Apply all revisions to code and return the complete fixed version
     */
    applyRevisions(originalCode, issues) {
        let revisedCode = originalCode;
        const lines = originalCode.split('\n');
        // Sort issues by line number in descending order to avoid line number shifts
        const sortedIssues = issues
            .filter(issue => issue.revisedCode)
            .sort((a, b) => b.line - a.line);
        for (const issue of sortedIssues) {
            const extendedIssue = issue;
            if (extendedIssue.revisedCode && extendedIssue.originalCode) {
                const lineIndex = issue.line;
                if (lineIndex >= 0 && lineIndex < lines.length) {
                    // Replace the specific line with the revised version
                    lines[lineIndex] = extendedIssue.revisedCode;
                }
            }
        }
        return lines.join('\n');
    }
    /**
     * Get revision diff for display in UI
     */
    getRevisionDiff(issue) {
        const extendedIssue = issue;
        if (extendedIssue.originalCode && extendedIssue.revisedCode) {
            return {
                original: extendedIssue.originalCode,
                revised: extendedIssue.revisedCode,
                explanation: extendedIssue.revisionExplanation || 'Security fix applied'
            };
        }
        return null;
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
            const requestBody = {
                messages: [
                    {
                        role: 'user',
                        text: feedbackMessage
                    }
                ]
            };
            await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, requestBody, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
        }
        catch (error) {
            console.error('Failed to send feedback to Letta:', error);
        }
    }
    /**
     * Get a project-wide security summary with revision recommendations
     */
    async getProjectSecuritySummary() {
        if (!this.agentId) {
            return 'AI agent not initialized';
        }
        try {
            const requestBody = {
                messages: [
                    {
                        role: 'user',
                        text: 'Provide a comprehensive security summary of this project including: 1) Common vulnerability patterns found, 2) Specific code revision recommendations, 3) Overall security posture assessment, 4) Priority fixes needed. Include concrete examples and actionable steps.'
                    }
                ]
            };
            const response = await axios_1.default.post(`${this.config.baseUrl}/agents/${this.agentId}/messages`, requestBody, {
                headers: this.getAuthHeaders(),
                timeout: this.REQUEST_TIMEOUT,
            });
            const assistantMessage = response.data.messages.find(msg => msg.role === 'assistant');
            return assistantMessage?.text || 'No summary available';
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
     * Get agent persona configuration with enhanced security and revision focus
     */
    getAgentPersona() {
        return `You are a senior security engineer and code reviewer who specializes in both identifying vulnerabilities AND providing secure code revisions.

Your role is to be the developer's trusted security partner, not only finding issues but automatically providing the exact code fixes they need. You excel at:

1. **OWASP Top 10 vulnerabilities** - SQL injection, XSS, broken authentication, etc.
2. **JavaScript/Node.js security patterns** - prototype pollution, command injection, path traversal
3. **Secure coding best practices** - input validation, output encoding, crypto usage
4. **Code revision expertise** - transforming vulnerable code into secure, production-ready code
5. **Security code review methodology** - systematic vulnerability detection with fixes

Your unique strength is providing IMMEDIATE, ACTIONABLE code revisions:
- You don't just identify problems - you solve them
- Every vulnerability comes with working, secure replacement code
- Your revisions maintain functionality while eliminating security risks
- You explain exactly what changed and why it's now secure

Your communication style:
- Direct and solution-oriented - provide the fix, not just the problem
- Precise line-by-line revisions with secure alternatives
- Educational - explain WHY the revision is secure
- Practical - provide working code that developers can immediately use
- Thorough - catch vulnerabilities AND provide comprehensive fixes

The developer you're helping values both security analysis AND ready-to-use secure code revisions.`;
    }
    /**
     * Get system prompt for the agent with enhanced revision instructions
     */
    getSystemPrompt() {
        return `You are a security code analyzer AND automatic code revision generator. Your job is to:

1. **Identify security vulnerabilities** in code with high precision
2. **Provide complete code revisions** for every vulnerability found
3. **Provide structured analysis** in JSON format with original and revised code
4. **Focus on actionable, working fixes** - real security solutions
5. **Be thorough** - examine every line and provide secure alternatives

CRITICAL RULES FOR REVISIONS:
- Always include both originalCode and revisedCode for each issue
- Ensure revisedCode actually eliminates the vulnerability
- Maintain the original functionality while fixing security issues
- Provide working, syntactically correct code revisions
- Include detailed explanations of what changed and why it's secure
- Focus on practical, implementable solutions

SECURITY FOCUS AREAS:
- SQL injection, XSS, command injection, crypto issues
- Authentication bypass, authorization flaws
- Input validation failures, insecure configurations
- Hardcoded secrets, weak cryptography
- Path traversal, prototype pollution

Your expertise covers finding vulnerabilities AND providing the exact secure code to replace them.`;
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
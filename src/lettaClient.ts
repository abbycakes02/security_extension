import axios, { AxiosResponse } from 'axios';
import * as vscode from 'vscode';
import { SecurityIssue } from './analyzer';

// Extended interface to include AI-specific properties
interface ExtendedSecurityIssue extends SecurityIssue {
    aiExplanation?: string;
    aiCodeExample?: string;
    cisControl?: string;
    cisVersion?: string;
    complianceLevel?: 'Level 1' | 'Level 2' | 'Level 3';
}

// CIS Control mapping interface
interface CISControl {
    id: string;
    title: string;
    description: string;
    level: 'Level 1' | 'Level 2' | 'Level 3';
    applicableLanguages: string[];
    checks: string[];
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

// Interface for AI response structure with CIS compliance
interface AIAnalysisResponse {
    issues: Array<{
        line?: number;
        severity?: string;
        type?: string;
        message?: string;
        explanation?: string;
        fix?: string;
        codeExample?: string;
        cisControl?: string;
        cisVersion?: string;
        complianceLevel?: string;
    }>;
    cisCompliance?: {
        overallScore: number;
        applicableControls: number;
        passedControls: number;
        failedControls: number;
        summary: string;
    };
}

// Configuration interface
export interface LettaConfig {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    cisVersion?: 'v8' | 'v7';
    complianceLevel?: 'Level 1' | 'Level 2' | 'Level 3';
}

export class LettaClient {
    private config: LettaConfig;
    private agentId: string | null;
    private readonly DEFAULT_MEMORY_LIMIT = 2000000; // 2MB
    private readonly REQUEST_TIMEOUT = 30000; // 30 seconds
    private cisControls: Map<string, CISControl>;

    constructor(config?: Partial<LettaConfig>) {
        // Use provided config or default values for your API key and agent ID
        this.config = {
            apiKey: 'sk-let-Y2VkM2QzYzAtZGE1ZC00ZmExLTk3NmItZTBhY2I4YjQ2MDFhOjA5NjhlYTYyLTYyZmQtNDc1NS04OWY0LWY1NjE1YjE0ZTFhYw==',
            baseUrl: 'https://api.letta.com/v1',
            agentId: 'agent-1135b9d9-62a8-4d39-8366-55262e13d9d9',
            cisVersion: 'v8',
            complianceLevel: 'Level 1',
            ...config,
        };
        this.agentId = this.config.agentId || null;
        this.cisControls = this.initializeCISControls();
    }

    /**
     * Initialize CIS Controls mapping for software development
     */
    private initializeCISControls(): Map<string, CISControl> {
        const controls = new Map<string, CISControl>();

        // CIS Control 3: Data Protection
        controls.set('CIS-3', {
            id: 'CIS-3',
            title: 'Data Protection',
            description: 'Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.',
            level: 'Level 1',
            applicableLanguages: ['javascript', 'typescript', 'node.js', 'python', 'java'],
            checks: [
                'Encrypt sensitive data at rest and in transit',
                'Implement secure key management',
                'Sanitize data before logging',
                'Use secure data transmission protocols'
            ]
        });

        // CIS Control 6: Access Control Management
        controls.set('CIS-6', {
            id: 'CIS-6',
            title: 'Access Control Management',
            description: 'Use the principle of least privilege to authorize access to assets and technologies.',
            level: 'Level 1',
            applicableLanguages: ['javascript', 'typescript', 'node.js', 'python', 'java'],
            checks: [
                'Implement proper authentication mechanisms',
                'Use role-based access control',
                'Validate user permissions before granting access',
                'Implement secure session management'
            ]
        });

        // CIS Control 11: Data Recovery
        controls.set('CIS-11', {
            id: 'CIS-11',
            title: 'Data Recovery',
            description: 'Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets.',
            level: 'Level 1',
            applicableLanguages: ['javascript', 'typescript', 'node.js', 'python', 'java'],
            checks: [
                'Implement secure backup mechanisms',
                'Validate data integrity',
                'Test recovery procedures',
                'Protect backup data from unauthorized access'
            ]
        });

        // CIS Control 16: Application Software Security
        controls.set('CIS-16', {
            id: 'CIS-16',
            title: 'Application Software Security',
            description: 'Manage the security life cycle of in-house developed, hosted, or acquired software.',
            level: 'Level 1',
            applicableLanguages: ['javascript', 'typescript', 'node.js', 'python', 'java'],
            checks: [
                'Input validation and sanitization',
                'Output encoding',
                'SQL injection prevention',
                'Cross-site scripting (XSS) prevention',
                'Command injection prevention',
                'Secure error handling',
                'Secure cryptographic implementations'
            ]
        });

        // CIS Control 18: Penetration Testing
        controls.set('CIS-18', {
            id: 'CIS-18',
            title: 'Penetration Testing',
            description: 'Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses.',
            level: 'Level 2',
            applicableLanguages: ['javascript', 'typescript', 'node.js', 'python', 'java'],
            checks: [
                'Code review for security vulnerabilities',
                'Static application security testing (SAST)',
                'Dynamic application security testing (DAST)',
                'Dependency vulnerability scanning'
            ]
        });

        return controls;
    }

    /**
     * Get CIS controls applicable to the given language
     */
    private getApplicableCISControls(language: string): CISControl[] {
        return Array.from(this.cisControls.values()).filter(control =>
            control.applicableLanguages.includes(language.toLowerCase())
        );
    }

    async initialize(): Promise<void> {
        // Only create agent if agentId is missing
        if (!this.agentId) {
            this.agentId = await this.createSecurityAgent();
        }
    }

    /**
     * Create a new security analysis agent with CIS compliance focus
     */
    private async createSecurityAgent(): Promise<string> {
        try {
            const agentConfig = {
                name: 'CISSecurityAnalyzer',
                persona: this.getAgentPersona(),
                human: 'Developer seeking CIS benchmark compliance and security analysis for their codebase',
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
     * Analyze code for security vulnerabilities with CIS compliance checking
     */
    async analyzeCode(
        code: string,
        fileName: string,
        language: string,
        context?: string
    ): Promise<SecurityIssue[]> {
        console.log('=== ANALYZING CODE WITH CIS COMPLIANCE ===');
        console.log('Code length:', code.length);
        console.log('CIS Version:', this.config.cisVersion);
        console.log('Compliance Level:', this.config.complianceLevel);
        
        if (!code.trim()) {
            return [];
        }

        if (!this.agentId) {
            await this.initialize();
        }

        try {
            const prompt = this.buildCISAnalysisPrompt(code, fileName, language, context);
            
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

            const assistantMessage = response.data.messages.find(msg => msg.role === 'assistant');
            const responseText = assistantMessage?.text || '';

            return this.parseSecurityIssuesWithCIS(responseText, code, language);
        } catch (error) {
            console.error('Letta CIS analysis failed:', error);
            if (axios.isAxiosError(error)) {
                console.error('Response status:', error.response?.status);
                console.error('Response data:', error.response?.data);
            }
            return this.createCISFallbackIssues(code, language);
        }
    }

    /**
     * Build the analysis prompt with CIS benchmark context
     */
    private buildCISAnalysisPrompt(
        code: string,
        fileName: string,
        language: string,
        context?: string
    ): string {
        const applicableControls = this.getApplicableCISControls(language);
        const contextSection = context ? `Context: ${context}\n` : '';
        
        const cisControlsSection = applicableControls.map(control => 
            `**${control.id} - ${control.title}** (${control.level}):\n${control.description}\nChecks: ${control.checks.join(', ')}`
        ).join('\n\n');

        return `You are a cybersecurity expert analyzing ${language} code for CIS Controls ${this.config.cisVersion} compliance at ${this.config.complianceLevel}.

CRITICAL CIS CONTROLS TO EVALUATE:
${cisControlsSection}

PRIMARY SECURITY VULNERABILITIES TO DETECT:
1. **SQL Injection** (CIS-16): Concatenating user input directly into SQL queries
2. **Cross-Site Scripting (XSS)** (CIS-16): Using innerHTML or similar with unsanitized input
3. **Command Injection** (CIS-16): Concatenating user input into shell commands
4. **Hardcoded Secrets** (CIS-3): API keys, passwords, tokens in plain text
5. **Weak Cryptography** (CIS-3): Using MD5, SHA1, or weak encryption
6. **Insecure Authentication** (CIS-6): Weak session management, poor access controls
7. **Input Validation Failures** (CIS-16): Missing or insufficient input validation
8. **Insecure Error Handling** (CIS-16): Exposing sensitive information in errors

File: ${fileName}
${contextSection}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

ANALYSIS REQUIREMENTS:
- Examine EVERY line for CIS control violations
- Map each finding to specific CIS control(s)
- Assess compliance level impact (Level 1/2/3)
- Provide CIS-aligned remediation guidance
- Calculate overall CIS compliance score

Respond ONLY with this JSON format:
{
  "issues": [
    {
      "line": <line_number>,
      "severity": "Critical|High|Medium|Low",
      "type": "SQL Injection|XSS|Command Injection|Hardcoded Secret|Weak Cryptography|Access Control|Input Validation",
      "message": "Brief description linking to CIS control violation",
      "explanation": "Detailed explanation of CIS control violation and security impact",
      "fix": "CIS-aligned remediation steps with code examples",
      "codeExample": "Secure code example following CIS guidelines",
      "cisControl": "CIS-X (e.g., CIS-16)",
      "cisVersion": "${this.config.cisVersion}",
      "complianceLevel": "Level 1|Level 2|Level 3"
    }
  ],
  "cisCompliance": {
    "overallScore": <0-100>,
    "applicableControls": <number>,
    "passedControls": <number>,
    "failedControls": <number>,
    "summary": "Brief CIS compliance assessment"
  }
}

If no violations are found, return: {"issues": [], "cisCompliance": {"overallScore": 100, "applicableControls": X, "passedControls": X, "failedControls": 0, "summary": "Code appears compliant with applicable CIS controls"}}

Focus on CIS control violations that represent real security risks.`;
    }

    /**
     * Parse AI response with CIS compliance information
     */
    private parseSecurityIssuesWithCIS(aiResponse: string, originalCode: string, language: string): SecurityIssue[] {
        try {
            console.log('AI Response with CIS:', aiResponse);
            
            let jsonStr = this.extractJSON(aiResponse);
            if (!jsonStr) {
                console.warn('No JSON found in AI response, using CIS fallback');
                return this.createCISFallbackIssues(originalCode, language);
            }

            const parsed: AIAnalysisResponse = JSON.parse(jsonStr);
            const issues: SecurityIssue[] = [];
            const lines = originalCode.split('\n');

            // Log CIS compliance summary
            if (parsed.cisCompliance) {
                console.log('CIS Compliance Summary:', parsed.cisCompliance);
            }

            for (const issue of parsed.issues || []) {
                if (!this.isValidIssue(issue)) {
                    console.warn('Skipping invalid CIS issue:', issue);
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
                    message: `${issue.message} (${issue.cisControl || 'CIS Violation'})`,
                    code: this.generateCISIssueCode(issue.type || 'cis-violation', issue.cisControl),
                    category: issue.type || 'CIS Compliance',
                    suggestion: issue.fix || 'Review and address this CIS control violation',
                    fixable: this.isFixable(issue.type || ''),
                    aiExplanation: issue.explanation,
                    aiCodeExample: issue.codeExample,
                    cisControl: issue.cisControl,
                    cisVersion: issue.cisVersion || this.config.cisVersion,
                    complianceLevel: issue.complianceLevel as 'Level 1' | 'Level 2' | 'Level 3'
                };

                issues.push(securityIssue);
            }

            return issues;
        } catch (error) {
            console.error('Failed to parse CIS AI response:', error);
            return this.createCISFallbackIssues(originalCode, language);
        }
    }

    /**
     * Create CIS-aware fallback security issues
     */
    private createCISFallbackIssues(code: string, language: string): SecurityIssue[] {
        console.log('=== CIS FALLBACK ANALYSIS ===');
        const issues: SecurityIssue[] = [];
        const lines = code.split('\n');
        const applicableControls = this.getApplicableCISControls(language);

        lines.forEach((line, index) => {
            const trimmedLine = line.trim().toLowerCase();
            
            // CIS-3 Data Protection: Hardcoded secrets
            if (this.detectHardcodedSecrets(trimmedLine)) {
                issues.push(this.createCISIssue(
                    index, line, 'Critical', 'Hardcoded Secret', 
                    'Hardcoded secret violates CIS-3 Data Protection requirements',
                    'CIS-3', 'Move secrets to secure configuration management (CIS-3.1)',
                    'Level 1'
                ));
            }

            // CIS-16 Application Security: SQL Injection
            if (this.detectSQLInjection(trimmedLine)) {
                issues.push(this.createCISIssue(
                    index, line, 'Critical', 'SQL Injection',
                    'SQL injection vulnerability violates CIS-16 Application Software Security',
                    'CIS-16', 'Use parameterized queries as per CIS-16.1 secure coding practices',
                    'Level 1'
                ));
            }

            // CIS-16 Application Security: XSS
            if (this.detectXSS(trimmedLine)) {
                issues.push(this.createCISIssue(
                    index, line, 'High', 'XSS',
                    'XSS vulnerability violates CIS-16 Application Software Security',
                    'CIS-16', 'Implement output encoding as per CIS-16.2 secure development practices',
                    'Level 1'
                ));
            }

            // CIS-16 Application Security: Command Injection
            if (this.detectCommandInjection(trimmedLine)) {
                issues.push(this.createCISIssue(
                    index, line, 'Critical', 'Command Injection',
                    'Command injection violates CIS-16 Application Software Security',
                    'CIS-16', 'Validate and sanitize all inputs per CIS-16.3',
                    'Level 1'
                ));
            }

            // CIS-3 Data Protection: Weak Cryptography
            if (this.detectWeakCrypto(trimmedLine)) {
                issues.push(this.createCISIssue(
                    index, line, 'Medium', 'Weak Cryptography',
                    'Weak cryptographic algorithm violates CIS-3 Data Protection',
                    'CIS-3', 'Use approved strong cryptographic algorithms per CIS-3.11',
                    'Level 1'
                ));
            }

            // CIS-6 Access Control: Insecure Authentication
            if (this.detectInsecureAuth(trimmedLine)) {
                issues.push(this.createCISIssue(
                    index, line, 'High', 'Insecure Authentication',
                    'Insecure authentication violates CIS-6 Access Control Management',
                    'CIS-6', 'Implement secure authentication mechanisms per CIS-6.2',
                    'Level 1'
                ));
            }
        });

        console.log(`CIS Fallback found ${issues.length} issues`);
        return issues;
    }

    // CIS-specific detection methods
    private detectHardcodedSecrets(line: string): boolean {
        return (line.includes('secret') || line.includes('password') || 
                line.includes('key') || line.includes('token')) && 
               line.includes('=') && 
               (line.includes('"') || line.includes("'")) &&
               !line.includes('process.env') && 
               !line.includes('config.');
    }

    private detectSQLInjection(line: string): boolean {
        return (line.includes('select') || line.includes('insert') || 
                line.includes('update') || line.includes('delete')) &&
               (line.includes('${') || line.includes('" +') || 
                line.includes("' +") || line.includes('` +'));
    }

    private detectXSS(line: string): boolean {
        return (line.includes('innerhtml') || line.includes('outerhtml') || 
                line.includes('document.write')) && 
               !line.includes('textcontent') &&
               !line.includes('sanitize');
    }

    private detectCommandInjection(line: string): boolean {
        return (line.includes('exec') || line.includes('spawn') || 
                line.includes('system')) &&
               (line.includes('+') || line.includes('${') || 
                line.includes('" +') || line.includes("' +"));
    }

    private detectWeakCrypto(line: string): boolean {
        return line.includes('sha1') || line.includes('md5') ||
               (line.includes('crypto') && 
                (line.includes('des') || line.includes('rc4')));
    }

    private detectInsecureAuth(line: string): boolean {
        return (line.includes('auth') || line.includes('login') || line.includes('session')) &&
               (line.includes('md5') || line.includes('sha1') || 
                line.includes('math.random') || line.includes('== password'));
    }

    /**
     * Create a CIS-compliant security issue
     */
    private createCISIssue(
        lineIndex: number, 
        lineText: string, 
        severity: string, 
        type: string, 
        message: string, 
        cisControl: string, 
        suggestion: string,
        complianceLevel: string
    ): ExtendedSecurityIssue {
        return {
            line: lineIndex,
            column: 0,
            endLine: lineIndex,
            endColumn: lineText.length,
            severity: this.mapSeverity(severity),
            message,
            code: this.generateCISIssueCode(type, cisControl),
            category: `${type} (${cisControl})`,
            suggestion,
            fixable: true,
            cisControl,
            cisVersion: this.config.cisVersion,
            complianceLevel: complianceLevel as 'Level 1' | 'Level 2' | 'Level 3'
        };
    }

    /**
     * Extract JSON from AI response
     */
    private extractJSON(response: string): string | null {
        const codeBlockMatch = response.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/i);
        if (codeBlockMatch) return codeBlockMatch[1];
        
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        if (jsonMatch) return jsonMatch[0];
        
        const startIdx = response.indexOf('{');
        const endIdx = response.lastIndexOf('}');
        if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
            return response.substring(startIdx, endIdx + 1);
        }
        
        return null;
    }

    /**
     * Generate CIS-specific issue codes
     */
    private generateCISIssueCode(type: string, cisControl?: string): string {
        const cleanType = type.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        const controlSuffix = cisControl ? `-${cisControl.toLowerCase()}` : '';
        return `cis-${cleanType}${controlSuffix}`;
    }

    /**
     * Get CIS compliance report for a project
     */
    async getCISComplianceReport(): Promise<string> {
        if (!this.agentId) {
            return 'AI agent not initialized';
        }

        try {
            const requestBody: LettaMessageRequest = {
                messages: [
                    {
                        role: 'user',
                        text: `Generate a comprehensive CIS Controls ${this.config.cisVersion} compliance report for this project. Include:
                        
1. Overall compliance score and status
2. Breakdown by CIS control category
3. Critical findings requiring immediate attention
4. Recommendations for improving compliance posture
5. Next steps for achieving higher compliance levels

Focus on ${this.config.complianceLevel} requirements.`
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
            return assistantMessage?.text || 'No CIS compliance report available';
        } catch (error) {
            console.error('Failed to get CIS compliance report:', error);
            return `Unable to generate CIS compliance report: ${this.getErrorMessage(error)}`;
        }
    }

    // ... (keep all existing methods from the original class)

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
     * Determine if an issue type is automatically fixable
     */
    private isFixable(type: string): boolean {
        const fixableTypes = [
            'hardcoded secret', 'weak crypto', 'insecure random', 'xss', 
            'path traversal', 'weak password', 'sql injection', 'command injection',
            'input validation', 'access control'
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
            const feedbackMessage = `User feedback on CIS security issue ${issueId}: ${feedback}${commentSection}. Please learn from this for future CIS compliance analysis.`;
            
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
                        text: `Provide a comprehensive security summary including:
                        1. CIS Controls ${this.config.cisVersion} compliance status
                        2. Security patterns and recurring issues observed
                        3. Recommendations for improving overall security posture
                        4. Specific CIS control improvements needed
                        5. Risk assessment and prioritization`
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
     * Get agent persona configuration with CIS focus
     */
    private getAgentPersona(): string {
        return `You are a senior security engineer and CIS Controls expert working with a software developer who needs to ensure their code meets CIS benchmark requirements.

Your expertise includes:

1. **CIS Controls ${this.config.cisVersion}** - Deep knowledge of all 18 controls and their implementation
2. **Secure Software Development** - CIS Control 16 implementation in practice
3. **Data Protection** - CIS Control 3 requirements for encryption and data handling
4. **Access Control Management** - CIS Control 6 implementation patterns
5. **Application Security Testing** - CIS Control 18 practices

Your role is to:
- Analyze code for CIS control violations
- Map security findings to specific CIS controls
- Provide CIS-compliant remediation guidance
- Assess overall compliance posture
- Recommend improvements for higher compliance levels

Communication style:
- Reference specific CIS controls in findings
- Provide compliance-focused remediation
- Explain business risk in CIS framework context
- Prioritize findings by compliance level impact
- Give actionable, CIS-aligned recommendations

The developer values thorough CIS compliance and wants to understand how each security finding impacts their overall compliance posture.`;
    }

    /**
     * Get system prompt for the agent with CIS focus
     */
    private getSystemPrompt(): string {
        return `You are a CIS Controls expert and security code analyzer. Your primary responsibilities:

1. **Analyze code for CIS Controls ${this.config.cisVersion} compliance**
2. **Map security findings to specific CIS controls**  
3. **Provide structured analysis in JSON format**
4. **Focus on ${this.config.complianceLevel} requirements**

CRITICAL CIS CONTROL MAPPING:
- **CIS-3 Data Protection**: Encryption, key management, data handling
- **CIS-6 Access Control**: Authentication, authorization, session management  
- **CIS-11 Data Recovery**: Backup security, data integrity
- **CIS-16 Application Security**: Input validation, secure coding, vulnerability prevention
- **CIS-18 Penetration Testing**: Code review, security testing

ANALYSIS REQUIREMENTS:
- Always map findings to CIS control violations
- Provide CIS version and compliance level context
- Include compliance scoring when possible
- Focus on exploitable security issues that violate CIS controls
- Give CIS-aligned remediation guidance

Your responses must be valid JSON in the exact format requested, with accurate CIS control references.`;
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
     * Get current CIS configuration
     */
    getCISConfig(): { version: string; level: string; controls: string[] } {
        return {
            version: this.config.cisVersion || 'v8',
            level: this.config.complianceLevel || 'Level 1',
            controls: Array.from(this.cisControls.keys())
        };
    }

    /**
     * Update CIS configuration
     */
    updateCISConfig(cisVersion?: 'v8' | 'v7', complianceLevel?: 'Level 1' | 'Level 2' | 'Level 3'): void {
        if (cisVersion) {
            this.config.cisVersion = cisVersion;
        }
        if (complianceLevel) {
            this.config.complianceLevel = complianceLevel;
        }
        
        // Reinitialize CIS controls if version changed
        if (cisVersion) {
            this.cisControls = this.initializeCISControls();
        }
    }

    /**
     * Get detailed information about a specific CIS control
     */
    getCISControlInfo(controlId: string): CISControl | null {
        return this.cisControls.get(controlId) || null;
    }

    /**
     * Get all CIS controls applicable to a language
     */
    getCISControlsForLanguage(language: string): CISControl[] {
        return this.getApplicableCISControls(language);
    }

    /**
     * Validate CIS compliance for a specific control
     */
    async validateCISControl(
        code: string,
        controlId: string,
        language: string
    ): Promise<{ compliant: boolean; issues: SecurityIssue[]; recommendations: string[] }> {
        const control = this.cisControls.get(controlId);
        if (!control) {
            throw new Error(`CIS Control ${controlId} not found`);
        }

        if (!this.agentId) {
            await this.initialize();
        }

        try {
            const prompt = `Analyze this ${language} code specifically for CIS Control ${controlId} compliance:

**${control.title}** (${control.level})
${control.description}

Required checks: ${control.checks.join(', ')}

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

Respond with JSON:
{
  "compliant": true/false,
  "issues": [/* same format as main analysis */],
  "recommendations": ["specific recommendations for ${controlId} compliance"]
}`;

            const requestBody: LettaMessageRequest = {
                messages: [{ role: 'user', text: prompt }]
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
            const responseText = assistantMessage?.text || '';
            
            const jsonStr = this.extractJSON(responseText);
            if (jsonStr) {
                const parsed = JSON.parse(jsonStr);
                return {
                    compliant: parsed.compliant || false,
                    issues: this.parseSecurityIssuesWithCIS(JSON.stringify(parsed), code, language),
                    recommendations: parsed.recommendations || []
                };
            }
            
            return {
                compliant: false,
                issues: [],
                recommendations: [`Unable to analyze ${controlId} compliance - manual review recommended`]
            };
        } catch (error) {
            console.error(`Failed to validate CIS control ${controlId}:`, error);
            return {
                compliant: false,
                issues: [],
                recommendations: [`Error validating ${controlId} - manual review required`]
            };
        }
    }

    /**
     * Generate a CIS control implementation checklist
     */
    generateCISChecklist(language: string): { [controlId: string]: string[] } {
        const checklist: { [controlId: string]: string[] } = {};
        const applicableControls = this.getApplicableCISControls(language);

        applicableControls.forEach(control => {
            checklist[control.id] = control.checks.map(check => 
                `${check} - ${control.level} requirement`
            );
        });

        return checklist;
    }

    /**
     * Reset the client (useful for testing or configuration changes)
     */
    reset(): void {
        this.agentId = null;
        this.cisControls = this.initializeCISControls();
    }

    /**
     * Get CIS compliance statistics from recent analyses
     */
    async getCISStats(): Promise<{
        totalAnalyses: number;
        averageComplianceScore: number;
        commonViolations: { [controlId: string]: number };
        improvementTrends: string;
    }> {
        if (!this.agentId) {
            return {
                totalAnalyses: 0,
                averageComplianceScore: 0,
                commonViolations: {},
                improvementTrends: 'No data available - AI agent not initialized'
            };
        }

        try {
            const requestBody: LettaMessageRequest = {
                messages: [
                    {
                        role: 'user',
                        text: 'Provide statistics on CIS compliance analyses performed, including common violations and trends. Return as JSON with totalAnalyses, averageComplianceScore, commonViolations (object with control IDs as keys and count as values), and improvementTrends (string).'
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
            const responseText = assistantMessage?.text || '';
            
            const jsonStr = this.extractJSON(responseText);
            if (jsonStr) {
                return JSON.parse(jsonStr);
            }
            
            return {
                totalAnalyses: 0,
                averageComplianceScore: 0,
                commonViolations: {},
                improvementTrends: 'Unable to retrieve statistics'
            };
        } catch (error) {
            console.error('Failed to get CIS statistics:', error);
            return {
                totalAnalyses: 0,
                averageComplianceScore: 0,
                commonViolations: {},
                improvementTrends: `Error retrieving statistics: ${this.getErrorMessage(error)}`
            };
        }
    }
}

// Agent creation response interface
interface CreateAgentResponse {
    id: string;
}
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CodeFixProvider = void 0;
const vscode = require("vscode");
class CodeFixProvider {
    provideCodeActions(document, range, context, token) {
        const actions = [];
        // Filter diagnostics from our extension
        const securityDiagnostics = context.diagnostics.filter(diagnostic => diagnostic.source === 'Security Analyzer');
        for (const diagnostic of securityDiagnostics) {
            const code = diagnostic.code;
            switch (code) {
                case 'xss-innerHTML':
                    actions.push(this.createInnerHTMLFix(document, diagnostic));
                    break;
                case 'hardcoded-password':
                    actions.push(this.createEnvironmentVariableFix(document, diagnostic));
                    break;
                case 'insecure-random':
                    actions.push(this.createSecureRandomFix(document, diagnostic));
                    break;
                case 'sql-injection':
                    actions.push(this.createParameterizedQueryFix(document, diagnostic));
                    break;
            }
        }
        return actions;
    }
    createInnerHTMLFix(document, diagnostic) {
        const action = new vscode.CodeAction('Replace innerHTML with textContent', vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        const edit = new vscode.WorkspaceEdit();
        const text = document.getText(diagnostic.range);
        const fixedText = text.replace(/\.innerHTML/g, '.textContent');
        edit.replace(document.uri, diagnostic.range, fixedText);
        action.edit = edit;
        return action;
    }
    createEnvironmentVariableFix(document, diagnostic) {
        const action = new vscode.CodeAction('Replace with environment variable', vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        const edit = new vscode.WorkspaceEdit();
        const text = document.getText(diagnostic.range);
        // Extract the variable name and create env var replacement
        const match = text.match(/(password|pwd|secret|key|token)/i);
        const varName = match ? match[1].toUpperCase() : 'SECRET';
        const envVarName = `process.env.${varName}`;
        // Replace the hardcoded value with environment variable
        const fixedText = text.replace(/[:=]\s*["`'][^"`']*["`']/, `: ${envVarName}`);
        edit.replace(document.uri, diagnostic.range, fixedText);
        action.edit = edit;
        return action;
    }
    createSecureRandomFix(document, diagnostic) {
        const action = new vscode.CodeAction('Use crypto.randomBytes() for secure random', vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        const edit = new vscode.WorkspaceEdit();
        const language = document.languageId;
        let replacement = '';
        if (language === 'javascript' || language === 'typescript') {
            replacement = 'crypto.randomBytes(16).toString(\'hex\')';
        }
        else if (language === 'python') {
            replacement = 'secrets.token_hex(16)';
        }
        if (replacement) {
            edit.replace(document.uri, diagnostic.range, replacement);
            action.edit = edit;
        }
        return action;
    }
    createParameterizedQueryFix(document, diagnostic) {
        const action = new vscode.CodeAction('Convert to parameterized query', vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        // This is a more complex fix that would require understanding the specific SQL library
        // For now, we'll just provide guidance through a command
        action.command = {
            command: 'vscode.open',
            title: 'Learn about parameterized queries',
            arguments: [vscode.Uri.parse('https://owasp.org/www-community/attacks/SQL_Injection')]
        };
        return action;
    }
}
exports.CodeFixProvider = CodeFixProvider;
//# sourceMappingURL=codeFixProvider.js.map
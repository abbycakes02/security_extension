"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DiagnosticsManager = void 0;
const vscode = require("vscode");
class DiagnosticsManager {
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('securityAnalyzer');
    }
    updateDiagnostics(document, issues) {
        const diagnostics = issues.map(issue => {
            const range = new vscode.Range(new vscode.Position(issue.line, issue.column), new vscode.Position(issue.endLine, issue.endColumn));
            const diagnostic = new vscode.Diagnostic(range, issue.message, issue.severity);
            diagnostic.code = issue.code;
            diagnostic.source = 'Security Analyzer';
            // Add additional information for hover
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(new vscode.Location(document.uri, range), `Category: ${issue.category}${issue.suggestion ? `\nSuggestion: ${issue.suggestion}` : ''}`)
            ];
            return diagnostic;
        });
        this.diagnosticCollection.set(document.uri, diagnostics);
    }
    clearDiagnostics(uri) {
        this.diagnosticCollection.delete(uri);
    }
    dispose() {
        this.diagnosticCollection.dispose();
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
//# sourceMappingURL=diagnostic.js.map
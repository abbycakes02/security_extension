import * as vscode from 'vscode';
import { SecurityIssue } from './analyzer';

export class DiagnosticsManager {
    public readonly diagnosticCollection: vscode.DiagnosticCollection;
    
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('securityAnalyzer');
    }
    
    updateDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]): void {
        const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
            const range = new vscode.Range(
                new vscode.Position(issue.line, issue.column),
                new vscode.Position(issue.endLine, issue.endColumn)
            );
            
            const diagnostic = new vscode.Diagnostic(
                range,
                issue.message,
                issue.severity
            );
            
            diagnostic.code = issue.code;
            diagnostic.source = 'Security Analyzer';
            
            // Add additional information for hover
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `Category: ${issue.category}${issue.suggestion ? `\nSuggestion: ${issue.suggestion}` : ''}`
                )
            ];
            
            return diagnostic;
        });
        
        this.diagnosticCollection.set(document.uri, diagnostics);
    }
    
    clearDiagnostics(uri: vscode.Uri): void {
        this.diagnosticCollection.delete(uri);
    }
    
    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
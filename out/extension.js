"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = require("vscode");
const analyzer_1 = require("./analyzer");
const diagnostic_1 = require("./diagnostic");
const codeFixProvider_1 = require("./codeFixProvider");
let analyzer;
let diagnosticsManager;
let codeFixProvider;
function activate(context) {
    console.log('Security Analyzer extension is now active!');
    // Initialize components
    analyzer = new analyzer_1.SecurityAnalyzer();
    diagnosticsManager = new diagnostic_1.DiagnosticsManager();
    codeFixProvider = new codeFixProvider_1.CodeFixProvider();
    // Register code fix provider
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(['javascript', 'typescript', 'python', 'java'], codeFixProvider, {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    });
    // Command to analyze current file
    const analyzeFileCommand = vscode.commands.registerCommand('securityAnalyzer.analyzeFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }
        await analyzeDocument(editor.document);
    });
    // Command to analyze entire workspace
    const analyzeWorkspaceCommand = vscode.commands.registerCommand('securityAnalyzer.analyzeWorkspace', async () => {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Analyzing workspace for security issues...",
            cancellable: true
        }, async (progress, token) => {
            const files = await vscode.workspace.findFiles('**/*.{js,ts,py,java}');
            const total = files.length;
            for (let i = 0; i < files.length; i++) {
                if (token.isCancellationRequested)
                    break;
                const doc = await vscode.workspace.openTextDocument(files[i]);
                await analyzeDocument(doc);
                progress.report({
                    increment: (100 / total),
                    message: `Analyzed ${i + 1}/${total} files`
                });
            }
        });
    });
    // Auto-analyze on file changes
    const onDidChangeTextDocument = vscode.workspace.onDidChangeTextDocument(async (event) => {
        const config = vscode.workspace.getConfiguration('securityAnalyzer');
        if (config.get('autoAnalyze')) {
            // Debounce analysis to avoid excessive calls
            setTimeout(() => analyzeDocument(event.document), 1000);
        }
    });
    // Auto-analyze when opening files
    const onDidOpenTextDocument = vscode.workspace.onDidOpenTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('securityAnalyzer');
        if (config.get('autoAnalyze')) {
            await analyzeDocument(document);
        }
    });
    // Register all disposables
    context.subscriptions.push(analyzeFileCommand, analyzeWorkspaceCommand, onDidChangeTextDocument, onDidOpenTextDocument, codeActionProvider, diagnosticsManager.diagnosticCollection);
}
exports.activate = activate;
async function analyzeDocument(document) {
    if (!shouldAnalyzeDocument(document))
        return;
    try {
        const issues = await analyzer.analyzeDocument(document);
        diagnosticsManager.updateDiagnostics(document, issues);
        if (issues.length > 0) {
            vscode.window.showInformationMessage(`Found ${issues.length} security issue(s) in ${document.fileName}`);
        }
    }
    catch (error) {
        console.error('Analysis error:', error);
        vscode.window.showErrorMessage('Security analysis failed');
    }
}
function shouldAnalyzeDocument(document) {
    // Only analyze supported file types
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java'];
    if (!supportedLanguages.includes(document.languageId))
        return false;
    // Skip very large files (>1MB)
    if (document.getText().length > 1024 * 1024)
        return false;
    // Skip node_modules and other common excludes
    if (document.uri.path.includes('node_modules') ||
        document.uri.path.includes('.git') ||
        document.uri.path.includes('dist/') ||
        document.uri.path.includes('build/')) {
        return false;
    }
    return true;
}
function deactivate() {
    if (diagnosticsManager) {
        diagnosticsManager.dispose();
    }
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map
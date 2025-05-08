// Test TypeScript code with suspicious constructs
function maliciousFunction() {
    // Suspicious eval via Function constructor
    const dynamicCode = "return alert('Backdoored!')";
    const execFunction = new Function(dynamicCode);
    execFunction();

    // Using type assertion to bypass type checking
    const userInput = (document.getElementById('user-input') as HTMLInputElement).value;
    (<any>window).eval(userInput);

    // Dynamic import (can be abused with dynamic paths)
    const moduleName = 'sensitive_module';
    import(moduleName).then(module => {
        module.executeCommand();
    });

    // Using as any to bypass type checking
    const unsafeData = JSON.parse(userInput) as any;
    unsafeData.execute();

    // Global namespace pollution
    declare global {
        interface Window {
            executeUnsafeCode: (code: string) => void;
        }
    }

    // Namespace with eval usage
    namespace UnsafeNamespace {
        export function dangerousFunction() {
            eval("console.log('Executed from namespace')");
        }
    }
}

// Interface that potentially exposes sensitive operations
interface DangerousInterface {
    executeCommand: (cmd: string) => void;
    injectHTML: (content: string) => void;
    readFile: (path: string) => string;
}

// Constructor.constructor abuse pattern
function sneakyEval(code: string): any {
    return function(){}.constructor.constructor(code)();
} 
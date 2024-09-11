import logging
import re
import json
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.bytecodes import apk
from androguard.misc import AnalyzeAPK
from xml.dom import minidom
import lxml.etree as ET

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Utility function to parse the APK file into an AST-like structure
def parse_ast_from_apk(apk_file_path):
    a, d, dx = AnalyzeAPK(apk_file_path)

    # Get the package name of the APK to filter only relevant classes
    package_name = a.get_package()

    ast = []

    for cls in dx.get_classes():
        class_name = str(cls.name)
        
        # Filter out external classes by checking if they start with the APK's package name
        if not class_name.startswith('L' + package_name):
            continue  # Skip classes not in the APK's package

        class_info = {'name': class_name, 'methods': []}
        for method in cls.get_methods():
            method_info = {
                'name': str(method.name),
                'code': None
            }
            if not method.is_external():  # Ensure it's an internal method before accessing the code
                method_code = method.get_method().get_code()
                if method_code:
                    bytecode = method_code.get_bc().get_raw()
                    method_info['code'] = bytecode.hex()  # Convert bytecode to hex string
            class_info['methods'].append(method_info)
        ast.append(class_info)

    logger.info(f"AST Analysis: {json.dumps(ast, indent=4)}")
    return ast


# 2. Detect insecure cryptography practices
def detect_insecure_cryptography(ast):
    insecure_practices = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(MD5|SHA-1|DES)', code_str):
                    insecure_practices.append(f"Method {method['name']} in class {cls['name']} uses insecure cryptography")
    logger.info(f"Insecure Cryptography: {json.dumps(insecure_practices, indent=4)}")
    return insecure_practices

# 3. Analyze control flow for unsafe patterns
def analyze_control_flow(ast):
    unsafe_patterns = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(while\s*\(true\)|goto\s+.*\b|throw\s+.*\b)', code_str):
                    unsafe_patterns.append(f"Method {method['name']} in class {cls['name']} has unsafe control flow")
    logger.info(f"Control Flow Analysis: {json.dumps(unsafe_patterns, indent=4)}")
    return unsafe_patterns

# 4. Detect hardcoded secrets
def detect_hardcoded_secrets(ast):
    secrets = []
    secret_patterns = [r'API_KEY', r'password', r'token', r'key']
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                for pattern in secret_patterns:
                    if re.search(pattern, code_str):
                        secrets.append(f"Method {method['name']} in class {cls['name']} has potential hardcoded secret")
    logger.info(f"Hardcoded Secrets: {json.dumps(secrets, indent=4)}")
    return secrets

# 5. Detect code injection vulnerabilities
def detect_code_injection_vulnerabilities(ast):
    vulnerabilities = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(exec\s*\(.*\)|Runtime.getRuntime().exec\()', code_str):
                    vulnerabilities.append(f"Method {method['name']} in class {cls['name']} may have code injection vulnerability")
    logger.info(f"Code Injection Vulnerabilities: {json.dumps(vulnerabilities, indent=4)}")
    return vulnerabilities

# 6. Find privilege escalation flaws
def find_privilege_escalation_flaws(ast):
    flaws = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(Context.startActivity\(.*\)|Context.startService\(.*\))', code_str):
                    flaws.append(f"Method {method['name']} in class {cls['name']} may have privilege escalation flaw")
    logger.info(f"Privilege Escalation Flaws: {json.dumps(flaws, indent=4)}")
    return flaws

# 7. Detect insecure network calls
def detect_insecure_network_calls(ast):
    insecure_calls = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(http://)', code_str) and not re.search(r'https://', code_str):
                    insecure_calls.append(f"Method {method['name']} in class {cls['name']} makes insecure network calls")
    logger.info(f"Insecure Network Calls: {json.dumps(insecure_calls, indent=4)}")
    return insecure_calls

# 8. Analyze reflection usage
def analyze_reflection_usage(ast):
    reflections = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(Class.forName\(.*\)|Method.invoke\(.*\))', code_str):
                    reflections.append(f"Method {method['name']} in class {cls['name']} uses reflection")
    logger.info(f"Reflection Usage: {json.dumps(reflections, indent=4)}")
    return reflections
# 9. Analyze dynamic code loading
def analyze_dynamic_code_loading(ast):
    dynamic_loading = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(DexClassLoader|PathClassLoader)', code_str):
                    dynamic_loading.append(f"Method {method['name']} in class {cls['name']} uses dynamic code loading")
    logger.info(f"Dynamic Code Loading: {json.dumps(dynamic_loading, indent=4)}")
    return dynamic_loading

# 10. Detect excessive permissions usage

    return excessive_permissions
# 11. Detect malicious behavior patterns
def detect_malicious_behavior_patterns(ast):
    malicious_patterns = []
    for cls in ast:
        for method in cls['methods']:
            if method['code']:
                code_str = method['code']
                if re.search(r'(getSystemService\(.*\)|getSharedPreferences\(.*\))', code_str):
                    malicious_patterns.append(f"Method {method['name']} in class {cls['name']} has potential malicious behavior")
    logger.info(f"Malicious Behavior Patterns: {json.dumps(malicious_patterns, indent=4)}")
    return malicious_patterns

# 12. Generate AST analysis report
def generate_ast_analysis_report(ast, manifest_file, output_format='json'):
    report = {
        'insecure_cryptography': detect_insecure_cryptography(ast),
        'control_flow_issues': analyze_control_flow(ast),
        'hardcoded_secrets': detect_hardcoded_secrets(ast),
        'code_injection_vulnerabilities': detect_code_injection_vulnerabilities(ast),
        'privilege_escalation_flaws': find_privilege_escalation_flaws(ast),
        'insecure_network_calls': detect_insecure_network_calls(ast),
        'reflection_usage': analyze_reflection_usage(ast),
        'dynamic_code_loading': analyze_dynamic_code_loading(ast),
        #'excessive_permissions_usage': detect_excessive_permissions_usage(ast, manifest_file),
        'malicious_behavior_patterns': detect_malicious_behavior_patterns(ast),
    }

    if output_format == 'json':
        report_json = json.dumps(report, indent=4)
        logger.info(f"AST Analysis Report: {report_json}")
        return report_json
    elif output_format == 'html':
        # Implement HTML report generation here if needed
        pass
    else:
        raise ValueError("Unsupported output format")

# Example usage
if __name__ == "__main__":
    apk_file_path = "encryptor.apk"  # Replace with the actual path to the APK file
    manifest_file = "AndroidManifest.xml"   # Replace with the actual path to AndroidManifest.xml

    ast = parse_ast_from_apk(apk_file_path)
    generate_ast_analysis_report(ast, manifest_file)

import logging
import os
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.misc import AnalyzeAPK
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json
from xml.dom import minidom
import lxml.etree as ET

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. Extract APK Info
def parse_apk_info(apk_file):
    apk = APK(apk_file)
    info = {
        'package_name': apk.get_package(),
        'version_code': apk.get_androidversion_code(),
        'version_name': apk.get_androidversion_name(),
        'target_sdk': apk.get_target_sdk_version(),
        'permissions': apk.get_permissions()
    }
    logger.info(f"APK Info: {json.dumps(info, indent=4)}")
    return info

# 2. Extract AndroidManifest.xml
def extract_manifest(apk_file):
    apk = APK(apk_file)
    manifest_xml = apk.get_android_manifest_xml()
    manifest_xml_str = ET.tostring(manifest_xml, encoding='unicode')
    manifest_dom = minidom.parseString(manifest_xml_str)

    exported_components = []
    activities = manifest_dom.getElementsByTagName('activity')
    for activity in activities:
        if activity.getAttribute('android:exported') == 'true':
            exported_components.append(f"Activity: {activity.getAttribute('android:name')}")

    services = manifest_dom.getElementsByTagName('service')
    for service in services:
        if service.getAttribute('android:exported') == 'true':
            exported_components.append(f"Service: {service.getAttribute('android:name')}")

    receivers = manifest_dom.getElementsByTagName('receiver')
    for receiver in receivers:
        if receiver.getAttribute('android:exported') == 'true':
            exported_components.append(f"Receiver: {receiver.getAttribute('android:name')}")

    debuggable = manifest_dom.documentElement.getAttribute('android:debuggable') == 'true'

    manifest_issues = {
        'exported_components': exported_components,
        'debuggable': debuggable,
    }

    logger.info(f"Manifest Analysis: {json.dumps(manifest_issues, indent=4)}")
    return manifest_issues

# 3. Extract and Disassemble DEX Files (optimized to avoid excessive strings)
def extract_dex_files(apk_file):
    apk, dvm_list, _ = AnalyzeAPK(apk_file)
    
    dex_analysis = {'total_classes': 0, 'total_methods': 0}
    
    for dvm in dvm_list:
        dex_analysis['total_classes'] += len(dvm.get_classes())
        for c in dvm.get_classes():
            dex_analysis['total_methods'] += len(c.get_methods())

    logger.info(f"DEX Analysis: {json.dumps(dex_analysis, indent=4)}")
    return dex_analysis

# 4. Find Sensitive APIs

SENSITIVE_APIS = ['java/security', 'javax/crypto', 'android/net', 'android/content']

# Exclude common third-party libraries from analysis
EXCLUDE_PACKAGES = ['Landroidx', 'Lcom/google', 'Landroid/support', 'Lkotlin']

def find_sensitive_apis(apk_file):
    apk, dvm_list, _ = AnalyzeAPK(apk_file)
    sensitive_api_usage = []

    # Iterate over each DEX file in the APK
    for dvm in dvm_list:
        # Iterate over classes in the DEX file
        for class_def in dvm.get_classes():
            class_name = str(class_def.get_name())
            
            # Skip classes from third-party packages
            if any(package in class_name for package in EXCLUDE_PACKAGES):
                continue

            # Iterate over methods in each class
            for method in class_def.get_methods():
                method_name = str(method.get_name())
                # Check if the method has associated code
                code = method.get_code()
                if code:
                    # Get bytecode and iterate over instructions
                    for instruction in code.get_bc().get_instructions():
                        instruction_str = str(instruction)  # Convert instruction to string
                        # Check if any instruction contains a reference to sensitive APIs
                        if any(api in instruction_str for api in SENSITIVE_APIS):
                            sensitive_api_usage.append(
                                f"Class {class_name} -> Method {method_name} references sensitive API in instruction: {instruction_str}"
                            )

    # Log the sensitive API usage
    logger.info(f"Sensitive API Usage: {json.dumps(sensitive_api_usage, indent=4)}")
    return sensitive_api_usage


# 5. Extract and Analyze Resource Files
def extract_resource_files(apk_file):
    apk = APK(apk_file)
    resources = apk.get_files()
    hardcoded_credentials = []

    for resource in resources:
        if "res/values/strings.xml" in resource:
            strings_xml = apk.get_file(resource)
            if b"password" in strings_xml or b"API_KEY" in strings_xml:
                hardcoded_credentials.append(f"Potential hardcoded credential in: {resource}")

    logger.info(f"Resource Analysis: {json.dumps(hardcoded_credentials, indent=4)}")
    return hardcoded_credentials

# 6. Analyze Permissions
def analyze_permissions(apk_file):
    apk = APK(apk_file)
    permissions = apk.get_permissions()
    dangerous_permissions = ['android.permission.READ_SMS', 'android.permission.WRITE_EXTERNAL_STORAGE']

    overprivileged = [perm for perm in permissions if perm in dangerous_permissions]
    permission_analysis = {
        'declared_permissions': permissions,
        'overprivileged': overprivileged
    }

    logger.info(f"Permission Analysis: {json.dumps(permission_analysis, indent=4)}")
    return permission_analysis

# 7. Analyze Code Signatures
def analyze_code_signatures(apk_file):
    """
    Analyze code signatures in the APK file, extracting certificate information
    such as subject, issuer, and validity period from each certificate.
    """
    apk = APK(apk_file)
    
    # Retrieve certificates from APK in DER format
    certs = apk.get_certificates_der_v2() or apk.get_certificates_der_v1()  # For APK Signature Scheme v2 or v1

    cert_info = []
    for cert_bytes in certs:
        # Load the certificate using the cryptography library
        x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
   
        # Extract certificate information and convert datetime objects to ISO 8601 strings
        cert_info.append({
            'subject': x509_cert.subject.rfc4514_string(),
            'issuer': x509_cert.issuer.rfc4514_string(),
            'valid_from': x509_cert.not_valid_before.isoformat(),  # Convert datetime to string
            'valid_to': x509_cert.not_valid_after.isoformat()      # Convert datetime to string
        })

    # Log the analyzed certificate information
    logger.info(f"Code Signature Analysis: {json.dumps(cert_info, indent=4)}")
    return cert_info



# 8. Check Native Code Libraries
def check_native_code_libraries(apk_file):
    apk = APK(apk_file)
    native_files = [file for file in apk.get_files() if file.endswith(".so")]
    
    native_libraries = []
    for native in native_files:
        architecture = os.path.basename(os.path.dirname(native))
        native_libraries.append({
            'library': native,
            'architecture': architecture
        })

    logger.info(f"Native Code Libraries: {json.dumps(native_libraries, indent=4)}")
    return native_libraries

# 9. Detect Obfuscation Techniques
def detect_obfuscation(apk_file):
    _, dvm_list, _ = AnalyzeAPK(apk_file)
    obfuscated_classes = []

    for dvm in dvm_list:
        for c in dvm.get_classes():
            if len(c.get_name()) < 3:  # Short class names are a sign of obfuscation
                obfuscated_classes.append(c.get_name())

    logger.info(f"Obfuscated Classes: {json.dumps(obfuscated_classes, indent=4)}")
    return obfuscated_classes

# 10. Generate APK Summary Report
def generate_apk_summary_report(apk_file):
    logger.info("Generating APK summary report...")
    report = {
        'apk_info': parse_apk_info(apk_file),
        'manifest_analysis': extract_manifest(apk_file),
        'dex_analysis': extract_dex_files(apk_file),
        'sensitive_api_usage': find_sensitive_apis(apk_file),
        'resource_analysis': extract_resource_files(apk_file),
        'permission_analysis': analyze_permissions(apk_file),
        'code_signature_analysis': analyze_code_signatures(apk_file),
        'native_library_analysis': check_native_code_libraries(apk_file),
        'obfuscation_analysis': detect_obfuscation(apk_file),
    }
    logger.info(f"APK Summary Report: {json.dumps(report, indent=4)}")
    return report

# Example usage
if __name__ == "__main__":
    apk_path = "zomato.apk"
    generate_apk_summary_report(apk_path)

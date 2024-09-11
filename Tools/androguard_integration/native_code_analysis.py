import os
import json
from androguard_integration.apk_parsing import parse_apk
from androguard_integration.native_code_analysis import (
    load_native_libraries,
    disassemble_native_code,
    detect_buffer_overflows,
    analyze_memory_management,
    detect_privilege_escalation_vulnerabilities,
    identify_unsafe_casting_and_pointer_usage,
    detect_insecure_use_of_system_apis,
    analyze_cryptographic_implementations,
    check_for_hardcoded_credentials_and_sensitive_data,
    detect_exploitable_format_string_vulnerabilities,
    identify_improper_file_access_and_insecure_file_operations,
    perform_cross_architecture_analysis,
    analyze_interactions_with_java_code,
    generate_native_code_analysis_report
)

def main(apk_file_path):
    # Step 1: Parse the APK file to extract native libraries
    ast = parse_apk(apk_file_path)
    if not ast:
        print("Failed to parse APK or AST is empty.")
        return

    # Step 2: Load native libraries
    native_libraries = load_native_libraries(apk_file_path)
    if not native_libraries:
        print("No native libraries found in APK.")
        return

    # Step 3: Analyze each native library
    results = {}

    for lib_name, native_library in native_libraries.items():
        print(f"Analyzing library: {lib_name}")

        # Disassemble native code
        assembly_instructions = disassemble_native_code(native_library)

        # Detect buffer overflows
        results[f"{lib_name}_buffer_overflows"] = detect_buffer_overflows(assembly_instructions)

        # Analyze memory management
        results[f"{lib_name}_memory_management"] = analyze_memory_management(assembly_instructions)

        # Detect privilege escalation vulnerabilities
        results[f"{lib_name}_privilege_escalation_vulnerabilities"] = detect_privilege_escalation_vulnerabilities(assembly_instructions)

        # Identify unsafe casting and pointer usage
        results[f"{lib_name}_unsafe_casting_and_pointer_usage"] = identify_unsafe_casting_and_pointer_usage(assembly_instructions)

        # Detect insecure use of system APIs
        results[f"{lib_name}_insecure_use_of_system_apis"] = detect_insecure_use_of_system_apis(native_library)

        # Analyze cryptographic implementations
        results[f"{lib_name}_cryptographic_implementations"] = analyze_cryptographic_implementations(native_library)

        # Check for hardcoded credentials and sensitive data
        results[f"{lib_name}_hardcoded_credentials_and_sensitive_data"] = check_for_hardcoded_credentials_and_sensitive_data(assembly_instructions)

        # Detect exploitable format string vulnerabilities
        results[f"{lib_name}_exploitable_format_string_vulnerabilities"] = detect_exploitable_format_string_vulnerabilities(assembly_instructions)

        # Identify improper file access and insecure file operations
        results[f"{lib_name}_improper_file_access_and_insecure_file_operations"] = identify_improper_file_access_and_insecure_file_operations(native_library)

        # Perform cross-architecture analysis
        cross_arch_analysis = perform_cross_architecture_analysis(native_libraries)
        results[f"{lib_name}_cross_architecture_analysis"] = cross_arch_analysis.get(lib_name, {})

        # Analyze interactions with Java code
        results[f"{lib_name}_interactions_with_java_code"] = analyze_interactions_with_java_code(native_library)

    # Step 4: Generate the analysis report
    output_format = 'json'
    report = generate_native_code_analysis_report(results, output_format)
    
    # Save or print the report
    with open('native_code_analysis_report.json', 'w') as report_file:
        json.dump(report, report_file, indent=4)
    
    print("Native code analysis report generated: native_code_analysis_report.json")

if __name__ == "__main__":
    apk_file_path = "path_to_your_apk_file.apk"  # Replace with the actual APK file path
    main(apk_file_path)

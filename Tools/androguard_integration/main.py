from androguard_integration.apk_parsing import parse_apk
from androguard_integration.ast_analysis import analyze_ast
from androguard_integration.data_flow_analysis import build_data_flow_graph, generate_data_flow_analysis_report
from androguard_integration.control_flow_analysis import build_control_flow_graph, generate_control_flow_analysis_report

def main(apk_file_path):
    # Step 1: Parse the APK file to get the AST
    ast = parse_apk(apk_file_path)
    if not ast:
        print("Failed to parse APK or AST is empty.")
        return

    # Step 2: Perform AST analysis (optional, depends on your implementation)
    analyze_ast(ast)

    # Step 3: Build Data Flow Graph and perform Data Flow Analysis
    df_graph = build_data_flow_graph(ast)
    print("Data Flow Analysis Report:")
    generate_data_flow_analysis_report(df_graph)

    # Step 4: Build Control Flow Graph and perform Control Flow Analysis
    cfg = build_control_flow_graph(ast)
    print("Control Flow Analysis Report:")
    generate_control_flow_analysis_report(cfg)

if __name__ == "__main__":
    apk_file_path = "path_to_your_apk_file.apk"  # Replace with the actual APK file path
    main(apk_file_path)

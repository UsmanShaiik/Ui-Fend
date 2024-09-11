import json
import networkx as nx
from  androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.misc import AnalyzeAPK
import re

def build_data_flow_graph(ast):
    df_graph = nx.DiGraph()

    for cls in ast:
        for method in cls['methods']:
            method_name = method['name']
            nodes = method['code'].split('\n') if method['code'] else []
            data_nodes = set()
            
            for idx, node in enumerate(nodes):
                current_node = f"{method_name}_{idx}"
                df_graph.add_node(current_node, type='data', value=node)
                
                # Detect data sources and sinks
                if re.search(r'(input|user_data|network_data)', node):
                    df_graph.nodes[current_node]['type'] = 'source'
                if re.search(r'(database|file_storage)', node):
                    df_graph.nodes[current_node]['type'] = 'sink'
                
                # Adding edges based on data flow
                if idx > 0:
                    prev_node = f"{method_name}_{idx-1}"
                    df_graph.add_edge(prev_node, current_node)
                
                # Collect all data nodes
                if 'source' in df_graph.nodes[current_node]['type']:
                    data_nodes.add(current_node)

    return df_graph

def detect_tainted_data_flow(df_graph):
    tainted_data_flows = []
    for node in df_graph.nodes:
        if df_graph.nodes[node]['type'] == 'source':
            successors = list(nx.descendants(df_graph, node))
            for succ in successors:
                if df_graph.nodes[succ]['type'] == 'sink':
                    tainted_data_flows.append((node, succ))
    return tainted_data_flows

def analyze_sensitive_data_flow(df_graph):
    sensitive_data_flows = []
    for node in df_graph.nodes:
        if 'sensitive' in df_graph.nodes[node]['value'].lower():
            successors = list(nx.descendants(df_graph, node))
            for succ in successors:
                if 'sink' in df_graph.nodes[succ]['type']:
                    sensitive_data_flows.append((node, succ))
    return sensitive_data_flows

def check_for_data_leaks(df_graph):
    data_leaks = []
    for node in df_graph.nodes:
        if df_graph.nodes[node]['type'] == 'sink':
            # Check if data reaches an external sink
            predecessors = list(df_graph.predecessors(node))
            for pred in predecessors:
                if df_graph.nodes[pred]['type'] == 'source':
                    data_leaks.append((pred, node))
    return data_leaks

def detect_unsafe_data_validation(df_graph):
    unsafe_validations = []
    for node in df_graph.nodes:
        if re.search(r'(validation_error|unsafe_validation)', df_graph.nodes[node]['value']):
            unsafe_validations.append(node)
    return unsafe_validations

def find_hardcoded_sensitive_data(df_graph):
    hardcoded_data = []
    for node in df_graph.nodes:
        if re.search(r'(password|api_key|token)', df_graph.nodes[node]['value']):
            hardcoded_data.append(node)
    return hardcoded_data

def track_interprocedural_data_flow(df_graph):
    interprocedural_flows = []
    for edge in df_graph.edges:
        src_node, tgt_node = edge
        if 'data' in df_graph.nodes[src_node]['type'] and 'data' in df_graph.nodes[tgt_node]['type']:
            interprocedural_flows.append(edge)
    return interprocedural_flows

def analyze_data_flow_for_privilege_escalation(df_graph):
    privilege_escalation = []
    for node in df_graph.nodes:
        if re.search(r'(privilege|role|access_token)', df_graph.nodes[node]['value']):
            successors = list(nx.descendants(df_graph, node))
            for succ in successors:
                if re.search(r'(elevated_privilege|admin)', df_graph.nodes[succ]['value']):
                    privilege_escalation.append((node, succ))
    return privilege_escalation

def detect_data_flow_for_side_channel_attacks(df_graph):
    side_channel_attacks = []
    for node in df_graph.nodes:
        if re.search(r'(timing_attack|cache_leak)', df_graph.nodes[node]['value']):
            side_channel_attacks.append(node)
    return side_channel_attacks

def identify_unsafe_data_storage(df_graph):
    unsafe_storage = []
    for node in df_graph.nodes:
        if re.search(r'(insecure_storage|plaintext)', df_graph.nodes[node]['value']):
            unsafe_storage.append(node)
    return unsafe_storage

def detect_insecure_transmission(df_graph):
    insecure_transmission = []
    for node in df_graph.nodes:
        if re.search(r'(http|plaintext)', df_graph.nodes[node]['value']):
            insecure_transmission.append(node)
    return insecure_transmission

def generate_data_flow_analysis_report(df_graph, output_format='json'):
    report = {
        'tainted_data_flow': detect_tainted_data_flow(df_graph),
        'sensitive_data_flow': analyze_sensitive_data_flow(df_graph),
        'data_leaks': check_for_data_leaks(df_graph),
        'unsafe_data_validation': detect_unsafe_data_validation(df_graph),
        'hardcoded_sensitive_data': find_hardcoded_sensitive_data(df_graph),
        'interprocedural_data_flow': track_interprocedural_data_flow(df_graph),
        'data_flow_privilege_escalation': analyze_data_flow_for_privilege_escalation(df_graph),
        'side_channel_attacks': detect_data_flow_for_side_channel_attacks(df_graph),
        'unsafe_data_storage': identify_unsafe_data_storage(df_graph),
        'insecure_transmission': detect_insecure_transmission(df_graph),
    }

    if output_format == 'json':
        report_json = json.dumps(report, indent=4)
        print(f"Data Flow Analysis Report: {report_json}")
        return report_json
    elif output_format == 'html':
        # Implement HTML report generation here
        pass
    else:
        raise ValueError("Unsupported output format")

# Example usage
if __name__ == "__main__":
    dex_file =  "/home/t/Downloads/Simple Calculator_6.1.0_APKPure.apk" # Replace with actual path to the DEX file
    apk, dvm_list, _ = AnalyzeAPK(dex_file)
    
    # Placeholder for extracting AST
    ast = [{'name': 'example_class', 'methods': [{'name': 'example_method', 'code': 'example_code'}]}]

    df_graph = build_data_flow_graph(ast)
    generate_data_flow_analysis_report(df_graph)

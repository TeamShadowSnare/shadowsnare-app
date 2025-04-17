#!/usr/bin/env python
import subprocess
import re
import os
import csv
import argparse
from collections import defaultdict

def run_volatility_command(memory_image, plugin, debug=True):
    cmd = ['python', 'vol.py', '-f', memory_image, plugin]
    print(f"Running: {' '.join(cmd)}")
    
    # Set environment variable for UTF-8 encoding
    my_env = os.environ.copy()
    my_env["PYTHONIOENCODING"] = "utf-8"
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=my_env)
    
    # Rest of the function...
    if result.returncode != 0:
        print(f"Error running {plugin}: {result.stderr}")
        return ""
    return result.stdout

def extract_pslist_features(memory_image):
    """Extract features from the pslist plugin."""
    output = run_volatility_command(memory_image, 'windows.pslist')
    
    processes = []
    for line in output.split('\n'):
        if 'PID' in line and 'PPID' in line:  # Header line
            continue
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 4:  # Ensure we have enough parts
            try:
                pid = int(parts[1])
                ppid = int(parts[2])
                threads = int(parts[3])
                processes.append({
                    'pid': pid,
                    'ppid': ppid,
                    'threads': threads,
                    'is_64bit': '64bit' in line.lower()
                })
            except (ValueError, IndexError):
                continue
    
    features = {
        'pslist.nproc': len(processes),
        'pslist.nppid': len(set(p['ppid'] for p in processes)),
        'pslist.avg_threads': sum(p['threads'] for p in processes) / len(processes) if processes else 0,
        'pslist.nprocs64bit': sum(1 for p in processes if p['is_64bit']),
    }
    
    # Getting handler count requires windows.handles plugin
    handlers_output = run_volatility_command(memory_image, 'windows.handles')
    handlers_by_pid = defaultdict(int)
    
    for line in handlers_output.split('\n'):
        if 'PID' in line and 'Handle' in line:  # Header line
            continue
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 2:
            try:
                pid = int(parts[1])
                handlers_by_pid[pid] += 1
            except (ValueError, IndexError):
                continue
    
    if handlers_by_pid:
        features['pslist.avg_handlers'] = sum(handlers_by_pid.values()) / len(handlers_by_pid)
    else:
        features['pslist.avg_handlers'] = 0
    
    return features

def extract_dlllist_features(memory_image):
    """Extract features from the dlllist plugin."""
    output = run_volatility_command(memory_image, 'windows.dlllist')
    print(output)

    dlls_by_pid = defaultdict(int)
    total_dlls = 0
    current_pid = None

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Skip known headers
        if 'Process' in line and 'PID' in line:
            continue
        if line.startswith('Base') and 'Size' in line and 'Path' in line:
            continue

        # Identify new process blocks
        pid_match = re.search(r'PID\s+(\d+)', line)
        if pid_match:
            current_pid = int(pid_match.group(1))
            continue

        # Count DLL lines (anything else under a process block)
        if current_pid is not None and 'Command line' not in line:
            dlls_by_pid[current_pid] += 1
            total_dlls += 1

    features = {
        'dlllist.ndlls': total_dlls,
        'dlllist.avg_dlls_per_proc': total_dlls / len(dlls_by_pid) if dlls_by_pid else 0
    }

    return features

def extract_handles_features(memory_image):
    """Extract features from the handles plugin."""
    output = run_volatility_command(memory_image, 'windows.handles')
    
    handles_by_pid = defaultdict(int)
    handle_types = defaultdict(int)
    
    for line in output.split('\n'):
        if 'PID' in line and 'Handle' in line:  # Header line
            continue
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 4:  # Ensure we have enough parts
            try:
                pid = int(parts[1])
                handle_type = parts[3].lower()
                
                handles_by_pid[pid] += 1
                handle_types[handle_type] += 1
            except (ValueError, IndexError):
                continue
    
    total_handles = sum(handles_by_pid.values())
    
    features = {
        'handles.nhandles': total_handles,
        'handles.avg_handles_per_proc': total_handles / len(handles_by_pid) if handles_by_pid else 0,
        'handles.nport': handle_types.get('port', 0),
        'handles.nfile': handle_types.get('file', 0),
        'handles.nevent': handle_types.get('event', 0),
        'handles.ndesktop': handle_types.get('desktop', 0),
        'handles.nkey': handle_types.get('key', 0),
        'handles.nthread': handle_types.get('thread', 0),
        'handles.ndirectory': handle_types.get('directory', 0),
        'handles.nsemaphore': handle_types.get('semaphore', 0),
        'handles.ntimer': handle_types.get('timer', 0),
        'handles.nsection': handle_types.get('section', 0),
        'handles.nmutant': handle_types.get('mutant', 0)
    }
    
    return features

def extract_ldrmodules_features(memory_image):
    """Extract features from the ldrmodules plugin."""
    # Assuming windows.ldrmodules is the correct plugin name in Volatility 3
    output = run_volatility_command(memory_image, 'windows.ldrmodules')
    
    not_in_load = 0
    not_in_init = 0
    not_in_mem = 0
    processes = set()
    
    for line in output.split('\n'):
        if 'PID' in line and 'Process' in line:  # Header line
            continue
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 7:  # Ensure we have enough parts
            try:
                pid = int(parts[1])
                processes.add(pid)
                
                # Check load, init, and mem flags
                load_flag = parts[4].lower()
                init_flag = parts[5].lower()
                mem_flag = parts[6].lower()
                
                if load_flag == 'false':
                    not_in_load += 1
                if init_flag == 'false':
                    not_in_init += 1
                if mem_flag == 'false':
                    not_in_mem += 1
            except (ValueError, IndexError):
                continue
    
    features = {
        'ldrmodules.not_in_load': not_in_load,
        'ldrmodules.not_in_init': not_in_init,
        'ldrmodules.not_in_mem': not_in_mem,
        'ldrmodules.not_in_load_avg': not_in_load / len(processes) if processes else 0,
        'ldrmodules.not_in_init_avg': not_in_init / len(processes) if processes else 0,
        'ldrmodules.not_in_mem_avg': not_in_mem / len(processes) if processes else 0
    }
    
    return features

def extract_malfind_features(memory_image):
    """Extract features from the malfind plugin."""
    output = run_volatility_command(memory_image, 'windows.malfind')
    
    injections = []
    commit_charge_total = 0
    protection_types = defaultdict(int)
    
    current_pid = None
    current_address = None
    
    for line in output.split('\n'):
        if not line.strip():
            continue
        
        # Process line with PID
        pid_match = re.search(r'Process\s+(\w+)\s+PID\s+(\d+)', line)
        if pid_match:
            current_pid = int(pid_match.group(2))
            continue
            
        # VadTag line contains address
        vad_match = re.search(r'VadTag:\s+(\w+)\s+at\s+(0x[0-9a-fA-F]+)', line)
        if vad_match:
            current_address = vad_match.group(2)
            continue
            
        # Commit charge line
        commit_match = re.search(r'CommitCharge:\s+(\d+)', line)
        if commit_match and current_pid and current_address:
            commit_charge = int(commit_match.group(1))
            commit_charge_total += commit_charge
            continue
            
        # Protection line
        protection_match = re.search(r'Protection:\s+(\w+)', line)
        if protection_match and current_pid and current_address:
            protection = protection_match.group(1)
            protection_types[protection] += 1
            
            # Record the injection
            injections.append((current_pid, current_address, protection))
            continue
    
    # Count unique injections (by address)
    unique_injections = len(set(addr for _, addr, _ in injections))
    
    features = {
        'malfind.ninjections': len(injections),
        'malfind.commitCharge': commit_charge_total,
        'malfind.protection': len(protection_types),
        'malfind.uniqueInjections': unique_injections
    }
    
    return features

def extract_psxview_features(memory_image):
    """Extract features from the psxview plugin."""
    # Note: psxview in Volatility 3 might be different or not available
    # This will need to be adapted based on the actual Volatility 3 equivalent
    output = run_volatility_command(memory_image, 'windows.psxview')
    
    # If the plugin doesn't exist or works differently
    if "No plugin named 'windows.psxview'" in output or not output:
        print("Warning: psxview plugin not found or not working in Volatility 3")
        return {
            'psxview.not_in_pslist': 0,
            'psxview.not_in_eprocess_pool': 0,
            'psxview.not_in_ethread_pool': 0,
            'psxview.not_in_pspcid_list': 0,
            'psxview.not_in_csrss_handles': 0,
            'psxview.not_in_session': 0,
            'psxview.not_in_deskthrd': 0,
            'psxview.not_in_pslist_false_avg': 0,
            'psxview.not_in_eprocess_pool_false_avg': 0,
            'psxview.not_in_ethread_pool_false_avg': 0,
            'psxview.not_in_pspcid_list_false_avg': 0,
            'psxview.not_in_csrss_handles_false_avg': 0,
            'psxview.not_in_session_false_avg': 0,
            'psxview.not_in_deskthrd_false_avg': 0
        }
    
    # Process the output if the plugin exists
    not_in_counts = defaultdict(int)
    total_processes = 0
    
    for line in output.split('\n'):
        if 'PID' in line and 'pslist' in line:  # Header line
            continue
        if not line.strip():
            continue
        
        parts = line.split()
        if len(parts) >= 8:  # Ensure we have enough parts
            try:
                total_processes += 1
                
                # Check each visibility method
                if parts[2].lower() == 'false':
                    not_in_counts['pslist'] += 1
                if parts[3].lower() == 'false':
                    not_in_counts['eprocess_pool'] += 1
                if parts[4].lower() == 'false':
                    not_in_counts['ethread_pool'] += 1
                if parts[5].lower() == 'false':
                    not_in_counts['pspcid_list'] += 1
                if parts[6].lower() == 'false':
                    not_in_counts['csrss_handles'] += 1
                if parts[7].lower() == 'false':
                    not_in_counts['session'] += 1
                if len(parts) >= 9 and parts[8].lower() == 'false':
                    not_in_counts['deskthrd'] += 1
            except (ValueError, IndexError):
                continue
    
    features = {
        'psxview.not_in_pslist': not_in_counts['pslist'],
        'psxview.not_in_eprocess_pool': not_in_counts['eprocess_pool'],
        'psxview.not_in_ethread_pool': not_in_counts['ethread_pool'],
        'psxview.not_in_pspcid_list': not_in_counts['pspcid_list'],
        'psxview.not_in_csrss_handles': not_in_counts['csrss_handles'],
        'psxview.not_in_session': not_in_counts['session'],
        'psxview.not_in_deskthrd': not_in_counts['deskthrd'],
        'psxview.not_in_pslist_false_avg': not_in_counts['pslist'] / total_processes if total_processes else 0,
        'psxview.not_in_eprocess_pool_false_avg': not_in_counts['eprocess_pool'] / total_processes if total_processes else 0,
        'psxview.not_in_ethread_pool_false_avg': not_in_counts['ethread_pool'] / total_processes if total_processes else 0,
        'psxview.not_in_pspcid_list_false_avg': not_in_counts['pspcid_list'] / total_processes if total_processes else 0,
        'psxview.not_in_csrss_handles_false_avg': not_in_counts['csrss_handles'] / total_processes if total_processes else 0,
        'psxview.not_in_session_false_avg': not_in_counts['session'] / total_processes if total_processes else 0,
        'psxview.not_in_deskthrd_false_avg': not_in_counts['deskthrd'] / total_processes if total_processes else 0
    }
    
    return features

def extract_modules_features(memory_image):
    """Extract features from the modules plugin."""
    output = run_volatility_command(memory_image, 'windows.modules')
    
    module_count = 0
    for line in output.split('\n'):
        if 'Base' in line and 'Size' in line:  # Header line
            continue
        if line.strip():
            module_count += 1
    
    features = {
        'modules.nmodules': module_count
    }
    
    return features

def extract_svcscan_features(memory_image):
    """Extract features from the svcscan plugin."""
    output = run_volatility_command(memory_image, 'windows.svcscan')
    
    services = []
    kernel_drivers = 0
    fs_drivers = 0
    process_services = 0
    shared_process_services = 0
    interactive_process_services = 0
    active_services = 0
    
    current_service = {}
    
    for line in output.split('\n'):
        if not line.strip():
            if current_service:
                services.append(current_service)
                current_service = {}
            continue
        
        # Service Record line indicates the start of a new service
        if 'Service Record' in line:
            if current_service:
                services.append(current_service)
            current_service = {}
            continue
        
        # Parse service type
        type_match = re.search(r'Type\s*:\s*(\w+)', line)
        if type_match and current_service is not None:
            service_type = type_match.group(1).lower()
            current_service['type'] = service_type
            
            if 'kernel' in service_type and 'driver' in service_type:
                kernel_drivers += 1
            elif 'fs' in service_type and 'driver' in service_type:
                fs_drivers += 1
            elif 'process' in service_type:
                process_services += 1
            elif 'shared' in service_type and 'process' in service_type:
                shared_process_services += 1
            elif 'interactive' in service_type:
                interactive_process_services += 1
            continue
        
        # Parse service state
        state_match = re.search(r'State\s*:\s*(\w+)', line)
        if state_match and current_service is not None:
            service_state = state_match.group(1).lower()
            current_service['state'] = service_state
            
            if 'active' in service_state or 'running' in service_state:
                active_services += 1
            continue
    
    # Add the last service if any
    if current_service:
        services.append(current_service)
    
    features = {
        'svcscan.nservices': len(services),
        'svcscan.kernel_drivers': kernel_drivers,
        'svcscan.fs_drivers': fs_drivers,
        'svcscan.process_services': process_services,
        'svcscan.shared_process_services': shared_process_services,
        'svcscan.interactive_process_services': interactive_process_services,
        'svcscan.nactive': active_services
    }
    
    return features

def extract_callbacks_features(memory_image):
    """Extract features from the callbacks plugin."""
    output = run_volatility_command(memory_image, 'windows.callbacks')
    
    callbacks_count = 0
    anonymous_count = 0
    generic_count = 0
    
    for line in output.split('\n'):
        if 'Type' in line and 'Callback' in line:  # Header line
            continue
        if not line.strip():
            continue
        
        callbacks_count += 1
        
        if 'ANONYMOUS' in line:
            anonymous_count += 1
        if 'GENERIC' in line:
            generic_count += 1
    
    features = {
        'callbacks.ncallbacks': callbacks_count,
        'callbacks.nanonymous': anonymous_count,
        'callbacks.ngeneric': generic_count
    }
    
    return features

def main():
    parser = argparse.ArgumentParser(description='Extract memory forensics features using Volatility 3')
    parser.add_argument('-f', '--file', required=True, help='Memory image file')
    parser.add_argument('-o', '--output', default='memory_features.csv', help='Output CSV file')
    args = parser.parse_args()
    
    # Check if the memory image exists
    if not os.path.isfile(args.file):
        print(f"Error: Memory image file '{args.file}' not found")
        return
    
    # Extract features from different plugins
    all_features = {}
    
    # Extract features from each plugin
    extractors = [
        extract_pslist_features,
        extract_dlllist_features,
        extract_handles_features,
        extract_ldrmodules_features,
        extract_malfind_features,
        extract_psxview_features,
        extract_modules_features,
        extract_svcscan_features,
        extract_callbacks_features
    ]
    
    for extractor in extractors:
        try:
            features = extractor(args.file)
            all_features.update(features)
            print(f"Extracted {len(features)} features from {extractor.__name__}")
        except Exception as e:
            print(f"Error in {extractor.__name__}: {str(e)}")
    
    # Print the extracted features
    print("\nExtracted Features:")
    for feature, value in sorted(all_features.items()):
        print(f"{feature}: {value}")
    
    # Save to CSV
    with open(args.output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Feature', 'Value'])
        for feature, value in sorted(all_features.items()):
            writer.writerow([feature, value])
    
    print(f"\nFeatures saved to {args.output}")

if __name__ == "__main__":
    main()
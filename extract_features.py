#!/usr/bin/env python3
import os
import subprocess
import json
import statistics
import re
import pandas as pd
import csv
from collections import defaultdict, Counter

# Configuration
MEMORY_DUMP = "C:/winpmem/memory_dmp.raw"
VOLATILITY3 = "c:/volatility3/vol.py"
OUTPUT_FILE = "memory_features.csv"

def run_volatility(plugin, args=None):
    """Run a volatility plugin and return the JSON output."""
    # Use --output-format=json instead of -o json
    cmd = ["python", VOLATILITY3, "-f", MEMORY_DUMP, "--output-format=json", plugin]
    if args:
        cmd.extend(args)
    
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running {plugin}: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON output from {plugin}")
        print(f"Raw output: {result.stdout[:500]}...")  # Print first 500 chars of output
        return None

def extract_pslist_features():
    """Extract features from the pslist plugin."""
    data = run_volatility("windows.pslist")
    if not data:
        return {}
    
    processes = data.get("rows", [])
    
    # Count total processes
    nproc = len(processes)
    
    # Count parent processes (unique PPIDs)
    ppids = set(proc[3] for proc in processes)
    nppid = len(ppids)
    
    # Calculate average threads per process
    threads = [int(proc[4]) for proc in processes]
    avg_threads = statistics.mean(threads) if threads else 0
    
    # Count 64-bit processes
    bit64_count = sum(1 for proc in processes if "64bit" in proc[7])
    nprocs64bit = bit64_count
    
    # Calculate average handle count if available
    handles = [int(proc[5]) for proc in processes if proc[5] is not None and proc[5] != ""]
    avg_handlers = statistics.mean(handles) if handles else 0
    
    return {
        "pslist.nproc": nproc,
        "pslist.nppid": nppid,
        "pslist.avg_threads": avg_threads,
        "pslist.nprocs64bit": nprocs64bit,
        "pslist.avg_handlers": avg_handlers
    }

def extract_dlllist_features():
    """Extract features from the dlllist plugin."""
    data = run_volatility("windows.dlllist")
    if not data:
        return {}
    
    rows = data.get("rows", [])
    
    # Group DLLs by process
    dlls_by_proc = defaultdict(list)
    for row in rows:
        proc_id = row[1]  # Process ID column
        if len(row) > 3 and row[3]:  # Check if DLL path exists
            dlls_by_proc[proc_id].append(row[3])
    
    # Count unique DLLs
    all_dlls = [dll for proc_dlls in dlls_by_proc.values() for dll in proc_dlls]
    ndlls = len(set(all_dlls))
    
    # Calculate average DLLs per process
    dll_counts = [len(dlls) for dlls in dlls_by_proc.values()]
    avg_dlls_per_proc = statistics.mean(dll_counts) if dll_counts else 0
    
    return {
        "dlllist.ndlls": ndlls,
        "dlllist.avg_dlls_per_proc": avg_dlls_per_proc
    }

def extract_handles_features():
    """Extract features from the handles plugin."""
    data = run_volatility("windows.handles")
    if not data:
        return {}
    
    rows = data.get("rows", [])
    
    # Count total handles
    nhandles = len(rows)
    
    # Group handles by process
    handles_by_proc = defaultdict(list)
    handle_types = defaultdict(int)
    
    for row in rows:
        proc_id = row[1]  # Process ID column
        handle_type = row[3].lower() if row[3] else "unknown"
        handles_by_proc[proc_id].append(handle_type)
        handle_types[handle_type] += 1
    
    # Calculate average handles per process
    handle_counts = [len(handles) for handles in handles_by_proc.values()]
    avg_handles_per_proc = statistics.mean(handle_counts) if handle_counts else 0
    
    # Count handles by type
    nport = handle_types.get("port", 0)
    nfile = handle_types.get("file", 0)
    nevent = handle_types.get("event", 0)
    ndesktop = handle_types.get("desktop", 0)
    nkey = handle_types.get("key", 0)
    nthread = handle_types.get("thread", 0)
    ndirectory = handle_types.get("directory", 0)
    nsemaphore = handle_types.get("semaphore", 0)
    ntimer = handle_types.get("timer", 0)
    nsection = handle_types.get("section", 0)
    nmutant = handle_types.get("mutant", 0)
    
    return {
        "handles.nhandles": nhandles,
        "handles.avg_handles_per_proc": avg_handles_per_proc,
        "handles.nport": nport,
        "handles.nfile": nfile,
        "handles.nevent": nevent,
        "handles.ndesktop": ndesktop,
        "handles.nkey": nkey,
        "handles.nthread": nthread,
        "handles.ndirectory": ndirectory,
        "handles.nsemaphore": nsemaphore,
        "handles.ntimer": ntimer,
        "handles.nsection": nsection,
        "handles.nmutant": nmutant
    }

def extract_ldrmodules_features():
    """Extract features from the ldrmodules plugin."""
    data = run_volatility("windows.ldrmodules")
    if not data:
        return {}
    
    rows = data.get("rows", [])
    
    # Group modules by process
    modules_by_proc = defaultdict(list)
    not_in_load = 0
    not_in_init = 0
    not_in_mem = 0
    
    for row in rows:
        proc_id = row[1]  # Process ID column
        in_load = row[4]
        in_init = row[5]
        in_mem = row[6]
        
        module_info = {
            "in_load": in_load.lower() == "true" if isinstance(in_load, str) else bool(in_load),
            "in_init": in_init.lower() == "true" if isinstance(in_init, str) else bool(in_init),
            "in_mem": in_mem.lower() == "true" if isinstance(in_mem, str) else bool(in_mem)
        }
        
        modules_by_proc[proc_id].append(module_info)
        
        if not module_info["in_load"]:
            not_in_load += 1
        if not module_info["in_init"]:
            not_in_init += 1
        if not module_info["in_mem"]:
            not_in_mem += 1
    
    # Calculate averages per process
    process_counts = []
    for proc_id, modules in modules_by_proc.items():
        if modules:
            proc_not_in_load = sum(1 for m in modules if not m["in_load"])
            proc_not_in_init = sum(1 for m in modules if not m["in_init"])
            proc_not_in_mem = sum(1 for m in modules if not m["in_mem"])
            
            process_counts.append({
                "not_in_load": proc_not_in_load / len(modules),
                "not_in_init": proc_not_in_init / len(modules),
                "not_in_mem": proc_not_in_mem / len(modules)
            })
    
    not_in_load_avg = statistics.mean([p["not_in_load"] for p in process_counts]) if process_counts else 0
    not_in_init_avg = statistics.mean([p["not_in_init"] for p in process_counts]) if process_counts else 0
    not_in_mem_avg = statistics.mean([p["not_in_mem"] for p in process_counts]) if process_counts else 0
    
    return {
        "ldrmodules.not_in_load": not_in_load,
        "ldrmodules.not_in_init": not_in_init,
        "ldrmodules.not_in_mem": not_in_mem,
        "ldrmodules.not_in_load_avg": not_in_load_avg,
        "ldrmodules.not_in_init_avg": not_in_init_avg,
        "ldrmodules.not_in_mem_avg": not_in_mem_avg
    }

def extract_malfind_features():
    """Extract features from the malfind plugin."""
    data = run_volatility("windows.malfind")
    if not data:
        return {}

    rows = data.get("rows", [])
    
    # Count total injections
    ninjections = len(rows)
    
    # Process protection and commit charge information
    commit_charges = []
    protections = Counter()
    unique_injections = set()
    
    for row in rows:
        if len(row) > 4:
            protection = row[4] if row[4] else "Unknown"
            protections[protection] += 1
            
            # Add to unique injections set (combination of process, address, and protection)
            if len(row) > 3:
                unique_key = f"{row[1]}_{row[3]}_{protection}"
                unique_injections.add(unique_key)
        
        if len(row) > 5 and row[5]:
            try:
                commit_charge = int(row[5])
                commit_charges.append(commit_charge)
            except (ValueError, TypeError):
                pass
    
    # Calculate average commit charge
    avg_commit_charge = statistics.mean(commit_charges) if commit_charges else 0
    
    # Most common protection
    most_common_protection = protections.most_common(1)[0][0] if protections else "None"
    
    return {
        "malfind.ninjections": ninjections,
        "malfind.commitCharge": avg_commit_charge,
        "malfind.protection": most_common_protection,
        "malfind.uniqueInjections": len(unique_injections)
    }

def extract_psxview_features():
    """Extract features from the psxview plugin."""
    # Note: In Vol3, psxview is known as psscan and pstree
    # We'll need to combine data from multiple plugins
    
    # Get data from pslist (our baseline)
    pslist_data = run_volatility("windows.pslist")
    psscan_data = run_volatility("windows.psscan")
    sessions_data = run_volatility("windows.sessions")
    handles_data = run_volatility("windows.handles")
    
    if not pslist_data or not psscan_data:
        return {}
    
    # Extract PIDs from each source
    pslist_pids = set(row[1] for row in pslist_data.get("rows", []))
    psscan_pids = set(row[1] for row in psscan_data.get("rows", []))
    
    # Extract session information
    session_pids = set()
    for row in sessions_data.get("rows", []) if sessions_data else []:
        if len(row) > 1:
            session_pids.add(row[1])
    
    # Extract CSRSS handles information (processes referenced by csrss)
    csrss_pids = set()
    csrss_processes = [row[1] for row in pslist_data.get("rows", []) if "csrss.exe" in row[2].lower()]
    
    for row in handles_data.get("rows", []) if handles_data else []:
        if row[1] in csrss_processes and row[3].lower() == "process":
            # Try to extract PID from the process object details
            pid_match = re.search(r"PID (\d+)", row[5] if len(row) > 5 else "")
            if pid_match:
                csrss_pids.add(int(pid_match.group(1)))
    
    # For eprocess_pool, ethread_pool, pspcid_list, deskthrd we'll estimate with what we have
    # These require more direct memory access than Vol3 API provides
    
    # Calculate metrics
    all_pids = pslist_pids.union(psscan_pids).union(session_pids).union(csrss_pids)
    process_status = {}
    
    for pid in all_pids:
        process_status[pid] = {
            "in_pslist": pid in pslist_pids,
            "in_psscan": pid in psscan_pids,  # Approximation for eprocess_pool
            "in_ethread_pool": True,  # Cannot reliably determine, assume true
            "in_pspcid_list": True,  # Cannot reliably determine, assume true
            "in_csrss_handles": pid in csrss_pids,
            "in_session": pid in session_pids,
            "in_deskthrd": True  # Cannot reliably determine, assume true
        }
    
    # Count processes not in each list
    not_in_pslist = sum(1 for status in process_status.values() if not status["in_pslist"])
    not_in_eprocess_pool = sum(1 for status in process_status.values() if not status["in_psscan"])
    not_in_ethread_pool = sum(1 for status in process_status.values() if not status["in_ethread_pool"])
    not_in_pspcid_list = sum(1 for status in process_status.values() if not status["in_pspcid_list"])
    not_in_csrss_handles = sum(1 for status in process_status.values() if not status["in_csrss_handles"])
    not_in_session = sum(1 for status in process_status.values() if not status["in_session"])
    not_in_deskthrd = sum(1 for status in process_status.values() if not status["in_deskthrd"])
    
    # Calculate false positives per process (hidden processes)
    hidden_proc_values = []
    for pid, status in process_status.items():
        if not status["in_pslist"]:
            hidden_proc_values.append({
                "not_in_pslist": 1 if not status["in_pslist"] else 0,
                "not_in_eprocess_pool": 1 if not status["in_psscan"] else 0,
                "not_in_ethread_pool": 1 if not status["in_ethread_pool"] else 0,
                "not_in_pspcid_list": 1 if not status["in_pspcid_list"] else 0,
                "not_in_csrss_handles": 1 if not status["in_csrss_handles"] else 0,
                "not_in_session": 1 if not status["in_session"] else 0,
                "not_in_deskthrd": 1 if not status["in_deskthrd"] else 0
            })
    
    # Calculate averages for hidden processes
    if hidden_proc_values:
        not_in_pslist_false_avg = statistics.mean([p["not_in_pslist"] for p in hidden_proc_values])
        not_in_eprocess_pool_false_avg = statistics.mean([p["not_in_eprocess_pool"] for p in hidden_proc_values])
        not_in_ethread_pool_false_avg = statistics.mean([p["not_in_ethread_pool"] for p in hidden_proc_values])
        not_in_pspcid_list_false_avg = statistics.mean([p["not_in_pspcid_list"] for p in hidden_proc_values])
        not_in_csrss_handles_false_avg = statistics.mean([p["not_in_csrss_handles"] for p in hidden_proc_values])
        not_in_session_false_avg = statistics.mean([p["not_in_session"] for p in hidden_proc_values])
        not_in_deskthrd_false_avg = statistics.mean([p["not_in_deskthrd"] for p in hidden_proc_values])
    else:
        not_in_pslist_false_avg = 0
        not_in_eprocess_pool_false_avg = 0
        not_in_ethread_pool_false_avg = 0
        not_in_pspcid_list_false_avg = 0
        not_in_csrss_handles_false_avg = 0
        not_in_session_false_avg = 0
        not_in_deskthrd_false_avg = 0
    
    return {
        "psxview.not_in_pslist": not_in_pslist,
        "psxview.not_in_eprocess_pool": not_in_eprocess_pool,
        "psxview.not_in_ethread_pool": not_in_ethread_pool,
        "psxview.not_in_pspcid_list": not_in_pspcid_list,
        "psxview.not_in_csrss_handles": not_in_csrss_handles,
        "psxview.not_in_session": not_in_session,
        "psxview.not_in_deskthrd": not_in_deskthrd,
        "psxview.not_in_pslist_false_avg": not_in_pslist_false_avg,
        "psxview.not_in_eprocess_pool_false_avg": not_in_eprocess_pool_false_avg,
        "psxview.not_in_ethread_pool_false_avg": not_in_ethread_pool_false_avg,
        "psxview.not_in_pspcid_list_false_avg": not_in_pspcid_list_false_avg,
        "psxview.not_in_csrss_handles_false_avg": not_in_csrss_handles_false_avg,
        "psxview.not_in_session_false_avg": not_in_session_false_avg,
        "psxview.not_in_deskthrd_false_avg": not_in_deskthrd_false_avg
    }

def extract_modules_features():
    """Extract features from the modules plugin."""
    data = run_volatility("windows.modules")
    if not data:
        return {}
    
    rows = data.get("rows", [])
    
    # Count total modules
    nmodules = len(rows)
    
    return {
        "modules.nmodules": nmodules
    }

def extract_svcscan_features():
    """Extract features from the svcscan plugin."""
    data = run_volatility("windows.svcscan")
    if not data:
        return {}
    
    rows = data.get("rows", [])
    
    # Count total services
    nservices = len(rows)
    
    # Count by service type
    kernel_drivers = 0
    fs_drivers = 0
    process_services = 0
    shared_process_services = 0
    interactive_process_services = 0
    active_services = 0
    
    for row in rows:
        service_type = row[3].lower() if len(row) > 3 and row[3] else ""
        service_state = row[4].lower() if len(row) > 4 and row[4] else ""
        
        if "kernel" in service_type:
            kernel_drivers += 1
        if "file system" in service_type:
            fs_drivers += 1
        if "own process" in service_type:
            process_services += 1
        if "share process" in service_type:
            shared_process_services += 1
        if "interactive" in service_type:
            interactive_process_services += 1
        
        if "running" in service_state:
            active_services += 1
    
    return {
        "svcscan.nservices": nservices,
        "svcscan.kernel_drivers": kernel_drivers,
        "svcscan.fs_drivers": fs_drivers,
        "svcscan.process_services": process_services,
        "svcscan.shared_process_services": shared_process_services,
        "svcscan.interactive_process_services": interactive_process_services,
        "svcscan.nactive": active_services
    }

def extract_callbacks_features():
    """Extract features from the callbacks plugin."""
    data = run_volatility("windows.callbacks")
    if not data:
        return {}
    
    rows = data.get("rows", [])
    
    # Count total callbacks
    ncallbacks = len(rows)
    
    # Count by type
    nanonymous = 0
    ngeneric = 0
    
    for row in rows:
        callback_type = row[1].lower() if len(row) > 1 and row[1] else ""
        module = row[2].lower() if len(row) > 2 and row[2] else ""
        
        if not module or module == "unknown":
            nanonymous += 1
        if "generic" in callback_type:
            ngeneric += 1
    
    return {
        "callbacks.ncallbacks": ncallbacks,
        "callbacks.nanonymous": nanonymous,
        "callbacks.ngeneric": ngeneric
    }

def main():
    """Main function to extract all features and write to CSV."""
    # Extract all features
    features = {}
    
    print("Extracting pslist features...")
    features.update(extract_pslist_features())
    
    print("Extracting dlllist features...")
    features.update(extract_dlllist_features())
    
    print("Extracting handles features...")
    features.update(extract_handles_features())
    
    print("Extracting ldrmodules features...")
    features.update(extract_ldrmodules_features())
    
    print("Extracting malfind features...")
    features.update(extract_malfind_features())
    
    print("Extracting psxview features...")
    features.update(extract_psxview_features())
    
    print("Extracting modules features...")
    features.update(extract_modules_features())
    
    print("Extracting svcscan features...")
    features.update(extract_svcscan_features())
    
    print("Extracting callbacks features...")
    features.update(extract_callbacks_features())
    
    # Write features to CSV
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        fieldnames = sorted(features.keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerow(features)
    
    print(f"Features extracted successfully to {OUTPUT_FILE}")
    
    # Display summary of extracted features
    print("\nExtracted Features Summary:")
    for feature, value in sorted(features.items()):
        print(f"{feature}: {value}")

if __name__ == "__main__":
    main()
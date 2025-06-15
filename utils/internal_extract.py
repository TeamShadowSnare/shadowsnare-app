import argparse
import csv
# import functools
# import json
# import subprocess
# import tempfile
import os
# import io
import pandas as pd
import traceback

from volatility3.framework import contexts, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework import constants, automagic
from volatility3 import framework
from volatility3.cli import text_renderer
from volatility3.framework import constants

from volatility3.framework import contexts, exceptions
from volatility3.framework.automagic import stacker, linux, windows
from volatility3.framework.configuration import requirements

from volatility3.framework import contexts, interfaces, exceptions
from volatility3.framework import automagic, constants, plugins
from volatility3 import plugins as vol_plugins
from volatility3.cli import text_renderer
import urllib.request
import urllib.parse

from volatility3.plugins.windows import pslist, dlllist, handles, ldrmodules, malfind, modules, callbacks, svcscan, psxview



def extract_pslist_features(jsondump):
    try:
        # Handle both list of dicts and DataFrame input
        df = pd.DataFrame(jsondump)
        # print(f"[DEBUG] pslist DataFrame shape: {df.shape}")
        # print(f"[DEBUG] pslist columns: {df.columns.tolist()}")
        if not df.empty:
            print(f"[DEBUG] pslist first few rows:\n{df.head()}")
            
    except Exception as e:
        print(f"[ERROR] pslist: Could not create DataFrame: {e}")
        return {}

    features = {}
    
    if df.empty:
        print("[WARN] pslist: DataFrame is empty")
        return {
            'pslist.nproc': 0,
            'pslist.nppid': 0,
            'pslist.avg_threads': 0,
            'pslist.nprocs64bit': 0,
        }
    
    try:
        # Number of processes
        if 'PPID' in df.columns:
            features['pslist.nproc'] = len(df)
            # print(f"[DEBUG] pslist.nproc = {len(df)}")
        else:
            print("[WARN] pslist: PPID column not found, using row count")
            features['pslist.nproc'] = len(df)
            
    except Exception as e:
        print(f"[WARN] pslist.nproc: {e}")
        features['pslist.nproc'] = 0
        
    try:
        # Number of unique parent process IDs
        if 'PPID' in df.columns:
            features['pslist.nppid'] = df['PPID'].nunique()
        else:
            print("[WARN] pslist: PPID column not found")
            features['pslist.nppid'] = 0
    except Exception as e:
        print(f"[WARN] pslist.nppid: {e}")
        features['pslist.nppid'] = 0
        
    try:
        # Average number of threads
        if 'Threads' in df.columns:
            # print("printing df.Threads...")
            # print(df['Threads'])

            # print("[DEBUG] Threads column types:")
            # print(df['Threads'].apply(lambda x: type(x)).value_counts())
            # print("[DEBUG] Threads column sample:")
            # print(df['Threads'].head())

            # features['pslist.avg_threads'] = float(df['Threads'].mean())
            df['Threads'] = pd.to_numeric(df['Threads'], errors='coerce')
            features['pslist.avg_threads'] = float(df['Threads'].mean())

        else:
            print("[WARN] pslist: Threads column not found")
            features['pslist.avg_threads'] = 0
    except Exception as e:
        print(f"[WARN] pslist.avg_threads: {e}")
        features['pslist.avg_threads'] = 0
        
    try:
        # Number of 64-bit processes (check different possible column names and values)
        nprocs64bit = 0
        if 'Wow64' in df.columns:
            # Wow64 True means 32-bit process on 64-bit system, so False means 64-bit
            wow64_col = df['Wow64']
            if wow64_col.dtype == 'object':  # String column
                nprocs64bit = len(df[df['Wow64'].astype(str).str.lower() == 'false'])
            else:  # Boolean column
                nprocs64bit = len(df[df['Wow64'] == False])
        elif 'IsWow64' in df.columns:  # Alternative column name
            iswow64_col = df['IsWow64']
            if iswow64_col.dtype == 'object':  # String column
                nprocs64bit = len(df[df['IsWow64'].astype(str).str.lower() == 'false'])
            else:  # Boolean column
                nprocs64bit = len(df[df['IsWow64'] == False])
        else:
            print("[WARN] pslist: Neither Wow64 nor IsWow64 column found")
            
        features['pslist.nprocs64bit'] = nprocs64bit
    except Exception as e:
        print(f"[WARN] pslist.nprocs64bit: {e}")
        features['pslist.nprocs64bit'] = 0
        
    return features



def extract_dlllist_features(jsondump):
    df = pd.DataFrame(jsondump)
    try:
        a = df.PID.size                                           #Total Number of all loaded libraries
        # b = df.PID.unique().size                              #Number of Processes loading dlls
        c = df.PID.size/df.PID.unique().size             #Average loaded libraries per process
        # d = df.Size.sum()/df.PID.unique().size                  #Average Size of loaded libraries
        # e = df.PID.size - len(df[df["File output"]=="Disabled"]) #Number of loaded librearies outputting files
    except:
        a = None
        # b = None
        c = None
        # d = None
        # e = None
    return{
        'dlllist.ndlls': a,
        # 'dlllist.nproc_dll': b,#Not part of our dataset
        'dlllist.avg_dlls_per_proc': c,
        # 'dlllist.avgSize': d,#Not part of our dataset
        # 'dlllist.outfile': e#Not part of our dataset
    }


def extract_handles_features(jsondump):
    features = {}

    try:
        df = pd.DataFrame(jsondump)
    except Exception as e:
        print(f"[ERROR] Could not read JSON: {e}")
        return features

    try:
        features['handles.nhandles'] = len(df)
    except Exception as e:
        print(f"[WARN] handles.nhandles: {e}")
        features['handles.nhandles'] = None

    try:
        pid_col = 'PID' if 'PID' in df.columns else 'Pid' if 'Pid' in df.columns else None
        if pid_col:
            handle_counts = df.groupby(pid_col).size()
            features['pslist.avg_handlers'] = handle_counts.mean()
        else:
            print("[WARN] No PID column found for avg_handles_per_proc calculation.")
            features['pslist.avg_handlers'] = None
    except Exception as e:
        print(f"[WARN] handles.avg_handles_per_proc: {e}")
        features['pslist.avg_handlers'] = None

    type_keys = [
        ('handles.nport', 'Port'),
        ('handles.nfile', 'File'),
        ('handles.nevent', 'Event'),
        ('handles.ndesktop', 'Desktop'),
        ('handles.nkey', 'Key'),
        ('handles.nthread', 'Thread'),
        ('handles.ndirectory', 'Directory'),
        ('handles.nsemaphore', 'Semaphore'),
        ('handles.ntimer', 'Timer'),
        ('handles.nsection', 'Section'),
        ('handles.nmutant', 'Mutant'),
    ]

    for feat_name, handle_type in type_keys:
        try:
            if 'Type' in df.columns:
                features[feat_name] = (df['Type'] == handle_type).sum()
            else:
                print(f"[WARN] {feat_name}: 'Type' column missing.")
                features[feat_name] = None
        except Exception as e:
            print(f"[WARN] {feat_name}: {e}")
            features[feat_name] = None

    return features





def extract_ldrmodules_features(jsondump):
    try:
        df = pd.DataFrame(jsondump)
        # print(f"[DEBUG] ldrmodules DataFrame shape: {df.shape}")
        # print(f"[DEBUG] ldrmodules columns: {df.columns.tolist()}")
        if not df.empty:
            print(f"[DEBUG] ldrmodules first few rows:\n{df.head()}")
    except Exception as e:
        print(f"[ERROR] ldrmodules: Could not create DataFrame: {e}")
        return {}
    
    features = {}
    
    if df.empty:
        print("[WARN] ldrmodules: DataFrame is empty")
        return {
            'ldrmodules.not_in_load': 0,
            'ldrmodules.not_in_init': 0,
            'ldrmodules.not_in_mem': 0,
            'ldrmodules.not_in_load_avg': 0,
            'ldrmodules.not_in_init_avg': 0,
            'ldrmodules.not_in_mem_avg': 0,
        }
    
    try:
        # Check what the actual column names are and handle boolean values properly
        total_modules = len(df)
        
        # Handle InLoad column
        if 'InLoad' in df.columns:
            # Convert string 'False'/'True' to boolean if needed
            inload_col = df['InLoad']
            if inload_col.dtype == 'object':  # String column
                not_in_load = len(df[df['InLoad'].astype(str).str.lower() == 'false'])
            else:  # Already boolean
                not_in_load = len(df[df['InLoad'] == False])
            features['ldrmodules.not_in_load'] = not_in_load
            features['ldrmodules.not_in_load_avg'] = not_in_load / total_modules if total_modules > 0 else 0
        else:
            print("[WARN] ldrmodules: InLoad column not found")
            features['ldrmodules.not_in_load'] = 0
            features['ldrmodules.not_in_load_avg'] = 0
            
        # Handle InInit column
        if 'InInit' in df.columns:
            inint_col = df['InInit']
            if inint_col.dtype == 'object':  # String column
                not_in_init = len(df[df['InInit'].astype(str).str.lower() == 'false'])
            else:  # Already boolean
                not_in_init = len(df[df['InInit'] == False])
            features['ldrmodules.not_in_init'] = not_in_init
            features['ldrmodules.not_in_init_avg'] = not_in_init / total_modules if total_modules > 0 else 0
        else:
            print("[WARN] ldrmodules: InInit column not found")
            features['ldrmodules.not_in_init'] = 0
            features['ldrmodules.not_in_init_avg'] = 0
            
        # Handle InMem column
        if 'InMem' in df.columns:
            inmem_col = df['InMem']
            if inmem_col.dtype == 'object':  # String column
                not_in_mem = len(df[df['InMem'].astype(str).str.lower() == 'false'])
            else:  # Already boolean
                not_in_mem = len(df[df['InMem'] == False])
            features['ldrmodules.not_in_mem'] = not_in_mem
            features['ldrmodules.not_in_mem_avg'] = not_in_mem / total_modules if total_modules > 0 else 0
        else:
            print("[WARN] ldrmodules: InMem column not found")
            features['ldrmodules.not_in_mem'] = 0
            features['ldrmodules.not_in_mem_avg'] = 0
            
    except Exception as e:
        print(f"[ERROR] ldrmodules feature extraction failed: {e}")
        features.update({
            'ldrmodules.not_in_load': 0,
            'ldrmodules.not_in_init': 0,
            'ldrmodules.not_in_mem': 0,
            'ldrmodules.not_in_load_avg': 0,
            'ldrmodules.not_in_init_avg': 0,
            'ldrmodules.not_in_mem_avg': 0,
        })
    
    return features

def extract_malfind_features(jsondump):
    df = pd.DataFrame(jsondump)
    # print("[DEBUG]: printing dataframe's CommitCharge: ")
    # print(df.CommitCharge)
    df['CommitCharge'] = pd.to_numeric(df['CommitCharge'], errors='coerce')
    # print("[DEBUG] CommitCharge summary stats:")
    # print(df['CommitCharge'].describe())
    # print("[DEBUG] Top CommitCharge values:")
    # print(df['CommitCharge'].sort_values(ascending=False).head())
    # print("[DEBUG] I need to pick one from: ")
    # print(f"df.CommitCharge.sum() = {df['CommitCharge'].sum()}, df.CommitCharge.mean() = {df['CommitCharge'].mean()}, and df.CommitCharge.max()={df['CommitCharge'].max()}")


    return {                                                                        
        'malfind.ninjections': df['CommitCharge'].size,                              #Number of hidden code injections found by malfind
        # 'malfind.commitCharge': df.CommitCharge.sum(),                            #Sum of Commit Charges over time                                
        'malfind.commitCharge': df['CommitCharge'].sum(),                            #Sum of Commit Charges over time  
        'malfind.protection': len(df[df["Protection"]=="PAGE_EXECUTE_READWRITE"]),#Number of injections with all permissions 
        'malfind.uniqueInjections': df.PID.unique().size,                         #Number of unique injections
        # 'malfind.avgInjec_per_proc': df.PID.size/df.PID.unique().size,            #Average number of injections per process
        # 'malfind.tagsVad': len(df[df["Tag"]=="Vad"]),                             #Number of Injections tagged as Vad
        # 'malfind.tagsVads': len(df[df["Tag"]=="Vads"]),                           #Number of Injections tagged as Vads
        # 'malfind.aveVPN_diff': df['End VPN'].sub(df['Start VPN']).sum()           #Avg VPN size of injections
    }

def extract_modules_features(jsondump):
    df = pd.DataFrame(jsondump)
    return {
        'modules.nmodules': df.Base.size,                                          #Number of Modules
        # 'modules.avgSize': df.Size.mean(),                             #Average size of the modules
        # 'modules.FO_enabled': df.Base.size - len(df[df["File output"]=='Disabled'])#Number of Output enabled File Output
    }
def extract_callbacks_features(jsondump):
    df = pd.DataFrame(jsondump)
    features = {}

    # Total callbacks
    try:
        features['callbacks.ncallbacks'] = len(df)
    except Exception as e:
        print(f"[WARN] Failed to compute callbacks.ncallbacks: {e}")

    # Anonymous callbacks
    try:
        features['callbacks.nanonymous'] = (df['Module'] == 'UNKNOWN').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute callbacks.nanonymous: {e}")

    # Generic callbacks
    try:
        features['callbacks.ngeneric'] = (df['Type'] == 'GenericKernelCallback').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute callbacks.ngeneric: {e}")

    return features


def extract_svcscan_features(jsondata):
    try:
        df = pd.DataFrame(jsondata)
    except Exception as e:
        print(f"[ERROR] svcscan: Could not create DataFrame: {e}")
        return {}

    features = {}
    try:
        features['svcscan.nservices'] = len(df)
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.nservices: {e}")

    try:
        features['svcscan.kernel_drivers'] = (df['Type'] == 'SERVICE_KERNEL_DRIVER').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.kernel_drivers: {e}")

    try:
        features['svcscan.fs_drivers'] = (df['Type'] == 'SERVICE_FILE_SYSTEM_DRIVER').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.fs_drivers: {e}")

    try:
        features['svcscan.process_services'] = (df['Type'] == 'SERVICE_WIN32_OWN_PROCESS').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.process_services: {e}")

    try:
        features['svcscan.shared_process_services'] = (df['Type'] == 'SERVICE_WIN32_SHARE_PROCESS').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.shared_process_services: {e}")

    try:
        features['svcscan.interactive_process_services'] = (df['Type'].str.contains('INTERACTIVE_PROCESS', na=False)).sum()
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.interactive_process_services: {e}")

    try:
        features['svcscan.nactive'] = (df['State'] == 'SERVICE_RUNNING').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute svcscan.nactive: {e}")

    return features

# def extract_psxview_features(jsondump):
#     psxview = json.load(jsondump)

#     # Auto-diagnostic for missing expected keys
#     expected_keys = ['pslist', 'psscan', 'csrss', 'pspcid', 'session', 'deskthrd', 'thrdproc']
#     for k in expected_keys:
#         missing = [p for p in psxview if k not in p or p[k] is None]
#         if missing:
#             print(f"[INFO] Missing key: {k} in {len(missing)} / {len(psxview)} entries")

#     def count_false(key):
#         return sum(1 for p in psxview if str(p.get(key, True)) == 'False')

#     total = len(psxview) if psxview else 1  # prevent division by zero

#     return {
#         'psxview.not_in_pslist': count_false('pslist'),
#         'psxview.not_in_eprocess_pool': count_false('psscan'),
#         'psxview.not_in_ethread_pool': count_false('thrdproc'),
#         'psxview.not_in_pspcid_list': count_false('pspcid'),
#         'psxview.not_in_csrss_handles': count_false('csrss'),
#         'psxview.not_in_session': count_false('session'),
#         'psxview.not_in_deskthrd': count_false('deskthrd'),

#         'psxview.not_in_pslist_false_avg': count_false('pslist') / total,
#         'psxview.not_in_eprocess_pool_false_avg': count_false('psscan') / total,
#         'psxview.not_in_ethread_pool_false_avg': count_false('thrdproc') / total,
#         'psxview.not_in_pspcid_list_false_avg': count_false('pspcid') / total,
#         'psxview.not_in_csrss_handles_false_avg': count_false('csrss') / total,
#         'psxview.not_in_session_false_avg': count_false('session') / total,
#         'psxview.not_in_deskthrd_false_avg': count_false('deskthrd') / total,
#     }
def get_available_psxview_features(psxview):
    keys_present = set()
    for entry in psxview:
        keys_present.update(entry.keys())
    # Remove non-boolean columns if necessary (like PID or name)
    keys_present.discard('PID')  # or 'pid', 'offset', etc., depending on your data
    return sorted(keys_present)

def extract_psxview_features(psxview):
    #print(get_available_psxview_features(psxview=psxview))
    total = len(psxview) if psxview else 1  # prevent division by zero

    def count_false(key):
        return sum(1 for p in psxview if str(p.get(key, True)) == 'False')

    return {
        'psxview.not_in_pslist': count_false('pslist'),
        'psxview.not_in_eprocess_pool': count_false('psscan'),
        'psxview.not_in_csrss_handles': count_false('csrss'),

        'psxview.not_in_pslist_false_avg': count_false('pslist') / total,
        'psxview.not_in_eprocess_pool_false_avg': count_false('psscan') / total,
        'psxview.not_in_csrss_handles_false_avg': count_false('csrss') / total,
    }




VOL_MODULES = {
    'pslist.PsList': extract_pslist_features,
    'dlllist.DllList': extract_dlllist_features,
    'handles.Handles': extract_handles_features,
    'ldrmodules.LdrModules': extract_ldrmodules_features,
    'malfind.Malfind': extract_malfind_features,
    'modules.Modules': extract_modules_features,
    'callbacks.Callbacks': extract_callbacks_features,
    'svcscan.SvcScan': extract_svcscan_features,
    'psxview.PsXView':extract_psxview_features
}

def invoke_volatility3(memdump_path, full_module_name):    
    # Create a proper FileHandler class that implements all required methods
    class LocalFileHandler(interfaces.plugins.FileHandlerInterface):
        """File handler for local files"""
        
        def open(self, request):
            """Open a file based on the request"""
            if isinstance(request, str):
                # Handle file:// URLs
                if request.startswith('file://'):
                    file_path = urllib.parse.urlparse(request).path
                    # On Windows, remove the leading slash from paths like /C:/path
                    if file_path.startswith('/') and len(file_path) > 1 and file_path[2] == ':':
                        file_path = file_path[1:]
                    return open(file_path, 'rb')
                elif request.startswith('file:'):
                    file_path = request[5:]  # Remove 'file:' prefix
                    return open(file_path, 'rb')
                else:
                    return open(request, 'rb')
            return open(request, 'rb')
            
        def close(self, file_handle):
            """Close a file handle"""
            if file_handle and hasattr(file_handle, 'close'):
                file_handle.close()

    # Split full module name
    module_name, plugin_class_name = full_module_name.split(".")

    plugin_path = f"windows.{full_module_name}"
    ctx = contexts.Context()
    base_config_path = "plugins"

    # Get available automagics
    automagics_list = automagic.available(ctx)

    # Load plugin class - using vol_plugins instead of framework
    plugin_list = framework.list_plugins()
    plugin_class = plugin_list.get(plugin_path)
    if plugin_class is None:
        raise ValueError(f"Plugin {plugin_path} not found")

    # Set memory layer + location
    ctx.config[base_config_path + "." + plugin_class.__name__ + ".primary"] = "memory_layer"
    ctx.config["automagic.LayerStacker.single_location"] = f"file:{memdump_path}"

    # Run automagics to build memory layer
    try:
        constructed = plugins.construct_plugin(
            ctx,
            automagics_list,
            plugin_class,
            base_config_path,
            open_method=LocalFileHandler,  # Pass the class, not an instance
            progress_callback=None
        )
    except exceptions.UnsatisfiedException as e:
        print("❌ Failed to satisfy plugin requirements:")
        for req in e.unsatisfied:
            print(f" - {req}")
        raise

    # Run plugin
    renderable = constructed.run()

    # Convert TreeGrid to list of dicts
    columns = renderable.columns
    output_data = []
    
    # Use the visitor pattern to iterate through TreeGrid
    def visitor(node, accumulator):
        # Get the row data from the node
        row_data = {}
        for i, col in enumerate(columns):
            try:
                value = node.values[i] if i < len(node.values) else None
                row_data[col.name] = str(value) if value is not None else ""
            except (IndexError, AttributeError):
                row_data[col.name] = ""
        accumulator.append(row_data)
        return accumulator
    
    # Apply visitor to all nodes in the TreeGrid
    renderable.visit(node=None, function=visitor, initial_accumulator=output_data)
    # print(plugin_list)
    return output_data



def write_dict_to_csv(filename, dictionary):
    fieldnames = list(dictionary.keys())
    file_exists = os.path.isfile(filename)

    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(dictionary)


#def extract_all_features_from_memdump(memdump_path, output_path):
def extract_all_features_from_memdump(memdump_path, output_path, progress_callback=None):
    features = {}
    print(f'=> Extracting features from {memdump_path}')
    print(f'=> Outputting to {output_path}')

    def emit_progress(message):
        if progress_callback:
            if hasattr(progress_callback, "emit"):
                progress_callback.emit(message)
            else:
                progress_callback(message)

    for module, extractor in VOL_MODULES.items():
        emit_progress(f"🧩 Running plugin: {module}...")
        try:
            json_output = invoke_volatility3(memdump_path, module)
            features.update(extractor(json_output))
            emit_progress(f"✅ Finished plugin: {module}")
        except Exception as e:
            msg = f"❌ Error running {module}: {e}"
            print(msg)
            emit_progress(msg)
            traceback.print_exc()

    features["mem.name_extn"] = os.path.basename(memdump_path)
    output_csv_path = os.path.join(output_path, "output.csv")
    write_dict_to_csv(output_csv_path, features)

    print("✅ All done.")
    return output_csv_path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--memdump", required=True, help="Path to a single memory dump file (.raw/.vmem/.mem)"
    )
    parser.add_argument(
        "-o", "--output", required=True, help="Output directory for CSV"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if not os.path.isfile(args.memdump):
        print(f"❌ Memory dump file does not exist: {args.memdump}")
        exit(1)

    if not os.path.isdir(args.output):
        os.makedirs(args.output)

    extract_all_features_from_memdump(args.memdump, args.output)
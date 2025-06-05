import argparse
import csv
import functools
import json
import subprocess
import tempfile
import os
import io
import pandas as pd

from volatility3.framework import contexts, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework import constants, automagic
from volatility3 import framework
from volatility3.cli import text_renderer

from volatility3.framework import contexts, exceptions
from volatility3.framework.automagic import stacker, linux, windows
from volatility3.framework import interfaces, layers
from volatility3.framework.configuration import requirements
from volatility3.cli import text_renderer

from volatility3.plugins.windows import pslist, dlllist, handles, ldrmodules, malfind, modules, callbacks, svcscan


# Extractor functions extracts features from the Volatility

def extract_winInfo_features(jsondump):
    df = pd.DataFrame(jsondump)
    try:
        a = bool(json.loads(df.loc[3].at["Value"].lower()))           #Is Windows a 64 Version 
        b = df.loc[8].at["Value"]                                 #Version of Windows Build
        c = int(df.loc[11].at["Value"])                               #Number of Processors
        d = bool(json.loads(df.loc[4].at["Value"].lower()))          #Is Windows Physical Address Extension (PAE) is a processor feature that enables x86 processors to access more than 4 GB of physical memory
    except:
        a = None
        b = None
        c = None
        d = None
    return{
        'info.Is64': a,
        'info.winBuild': b,
        'info.npro': c,
        'info.IsPAE': d
    }
def extract_pslist_features(jsondump):
    df = pd.DataFrame(jsondump)
    features = {}

    try:
        print("nproc = ",df.PPID.size)
        features['pslist.nproc'] = df.PPID.size
    except Exception as e:
        print(f"[WARN] pslist.nproc: {e}")

    try:
        features['pslist.nppid'] = df.PPID.nunique()
    except Exception as e:
        print(f"[WARN] pslist.nppid: {e}")

    try:
        features['pslist.avg_threads'] = df.Threads.mean()
    except Exception as e:
        print(f"[WARN] pslist.avg_threads: {e}")

    # try:
    #     print("DFBUGGING: Printing df.Handles...")
    #     print(df.Handles)
    #     features['pslist.avg_handlers'] = df.Handles.mean()
    # except Exception as e:
    #     print(f"[WARN] pslist.avg_handlers: {e}")

    try:
        features['pslist.nprocs64bit'] = len(df[df["Wow64"] == "True"])
    except Exception as e:
        print(f"[WARN] pslist.nprocs64bit: {e}")

    # Optional: Commented because not in your dataset
    # try:
    #     features['pslist.outfile'] = df.PPID.size - len(df[df["File output"] == "Disabled"])
    # except Exception as e:
    #     print(f"[WARN] pslist.outfile: {e}")

    return features



def extract_dlllist_features(jsondump):
    df = pd.DataFrame(jsondump)
    try:
        a = df.PID.size                                           #Total Number of all loaded libraries
        b = df.PID.unique().size                              #Number of Processes loading dlls
        c = df.PID.size/df.PID.unique().size             #Average loaded libraries per process
        d = df.Size.sum()/df.PID.unique().size                  #Average Size of loaded libraries
        e = df.PID.size - len(df[df["File output"]=="Disabled"]) #Number of loaded librearies outputting files
    except:
        a = None
        b = None
        c = None
        d = None
        e = None
    return{
        'dlllist.ndlls': a,
        # 'dlllist.nproc_dll': b,#Not part of our dataset
        'dlllist.avg_dllPerProc': c,
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
            print("[WARN] No PID column found for avg_handlers calculation.")
            features['pslist.avg_handlers'] = None
    except Exception as e:
        print(f"[WARN] pslist.avg_handlers: {e}")
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
    df = pd.DataFrame(jsondump)
    return {
        # 'ldrmodules.total': df.Base.size,                                       #Number of total modules
        'ldrmodules.not_in_load': len(df[df["InLoad"]==False]),                 #Number of modules missing from load list
        'ldrmodules.not_in_init': len(df[df["InInit"]==False]),                 #Number of modules missing from init list
        'ldrmodules.not_in_mem': len(df[df["InMem"]==False]),                   #Number of modules missing from mem list
	# 'ldrmodules.nporc': df.Pid.unique().size,                               #Number of processes with modules in memory
        'ldrmodules.not_in_load_avg': len(df[df["InLoad"]==False])/df.Base.size,#Avg number of modules missing from load list
        'ldrmodules.not_in_init_avg': len(df[df["InInit"]==False])/df.Base.size,#Avg number of modules missing from init list
        'ldrmodules.not_in_mem_avg': len(df[df["InMem"]==False])/df.Base.size,  #Avg number of modules missing from mem list
    }

def extract_malfind_features(jsondump):
    df = pd.DataFrame(jsondump)
    return {                                                                        
        'malfind.ninjections': df.CommitCharge.size,                              #Number of hidden code injections found by malfind
	'malfind.commitCharge': df.CommitCharge.sum(),                            #Sum of Commit Charges over time                                
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


#     return features
def extract_psxview_features(jsondump):
    psxview = json.load(jsondump)

    # Auto-diagnostic for missing expected keys
    expected_keys = ['pslist', 'psscan', 'csrss', 'pspcid', 'session', 'deskthrd', 'thrdproc']
    for k in expected_keys:
        missing = [p for p in psxview if k not in p or p[k] is None]
        if missing:
            print(f"[INFO] Missing key: {k} in {len(missing)} / {len(psxview)} entries")

    def count_false(key):
        return sum(1 for p in psxview if str(p.get(key, True)) == 'False')

    total = len(psxview) if psxview else 1  # prevent division by zero

    return {
        'psxview.not_in_pslist': count_false('pslist'),
        'psxview.not_in_eprocess_pool': count_false('psscan'),
        'psxview.not_in_ethread_pool': count_false('thrdproc'),
        'psxview.not_in_pspcid_list': count_false('pspcid'),
        'psxview.not_in_csrss_handles': count_false('csrss'),
        'psxview.not_in_session': count_false('session'),
        'psxview.not_in_deskthrd': count_false('deskthrd'),

        'psxview.not_in_pslist_false_avg': count_false('pslist') / total,
        'psxview.not_in_eprocess_pool_false_avg': count_false('psscan') / total,
        'psxview.not_in_ethread_pool_false_avg': count_false('thrdproc') / total,
        'psxview.not_in_pspcid_list_false_avg': count_false('pspcid') / total,
        'psxview.not_in_csrss_handles_false_avg': count_false('csrss') / total,
        'psxview.not_in_session_false_avg': count_false('session') / total,
        'psxview.not_in_deskthrd_false_avg': count_false('deskthrd') / total,
    }



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


VOL_MODULES = {
    # 'pslist': extract_pslist_features,
    # 'dlllist': extract_dlllist_features,
    # 'handles': extract_handles_features,
    # 'ldrmodules': extract_ldrmodules_features,
    # 'malfind': extract_malfind_features,
    # 'modules': extract_modules_features,
    # 'callbacks': extract_callbacks_features,
    'svcscan': extract_svcscan_features,
    # 'psxview.PsXView':extract_psxview_features
}


def invoke_volatility3(memdump_path, module):
    ctx = contexts.ContextInterface()
    base_config_path = "automagic"
    progress = interfaces.renderers.ProgressRenderer()

    automagics = automagic.available(ctx)
    plugin_list = framework.plugins.list_plugins()
    plugin = plugin_list.get("windows." + module, None)

    if plugin is None:
        raise ValueError(f"Plugin windows.{module} not found")

    constructed = framework.plugins.construct_plugin(ctx, automagics, plugin, base_config_path, progress, memory_file=memdump_path)
    renderable = constructed.run()

    # The renderable is a TreeGrid, convert it to a list of dicts
    columns = renderable.columns
    output_data = []

    for row in renderable:
        flat_row = {}
        for i, col in enumerate(columns):
            flat_row[col.name] = str(row[i]) if row[i] is not None else ""
        output_data.append(flat_row)

    return output_data



def write_dict_to_csv(filename, dictionary):
    fieldnames = list(dictionary.keys())
    file_exists = os.path.isfile(filename)

    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(dictionary)


def extract_all_features_from_memdump(memdump_path, output_path):
    features = {}
    print(f'=> Extracting features from {memdump_path}')
    print(f'=> Outputting to {output_path}')

    for module, extractor in VOL_MODULES.items():
        print(f"=> Running Volatility module: {module}")
        try:
            json_output = invoke_volatility3(memdump_path, module)
            features.update(extractor(json_output))
        except Exception as e:
            print(f"[ERROR] {module} failed: {e}")

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
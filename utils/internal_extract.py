"""
Volatility3-based feature extraction utilities.

Provides per-plugin extractors that turn raw plugin JSON/rows into a flat
feature dictionary, a runner that invokes Volatility3 plugins on a memory dump,
and a pipeline that aggregates all features and writes them to CSV.
"""

import argparse
import csv
import os
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
    """Compute pslist-derived features from plugin output.

    Parameters
    ----------
    jsondump : list[dict]
        Rows produced by the Volatility3 `pslist` plugin.

    Returns
    -------
    dict
        Keys: pslist.nproc, pslist.nppid, pslist.avg_threads, pslist.nprocs64bit.
    """
    try:
        df = pd.DataFrame(jsondump)
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
        if 'PPID' in df.columns:
            features['pslist.nproc'] = len(df)
        else:
            print("[WARN] pslist: PPID column not found, using row count")
            features['pslist.nproc'] = len(df)
            
    except Exception as e:
        print(f"[WARN] pslist.nproc: {e}")
        features['pslist.nproc'] = 0
        
    try:
        if 'PPID' in df.columns:
            features['pslist.nppid'] = df['PPID'].nunique()
        else:
            print("[WARN] pslist: PPID column not found")
            features['pslist.nppid'] = 0
    except Exception as e:
        print(f"[WARN] pslist.nppid: {e}")
        features['pslist.nppid'] = 0
        
    try:
        if 'Threads' in df.columns:
            df['Threads'] = pd.to_numeric(df['Threads'], errors='coerce')
            features['pslist.avg_threads'] = float(df['Threads'].mean())

        else:
            print("[WARN] pslist: Threads column not found")
            features['pslist.avg_threads'] = 0
    except Exception as e:
        print(f"[WARN] pslist.avg_threads: {e}")
        features['pslist.avg_threads'] = 0
        
    try:
        nprocs64bit = 0
        if 'Wow64' in df.columns:
            wow64_col = df['Wow64']
            if wow64_col.dtype == 'object':
                nprocs64bit = len(df[df['Wow64'].astype(str).str.lower() == 'false'])
            else:
                nprocs64bit = len(df[df['Wow64'] == False])
        elif 'IsWow64' in df.columns:
            iswow64_col = df['IsWow64']
            if iswow64_col.dtype == 'object':
                nprocs64bit = len(df[df['IsWow64'].astype(str).str.lower() == 'false'])
            else:
                nprocs64bit = len(df[df['IsWow64'] == False])
        else:
            print("[WARN] pslist: Neither Wow64 nor IsWow64 column found")
            
        features['pslist.nprocs64bit'] = nprocs64bit
    except Exception as e:
        print(f"[WARN] pslist.nprocs64bit: {e}")
        features['pslist.nprocs64bit'] = 0
        
    return features



def extract_dlllist_features(jsondump):
    """Compute dlllist-derived features.

    Parameters
    ----------
    jsondump : list[dict]
        Rows from Volatility3 `dlllist`.

    Returns
    -------
    dict
        dlllist.ndlls, dlllist.avg_dlls_per_proc.
    """
    df = pd.DataFrame(jsondump)
    try:
        a = df.PID.size
        b = df.PID.size/df.PID.unique().size
    except:
        a = None
        b = None
    return{
        'dlllist.ndlls': a,
        'dlllist.avg_dlls_per_proc': b
    }


def extract_handles_features(jsondump):
    """Compute handle-related features including per-type counts.

    Parameters
    ----------
    jsondump : list[dict]
        Rows from Volatility3 `handles`.

    Returns
    -------
    dict
        Various `handles.*` counts and `pslist.avg_handlers`.
    """
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
    """Compute features from ldrmodules plugin output.

    Parameters
    ----------
    jsondump : list[dict]
        Rows from Volatility3 `ldrmodules`.

    Returns
    -------
    dict
        Counts and ratios for modules not in {Load, Init, Mem}.
    """
    try:
        df = pd.DataFrame(jsondump)
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
        total_modules = len(df)
        if 'InLoad' in df.columns:
            inload_col = df['InLoad']
            if inload_col.dtype == 'object':
                not_in_load = len(df[df['InLoad'].astype(str).str.lower() == 'false'])
            else:
                not_in_load = len(df[df['InLoad'] == False])
            features['ldrmodules.not_in_load'] = not_in_load
            features['ldrmodules.not_in_load_avg'] = not_in_load / total_modules if total_modules > 0 else 0
        else:
            print("[WARN] ldrmodules: InLoad column not found")
            features['ldrmodules.not_in_load'] = 0
            features['ldrmodules.not_in_load_avg'] = 0

        if 'InInit' in df.columns:
            inint_col = df['InInit']
            if inint_col.dtype == 'object':
                not_in_init = len(df[df['InInit'].astype(str).str.lower() == 'false'])
            else:
                not_in_init = len(df[df['InInit'] == False])
            features['ldrmodules.not_in_init'] = not_in_init
            features['ldrmodules.not_in_init_avg'] = not_in_init / total_modules if total_modules > 0 else 0
        else:
            print("[WARN] ldrmodules: InInit column not found")
            features['ldrmodules.not_in_init'] = 0
            features['ldrmodules.not_in_init_avg'] = 0
            
        if 'InMem' in df.columns:
            inmem_col = df['InMem']
            if inmem_col.dtype == 'object':
                not_in_mem = len(df[df['InMem'].astype(str).str.lower() == 'false'])
            else:
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
    """Compute malfind-derived features (injections, protections, charge, unique PIDs).

    Parameters
    ----------
    jsondump : list[dict]
        Rows from Volatility3 `malfind`.

    Returns
    -------
    dict
        malfind.ninjections, malfind.commitCharge, malfind.protection, malfind.uniqueInjections.
    """
    df = pd.DataFrame(jsondump)
    df['CommitCharge'] = pd.to_numeric(df['CommitCharge'], errors='coerce')

    return {                                                                        
        'malfind.ninjections': df['CommitCharge'].size,
        'malfind.commitCharge': df['CommitCharge'].sum(),
        'malfind.protection': len(df[df["Protection"]=="PAGE_EXECUTE_READWRITE"]),
        'malfind.uniqueInjections': df.PID.unique().size,
    }

def extract_modules_features(jsondump):
    """Compute simple module count from `modules` plugin output.

    Parameters
    ----------
    jsondump : list[dict]
        Rows from Volatility3 `modules`.

    Returns
    -------
    dict
        modules.nmodules count.
    """
    df = pd.DataFrame(jsondump)
    return {
        'modules.nmodules': df.Base.size
    }

def extract_callbacks_features(jsondump):
    """Compute callbacks plugin features (counts, anonymous, generic types).

    Parameters
    ----------
    jsondump : list[dict]
        Rows from Volatility3 `callbacks`.

    Returns
    -------
    dict
        callbacks.ncallbacks, callbacks.nanonymous, callbacks.ngeneric.
    """
    df = pd.DataFrame(jsondump)
    features = {}
    try:
        features['callbacks.ncallbacks'] = len(df)
    except Exception as e:
        print(f"[WARN] Failed to compute callbacks.ncallbacks: {e}")
    try:
        features['callbacks.nanonymous'] = (df['Module'] == 'UNKNOWN').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute callbacks.nanonymous: {e}")
    try:
        features['callbacks.ngeneric'] = (df['Type'] == 'GenericKernelCallback').sum()
    except Exception as e:
        print(f"[WARN] Failed to compute callbacks.ngeneric: {e}")

    return features


def extract_svcscan_features(jsondata):
    """Compute service scan features (by type/state).

    Parameters
    ----------
    jsondata : list[dict]
        Rows from Volatility3 `svcscan`.

    Returns
    -------
    dict
        Counts for service types and running state.
    """
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


def get_available_psxview_features(psxview):
    """Return the set of available psxview keys (excluding PID), sorted.

    Parameters
    ----------
    psxview : list[dict]
        Rows from Volatility3 `psxview`.

    Returns
    -------
    list[str]
        Sorted list of keys present (without 'PID').
    """
    keys_present = set()
    for entry in psxview:
        keys_present.update(entry.keys())
    
    keys_present.discard('PID')
    return sorted(keys_present)

def extract_psxview_features(psxview):
    """Compute psxview 'not in X' counts and normalized ratios.

    Parameters
    ----------
    psxview : list[dict]
        Rows from Volatility3 `psxview`.

    Returns
    -------
    dict
        Counts and averages for pslist/psscan/csrss checks.
    """
    total = len(psxview) if psxview else 1

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
    """Run a specific Volatility3 plugin on a memory dump and return rows.

    Parameters
    ----------
    memdump_path : str
        Path to the memory dump file.
    full_module_name : str
        e.g., "pslist.PsList", "dlllist.DllList" (Windows plugins).

    Returns
    -------
    list[dict]
        Rows rendered from the plugin's `renderable`, as string-valued dicts.

    Raises
    ------
    ValueError
        If the requested plugin cannot be found.
    exceptions.UnsatisfiedException
        If automagic requirements cannot be satisfied.
    """
    class LocalFileHandler(interfaces.plugins.FileHandlerInterface):
        """Minimal file handler for accessing local files with file:// support."""
        
        def open(self, request):
            """Open and return a readable file handle for the given request string/path."""
            if isinstance(request, str):
                if request.startswith('file://'):
                    file_path = urllib.parse.urlparse(request).path
                    if file_path.startswith('/') and len(file_path) > 1 and file_path[2] == ':':
                        file_path = file_path[1:]
                    return open(file_path, 'rb')
                elif request.startswith('file:'):
                    file_path = request[5:]
                    return open(file_path, 'rb')
                else:
                    return open(request, 'rb')
            return open(request, 'rb')
            
        def close(self, file_handle):
            """Close a file handle if it supports `close()`."""
            if file_handle and hasattr(file_handle, 'close'):
                file_handle.close()

    module_name, plugin_class_name = full_module_name.split(".")

    plugin_path = f"windows.{full_module_name}"
    ctx = contexts.Context()
    base_config_path = "plugins"

    automagics_list = automagic.available(ctx)

    plugin_list = framework.list_plugins()
    plugin_class = plugin_list.get(plugin_path)
    if plugin_class is None:
        raise ValueError(f"Plugin {plugin_path} not found")

    ctx.config[base_config_path + "." + plugin_class.__name__ + ".primary"] = "memory_layer"
    ctx.config["automagic.LayerStacker.single_location"] = f"file:{memdump_path}"

    try:
        constructed = plugins.construct_plugin(
            ctx,
            automagics_list,
            plugin_class,
            base_config_path,
            open_method=LocalFileHandler,
            progress_callback=None
        )
    except exceptions.UnsatisfiedException as e:
        print("❌ Failed to satisfy plugin requirements:")
        for req in e.unsatisfied:
            print(f" - {req}")
        raise

    renderable = constructed.run()

    columns = renderable.columns
    output_data = []
    
    def visitor(node, accumulator):
        """Visitor callback used by renderable.visit to collect rows into dicts."""
        row_data = {}
        for i, col in enumerate(columns):
            try:
                value = node.values[i] if i < len(node.values) else None
                row_data[col.name] = str(value) if value is not None else ""
            except (IndexError, AttributeError):
                row_data[col.name] = ""
        accumulator.append(row_data)
        return accumulator
    
    renderable.visit(node=None, function=visitor, initial_accumulator=output_data)
    return output_data



def write_dict_to_csv(filename, dictionary):
    """Append a single row (dictionary) to a CSV file, writing a header if needed.

    Parameters
    ----------
    filename : str
        Path to the CSV to write/append.
    dictionary : dict
        Row data; keys become fieldnames.
    """
    fieldnames = list(dictionary.keys())
    file_exists = os.path.isfile(filename)

    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(dictionary)

def extract_all_features_from_memdump(memdump_path, output_path, progress_callback=None):
    """Run all configured Volatility3 plugins and write features to output.csv.

    Parameters
    ----------
    memdump_path : str
        Path to the memory dump file.
    output_path : str
        Directory where `output.csv` will be created/updated.
    progress_callback : callable | Qt signal, optional
        Receives textual progress messages.

    Returns
    -------
    str
        Path to the generated CSV file (output.csv).
    """
    features = {}
    print(f'=> Extracting features from {memdump_path}')
    print(f'=> Outputting to {output_path}')

    def emit_progress(message):
        """Emit progress messages via callback or direct call."""
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
    """Parse CLI arguments for single-dump extraction (memdump path and output dir)."""
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

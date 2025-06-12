# import argparse
# import csv
# import functools
# import json
# import subprocess
# import tempfile
# import os
# import pandas as pd

# plugin_dict = {}
# # Extractor functions extracts features from the Volatility

# def extract_winInfo_features(jsondump):
#     df = pd.read_json(jsondump)
#     try:
#         a = bool(json.loads(df.loc[3].at["Value"].lower()))           #Is Windows a 64 Version 
#         b = df.loc[8].at["Value"]                                 #Version of Windows Build
#         c = int(df.loc[11].at["Value"])                               #Number of Processors
#         d = bool(json.loads(df.loc[4].at["Value"].lower()))          #Is Windows Physical Address Extension (PAE) is a processor feature that enables x86 processors to access more than 4 GB of physical memory
#     except:
#         a = None
#         b = None
#         c = None
#         d = None
#     return{
#         'info.Is64': a,
#         'info.winBuild': b,
#         'info.npro': c,
#         'info.IsPAE': d
#     }

# def extract_pslist_features(jsondump):
#     features = {}
#     try:
#         df = pd.read_json(jsondump)
#         plugin_dict["pslist.pids"] = set(df["PID"] if "PID" in df.columns else df["Pid"])  # For psxview
#     except Exception as e:
#         print(f"[ERROR] Could not read JSON: {e}")
#         return features

#     try:
#         features['pslist.nproc'] = df.PPID.size
#     except Exception as e:
#         print(f"[WARN] pslist.nproc: {e}")

#     try:
#         features['pslist.nppid'] = df.PPID.nunique()
#     except Exception as e:
#         print(f"[WARN] pslist.nppid: {e}")

#     try:
#         features['pslist.avg_threads'] = df.Threads.mean()
#     except Exception as e:
#         print(f"[WARN] pslist.avg_threads: {e}")

#     try:
#         features['pslist.nprocs64bit'] = len(df[df["Wow64"] == "True"])
#     except Exception as e:
#         print(f"[WARN] pslist.nprocs64bit: {e}")

#     return features

# def extract_session_features(jsondump):
#     features = {}
#     try:
#         df = pd.read_json(jsondump)
#         plugin_dict["session.pids"] = set(df["PID"] if "PID" in df.columns else df["Pid"])  # For psxview
#     except Exception as e:
#         print(f"[ERROR] session plugin failed: {e}")
#         plugin_dict["session.pids"] = set()
#     return features

# def extract_poolscan_features(jsondump):
#     features = {}
#     try:
#         df = pd.read_json(jsondump)
#         plugin_dict["pool.pids"] = set(df["PID"] if "PID" in df.columns else df["Pid"])  # For psxview
#     except Exception as e:
#         print(f"[ERROR] pool plugin failed: {e}")
#         plugin_dict["pool.pids"] = set()
#     return features



# def extract_dlllist_features(jsondump):
#     df = pd.read_json(jsondump)
#     try:
#         a = df.PID.size                                           #Total Number of all loaded libraries
#         b = df.PID.unique().size                              #Number of Processes loading dlls
#         c = df.PID.size/df.PID.unique().size             #Average loaded libraries per process
#         d = df.Size.sum()/df.PID.unique().size                  #Average Size of loaded libraries
#         e = df.PID.size - len(df[df["File output"]=="Disabled"]) #Number of loaded librearies outputting files
#     except:
#         a = None
#         b = None
#         c = None
#         d = None
#         e = None
#     return{
#         'dlllist.ndlls': a,
#         # 'dlllist.nproc_dll': b,#Not part of our dataset
#         'dlllist.avg_dllPerProc': c,
#         # 'dlllist.avgSize': d,#Not part of our dataset
#         # 'dlllist.outfile': e#Not part of our dataset
#     }




# # def extract_handles_features(jsondump):
# #     features = {}

# #     try:
# #         df = pd.read_json(jsondump)
# #         plugin_dataframes["handles"] = df
# #     except Exception as e:
# #         print(f"[ERROR] Could not read JSON: {e}")
# #         return features

# #     try:
# #         features['handles.nhandles'] = len(df)
# #     except Exception as e:
# #         print(f"[WARN] handles.nhandles: {e}")
# #         features['handles.nhandles'] = None

# #     try:
# #         pid_col = 'PID' if 'PID' in df.columns else 'Pid' if 'Pid' in df.columns else None
# #         if pid_col:
# #             handle_counts = df.groupby(pid_col).size()
# #             features['pslist.avg_handlers'] = handle_counts.mean()
# #         else:
# #             print("[WARN] No PID column found for avg_handlers calculation.")
# #             features['pslist.avg_handlers'] = None
# #     except Exception as e:
# #         print(f"[WARN] pslist.avg_handlers: {e}")
# #         features['pslist.avg_handlers'] = None

# #     type_keys = [
# #         ('handles.nport', 'Port'),
# #         ('handles.nfile', 'File'),
# #         ('handles.nevent', 'Event'),
# #         ('handles.ndesktop', 'Desktop'),
# #         ('handles.nkey', 'Key'),
# #         ('handles.nthread', 'Thread'),
# #         ('handles.ndirectory', 'Directory'),
# #         ('handles.nsemaphore', 'Semaphore'),
# #         ('handles.ntimer', 'Timer'),
# #         ('handles.nsection', 'Section'),
# #         ('handles.nmutant', 'Mutant'),
# #     ]

# #     for feat_name, handle_type in type_keys:
# #         try:
# #             if 'Type' in df.columns:
# #                 features[feat_name] = (df['Type'] == handle_type).sum()
# #             else:
# #                 print(f"[WARN] {feat_name}: 'Type' column missing.")
# #                 features[feat_name] = None
# #         except Exception as e:
# #             print(f"[WARN] {feat_name}: {e}")
# #             features[feat_name] = None

# #     return features
# def extract_handles_features(jsondump):
#     features = {}

#     try:
#         df = pd.read_json(jsondump)
#         plugin_dict["handles.pids"] = set(df["PID"] if "PID" in df.columns else df["Pid"])  # For psxview
#     except Exception as e:
#         print(f"[ERROR] Could not read JSON: {e}")
#         return features

#     try:
#         features['handles.nhandles'] = len(df)
#     except Exception as e:
#         print(f"[WARN] handles.nhandles: {e}")
#         features['handles.nhandles'] = None

#     try:
#         pid_col = 'PID' if 'PID' in df.columns else 'Pid' if 'Pid' in df.columns else None
#         if pid_col:
#             handle_counts = df.groupby(pid_col).size()
#             features['pslist.avg_handlers'] = handle_counts.mean()
#         else:
#             print("[WARN] No PID column found for avg_handlers calculation.")
#             features['pslist.avg_handlers'] = None
#     except Exception as e:
#         print(f"[WARN] pslist.avg_handlers: {e}")
#         features['pslist.avg_handlers'] = None

#     type_keys = [
#         ('handles.nport', 'Port'),
#         ('handles.nfile', 'File'),
#         ('handles.nevent', 'Event'),
#         ('handles.ndesktop', 'Desktop'),
#         ('handles.nkey', 'Key'),
#         ('handles.nthread', 'Thread'),
#         ('handles.ndirectory', 'Directory'),
#         ('handles.nsemaphore', 'Semaphore'),
#         ('handles.ntimer', 'Timer'),
#         ('handles.nsection', 'Section'),
#         ('handles.nmutant', 'Mutant'),
#     ]

#     for feature_name, object_type in type_keys:
#         try:
#             features[feature_name] = (df['Type'] == object_type).sum()
#         except Exception as e:
#             print(f"[WARN] {feature_name}: {e}")
#             features[feature_name] = None

#     return features




# def extract_ldrmodules_features(jsondump):
#     df = pd.read_json(jsondump)
#     return {
#         # 'ldrmodules.total': df.Base.size,                                       #Number of total modules
#         'ldrmodules.not_in_load': len(df[df["InLoad"]==False]),                 #Number of modules missing from load list
#         'ldrmodules.not_in_init': len(df[df["InInit"]==False]),                 #Number of modules missing from init list
#         'ldrmodules.not_in_mem': len(df[df["InMem"]==False]),                   #Number of modules missing from mem list
# 	# 'ldrmodules.nporc': df.Pid.unique().size,                               #Number of processes with modules in memory
#         'ldrmodules.not_in_load_avg': len(df[df["InLoad"]==False])/df.Base.size,#Avg number of modules missing from load list
#         'ldrmodules.not_in_init_avg': len(df[df["InInit"]==False])/df.Base.size,#Avg number of modules missing from init list
#         'ldrmodules.not_in_mem_avg': len(df[df["InMem"]==False])/df.Base.size,  #Avg number of modules missing from mem list
#     }

# def extract_malfind_features(jsondump):
#     df = pd.read_json(jsondump)
#     return {                                                                        
#         'malfind.ninjections': df.CommitCharge.size,                              #Number of hidden code injections found by malfind
# 	'malfind.commitCharge': df.CommitCharge.sum(),                            #Sum of Commit Charges over time                                
# 	'malfind.protection': len(df[df["Protection"]=="PAGE_EXECUTE_READWRITE"]),#Number of injections with all permissions 
# 	'malfind.uniqueInjections': df.PID.unique().size,                         #Number of unique injections
#         # 'malfind.avgInjec_per_proc': df.PID.size/df.PID.unique().size,            #Average number of injections per process
#         # 'malfind.tagsVad': len(df[df["Tag"]=="Vad"]),                             #Number of Injections tagged as Vad
#         # 'malfind.tagsVads': len(df[df["Tag"]=="Vads"]),                           #Number of Injections tagged as Vads
#         # 'malfind.aveVPN_diff': df['End VPN'].sub(df['Start VPN']).sum()           #Avg VPN size of injections
#     }

# def extract_modules_features(jsondump):
#     df = pd.read_json(jsondump)
#     return {
#         'modules.nmodules': df.Base.size,                                          #Number of Modules
#         # 'modules.avgSize': df.Size.mean(),                             #Average size of the modules
#         # 'modules.FO_enabled': df.Base.size - len(df[df["File output"]=='Disabled'])#Number of Output enabled File Output
#     }
# def extract_callbacks_features(jsondump):
#     df = pd.read_json(jsondump)
#     features = {}

#     # Total callbacks
#     try:
#         features['callbacks.ncallbacks'] = len(df)
#     except Exception as e:
#         print(f"[WARN] Failed to compute callbacks.ncallbacks: {e}")

#     # Anonymous callbacks
#     try:
#         features['callbacks.nanonymous'] = (df['Module'] == 'UNKNOWN').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute callbacks.nanonymous: {e}")

#     # Generic callbacks
#     try:
#         features['callbacks.ngeneric'] = (df['Type'] == 'GenericKernelCallback').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute callbacks.ngeneric: {e}")

#     return features




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
#         # 'psxview.not_in_ethread_pool': count_false('thrdproc'),#unavailable with Volatility3
#         # 'psxview.not_in_pspcid_list': count_false('pspcid'),#unavailable with Volatility3
#         'psxview.not_in_csrss_handles': count_false('csrss'),
#         # 'psxview.not_in_session': count_false('session'),#unavailable with Volatility3
#         # 'psxview.not_in_deskthrd': count_false('deskthrd'),#unavailable with Volatility3

#         'psxview.not_in_pslist_false_avg': count_false('pslist') / total,
#         'psxview.not_in_eprocess_pool_false_avg': count_false('psscan') / total,
#         # 'psxview.not_in_ethread_pool_false_avg': count_false('thrdproc') / total,,#unavailable with Volatility3
#         # 'psxview.not_in_pspcid_list_false_avg': count_false('pspcid') / total,,#unavailable with Volatility3
#         'psxview.not_in_csrss_handles_false_avg': count_false('csrss') / total,
#         # 'psxview.not_in_session_false_avg': count_false('session') / total,,#unavailable with Volatility3
#         # 'psxview.not_in_deskthrd_false_avg': count_false('deskthrd') / total,,#unavailable with Volatility3
#     }






# def extract_svcscan_features(jsondump):
#     try:
#         df = pd.read_json(jsondump)
#     except Exception as e:
#         print(f"[ERROR] svcscan: Could not read JSON: {e}")
#         return {}

#     features = {}
#     try:
#         features['svcscan.nservices'] = len(df)
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.nservices: {e}")

#     try:
#         features['svcscan.kernel_drivers'] = (df['Type'] == 'SERVICE_KERNEL_DRIVER').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.kernel_drivers: {e}")

#     try:
#         features['svcscan.fs_drivers'] = (df['Type'] == 'SERVICE_FILE_SYSTEM_DRIVER').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.fs_drivers: {e}")

#     try:
#         features['svcscan.process_services'] = (df['Type'] == 'SERVICE_WIN32_OWN_PROCESS').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.process_services: {e}")

#     try:
#         features['svcscan.shared_process_services'] = (df['Type'] == 'SERVICE_WIN32_SHARE_PROCESS').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.shared_process_services: {e}")

#     try:
#         features['svcscan.interactive_process_services'] = (df['Type'].str.contains('INTERACTIVE_PROCESS', na=False)).sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.interactive_process_services: {e}")

#     try:
#         features['svcscan.nactive'] = (df['State'] == 'SERVICE_RUNNING').sum()
#     except Exception as e:
#         print(f"[WARN] Failed to compute svcscan.nactive: {e}")

#     return features


# def extract_deskthrd_features(jsondump):
#     features = {}
#     try:
#         df = pd.read_json(jsondump)
#         plugin_dict["deskthrd.pids"] = set(df["PID"] if "PID" in df.columns else df["Pid"])
#     except Exception as e:
#         print(f"[ERROR] deskthrd plugin failed: {e}")
#         plugin_dict["deskthrd.pids"] = set()
#     return features

# def extract_psxview_approximation(plugin_dict):
#     features = {}

#     pslist_pids = plugin_dict.get("pslist.pids", set())
#     pool_pids = plugin_dict.get("pool.pids", set())
#     handles_pids = plugin_dict.get("handles.pids", set())
#     session_pids = plugin_dict.get("session.pids", set())
#     deskthrd_pids = plugin_dict.get("deskthrd.pids", set())

#     # Core mismatch counts
#     features['psxview.not_int_ethread_pool'] = len(pool_pids - pslist_pids)
#     features['psxview.not_int_pspcid_list'] = len(handles_pids - pslist_pids)
#     features['psxview.not_in_session'] = len(session_pids - pslist_pids)
#     features['psxview.not_in_deskthrd'] = len(deskthrd_pids - pslist_pids)

#     # "False avg" versions — average # of mismatches per pslist PID
#     try:
#         n_total = len(pslist_pids)
#         if n_total == 0:
#             raise ZeroDivisionError("No pslist PIDs to compare against")

#         features['psxview.not_int_ethread_pool_false_avg'] = len(pslist_pids - pool_pids) / n_total
#         features['psxview.not_int_pspcid_list_false_avg'] = len(pslist_pids - handles_pids) / n_total
#         features['psxview.not_in_session_false_avg'] = len(pslist_pids - session_pids) / n_total
#         features['psxview.not_in_deskthrd_false_avg'] = len(pslist_pids - deskthrd_pids) / n_total
#     except Exception as e:
#         print(f"[WARN] false_avg psxview features: {e}")
#         features['psxview.not_int_ethread_pool_false_avg'] = None
#         features['psxview.not_int_pspcid_list_false_avg'] = None
#         features['psxview.not_in_session_false_avg'] = None
#         features['psxview.not_in_deskthrd_false_avg'] = None

#     return features






# VOL_MODULES = {
#     'pslist': extract_pslist_features,
#     'dlllist': extract_dlllist_features,
#     'handles': extract_handles_features,
#     'ldrmodules': extract_ldrmodules_features,
#     'malfind': extract_malfind_features,
#     'modules': extract_modules_features,
#     'callbacks': extract_callbacks_features,
#     'svcscan': extract_svcscan_features,
#     'psxview.PsXView':extract_psxview_features
# }



# def invoke_volatility3(vol_py_path, memdump_path, module, output_to):
#     with open(output_to,'w') as f:
#         subprocess.run(['python',vol_py_path, '-f', memdump_path, '-r=json', 'windows.'+module],stdout=f,text=True, check=True)




# def write_dict_to_csv(filename, dictionary,memdump_path):
#     fieldnames = list(dictionary.keys())
    
#     # Check if the file already exists
#     file_exists = os.path.isfile(filename)
    
#     with open(filename, 'a', newline='') as csvfile:
#         writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
#         # Write header only if the file is empty
#         if not file_exists:
#             writer.writeheader()
#         writer.writerow(dictionary)







# def extract_all_features_from_memdump(memdump_path, CSVoutput_path, volatility_path):
#     features = {}
#     print('=> Outputting to', CSVoutput_path)

#     with tempfile.TemporaryDirectory() as workdir:
#         vol = functools.partial(invoke_volatility3, volatility_path, memdump_path)
#         for module, extractor in VOL_MODULES.items():
#             print('=> Executing Volatility module', repr(module))
#             output_file_path = os.path.join(workdir, module)
#             vol(module, output_file_path)
#             with open(output_file_path, 'r') as output:
#                 features.update(extractor(output))
    
#     psxview_features = extract_psxview_approximation(plugin_dict)
#     features.update(psxview_features)

    
#     features_mem = {'mem.name_extn': str(memdump_path).rsplit('/', 1)[-1]}
#     features_mem.update(features)

#     file_path = os.path.join(CSVoutput_path, 'output.csv')
#     write_dict_to_csv(file_path,features_mem,memdump_path)

#     print('=> All done')



# def parse_args():
#     p = argparse.ArgumentParser()
#     p.add_argument('-f','--memdump',default=None, help='Path to folder/directory which has all memdumps',required = True)
#     p.add_argument('-o', '--output', default=None, help='Path to the folder where to output the CSV',required = True)
#     p.add_argument('-V', '--volatility', default=None, help='Path to the vol.py file in Volatility folder including the extension .py',required = True)
#     return p, p.parse_args()





# if __name__ == '__main__':
#     p, args = parse_args()

#     print(args.memdump)
#     folderpath = str(args.memdump)
#     print(folderpath)

#     for filename in os.listdir(folderpath):
#         print(filename)
#         file_path = os.path.join(folderpath, filename)
#         print(file_path)

#         if (file_path).endswith('.raw') or (file_path).endswith('.mem') or (file_path).endswith('.vmem') or (file_path).endswith('.mddramimage'):
#             extract_all_features_from_memdump((file_path), args.output, args.volatility)

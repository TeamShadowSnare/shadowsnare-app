import argparse
import csv
import functools
import json
import subprocess
import tempfile
import os
import pandas as pd


# Extractor functions extracts features from the Volatility

def extract_winInfo_features(jsondump):
    df = pd.read_json(jsondump)
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
    df = pd.read_json(jsondump)
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

# def extract_pslist_features(jsondump):
#     df = pd.read_json(jsondump)
#     try:
#         a = df.PPID.size                                           #Number of Processes
#         b = df.PPID.nunique()                                  #Number of Parent Processes
#         c = df.Threads.mean()                  #Average Thread count
#         d = df.Handles.mean()                 #Average Handler count
#         e = len(df[df["Wow64"]=="True"])                     #Number of 64-Bit Processes
#         f = df.PPID.size - len(df[df["File output"]=="Disabled"]) #Number of processes with FileOutput enabled 
#     except:
#         a = None
#         b = None
#         c = None
#         d = None
#         e = None
#         f = None
#     return{
#         'pslist.nproc': a,
#         'pslist.nppid': b,
#         'pslist.avg_threads': c,
#         'pslist.avg_handlers': d,
#         'pslist.nprocs64bit': e,
#         # 'pslist.outfile': f#Not part of our dataset
#     }

def extract_dlllist_features(jsondump):
    df = pd.read_json(jsondump)
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

# def extract_handles_features(jsondump):
#     df = pd.read_json(jsondump)
#     try:
#         a = df.HandleValue.size                                #Total number of opened Handles
#         b = df.HandleValue.unique().size                #Total number of distinct Handle Values
#         c = df.PID.unique().size                                  #Number of processes with handles
#         d = df.GrantedAccess.unique().size                      #Number of distinct GrantedAccess
#         e = df.HandleValue.size/df.PID.unique().size#Average number of handles per process
#         f = len(df[df["Type"]=="Port"])                       #Number of Type of Handles --> Ports
#         g = len(df[df["Type"]=="Process"])                    #Number of Type of Handles --> Process
#         h = len(df[df["Type"]=="Thread"])                   #Number of Type of Handles --> Thread
#         i = len(df[df["Type"]=="Key"])                         #Number of Type of Handles --> Key
#         j = len(df[df["Type"]=="Event"])                     #Number of Type of Handles --> Event
#         k = len(df[df["Type"]=="File"])                      #Number of Type of Handles --> File
#         l = len(df[df["Type"]=="Directory"])                   #Number of Type of Handles --> Directory
#         m = len(df[df["Type"]=="Section"])                     #Number of Type of Handles --> Section
#         n = len(df[df["Type"]=="Desktop"])                    #Number of Type of Handles --> Desktop
#         o = len(df[df["Type"]=="Token"])                     #Number of Type of Handles --> Token
#         p = len(df[df["Type"]=="Mutant"])                   #Number of Type of Handles --> Mutant
#         q = len(df[df["Type"]=="KeyedEvent"])             #Number of Type of Handles --> KeyedEvent
#         r = len(df[df["Type"]=="SymbolicLink"])           #Number of Type of Handles --> SymbolicLink
#         s = len(df[df["Type"]=="Semaphore"])                #Number of Type of Handles --> Semaphore
#         t = len(df[df["Type"]=="WindowStation"])            #Number of Type of Handles --> WindowStation
#         u = len(df[df["Type"]=="Timer"])                     #Number of Type of Handles --> Timer
#         v = len(df[df["Type"]=="IoCompletion"])                 #Number of Type of Handles --> IoCompletion
#         w = len(df[df["Type"]=="WmiGuid"])                     #Number of Type of Handles --> WmiGuid
#         x = len(df[df["Type"]=="WaitablePort"])           #Number of Type of Handles --> WaitablePort
#         y = len(df[df["Type"]=="Job"])                         #Number of Type of Handles --> Job
#         z = df.HandleValue.size - len(df[df["Type"]=="Port"]) - len(df[df["Type"]=="Process"]) - len(df[df["Type"]=="Thread"]) - len(df[df["Type"]=="Key"])  \
#                                                     - len(df[df["Type"]=="Event"]) - len(df[df["Type"]=="File"]) - len(df[df["Type"]=="Directory"]) - len(df[df["Type"]=="Section"])\
#                                                     - len(df[df["Type"]=="Desktop"]) - len(df[df["Type"]=="Token"]) - len(df[df["Type"]=="Mutant"]) - len(df[df["Type"]=="KeyedEvent"])\
#                                                     - len(df[df["Type"]=="Semaphore"]) - len(df[df["Type"]=="WindowStation"]) - len(df[df["Type"]=="Timer"]) - len(df[df["Type"]=="IoCompletion"])\
#                                                     - len(df[df["Type"]=="WaitablePort"]) - len(df[df["Type"]=="Job"]) - len(df[df["Type"]=="SymbolicLink"]) - len(df[df["Type"]=="WmiGuid"])
#     except:
#         a = None
#         b = None
#         c = None
#         d = None
#         e = None
#         f = None        
#         g = None
#         h = None
#         i = None
#         j = None
#         k = None
#         l = None
#         m = None
#         n = None
#         o = None
#         p = None
#         q = None
#         r = None
#         s = None
#         t = None
#         u = None
#         v = None
#         w = None
#         x = None
#         y = None
        # z = None
                                                                                #Number of Type of Handles --> Unknown 
    # return{
    #     'handles.nHandles': a,
    #     'handles.distinctHandles': b,#Not part of our dataset
    #     'handles.nproc': c,#Not part of our dataset
    #     'handles.nAccess': d,

    #     'handles.avgHandles_per_proc': e,
    #     'handles.nTypePort': f,
    #     'handles.nTyepProc': g,
    #     'handles.nTypeThread': h,
    #     'handles.nTypeKey': i,
    #     'handles.nTypeEvent': j,
    #     'handles.nTypeFile': k,
    #     'handles.nTypeDir': l,
    #     'handles.nTypeSec': m,
    #     'handles.nTypeDesk': n,
    #     'handles.nTypeToken': o,
    #     'handles.nTypeMutant': p,
    #     'handles.nTypeKeyEvent': q,
    #     'handles.nTypeSymLink': r,
    #     'handles.nTypeSemaph': s,
    #     'handles.nTypeWinSta': t,
    #     'handles.nTypeTimer': u,
    #     'handles.nTypeIO': v,
    #     'handles.nTypeWmi': w,
    #     'handles.nTypeWaitPort': x,
    #     'handles.nTypeJob': y,
    #     'handles.nTypeUnknown': z  
    # }
    # handles = df
    # return {
    #     # Total # of opened handles
    #     'handles.nhandles': len(handles),
    #     # Avg. handle count per process
    #     'handles.avg_handles_per_proc': len(handles) / len(set(h['Pid'] for h in handles)),
    #     # TODO: Per-type counts?
	# # # of handles of type port
	# 'handles.nport': sum(1 if t['Type'] == 'Port' else 0 for t in handles),
	# # # of handles of type file
	# 'handles.nfile': sum(1 if t['Type'] == 'File' else 0 for t in handles),
	# # # of handles of type event
	# 'handles.nevent': sum(1 if t['Type'] == 'Event' else 0 for t in handles),
	# # # of handles of type desktop
	# 'handles.ndesktop': sum(1 if t['Type'] == 'Desktop' else 0 for t in handles),
	# # # of handles of type key
	# 'handles.nkey': sum(1 if t['Type'] == 'Key' else 0 for t in handles),
	# # # of handles of type thread
	# 'handles.nthread': sum(1 if t['Type'] == 'Thread' else 0 for t in handles),
	# # # of handles of type directory
	# 'handles.ndirectory': sum(1 if t['Type'] == 'Directory' else 0 for t in handles),
	# # # of handles of type semaphore
	# 'handles.nsemaphore': sum(1 if t['Type'] == 'Semaphore' else 0 for t in handles),
	# # # of handles of type timer
	# 'handles.ntimer': sum(1 if t['Type'] == 'Timer' else 0 for t in handles),
	# # # of handles of type section
	# 'handles.nsection': sum(1 if t['Type'] == 'Section' else 0 for t in handles),
	# # # of handles of type mutant
	# 'handles.nmutant': sum(1 if t['Type'] == 'Mutant' else 0 for t in handles),
    # }

# def extract_handles_features(jsondump):#LATEST
#     df = pd.read_json(jsondump)

#     try:
#         return {
#             'handles.nhandles': len(df),
#             'handles.avg_handles_per_proc': len(df) / df['Pid'].nunique(),

#             'handles.nport': (df['Type'] == 'Port').sum(),
#             'handles.nfile': (df['Type'] == 'File').sum(),
#             'handles.nevent': (df['Type'] == 'Event').sum(),
#             'handles.ndesktop': (df['Type'] == 'Desktop').sum(),
#             'handles.nkey': (df['Type'] == 'Key').sum(),
#             'handles.nthread': (df['Type'] == 'Thread').sum(),
#             'handles.ndirectory': (df['Type'] == 'Directory').sum(),
#             'handles.nsemaphore': (df['Type'] == 'Semaphore').sum(),
#             'handles.ntimer': (df['Type'] == 'Timer').sum(),
#             'handles.nsection': (df['Type'] == 'Section').sum(),
#             'handles.nmutant': (df['Type'] == 'Mutant').sum(),
#         }
#     except Exception as e:
#         print(f"[ERROR] handle feature extraction failed: {e}")
#         return {}

# def extract_handles_features(jsondump):#LATEST 28/05 20:58
#     df = pd.read_json(jsondump)
#     features = {}

#     try:
#         features['handles.nhandles'] = len(df)
#     except Exception as e:
#         print(f"[WARN] handles.nhandles: {e}")

#     try:
#         features['handles.avg_handles_per_proc'] = len(df) / df['Pid'].nunique()
#     except Exception as e:
#         print(f"[WARN] handles.avg_handles_per_proc: {e}")

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

#     for feat_name, handle_type in type_keys:
#         try:
#             features[feat_name] = (df['Type'] == handle_type).sum()
#         except Exception as e:
#             print(f"[WARN] {feat_name}: {e}")

#     return features


def extract_handles_features(jsondump):
    features = {}

    try:
        df = pd.read_json(jsondump)
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
    df = pd.read_json(jsondump)
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
    df = pd.read_json(jsondump)
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
    df = pd.read_json(jsondump)
    return {
        'modules.nmodules': df.Base.size,                                          #Number of Modules
        # 'modules.avgSize': df.Size.mean(),                             #Average size of the modules
        # 'modules.FO_enabled': df.Base.size - len(df[df["File output"]=='Disabled'])#Number of Output enabled File Output
    }
def extract_callbacks_features(jsondump):
    df = pd.read_json(jsondump)
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



# def extract_callbacks_features(jsondump):
#     df = pd.read_json(jsondump)
#     return {
#     'callbacks.ncallbacks': len(df),
#     'callbacks.nanonymous': sum(1 if c['Module'] == 'UNKNOWN' else 0 for c in df),
#     'callbacks.ngeneric': sum(1 if c['Type'] == 'GenericKernelCallback' else 0 for c in df),
# }
    # return {
    #     'callbacks.ncallbacks': df.Callback.size,                                               #Number of callbacks
    #     'callbacks.nNoDetail': len(df[df["Detail"]=='None']),                                   #Number of callbacks with no detail
    #     'callbacks.nBugCheck': len(df[df["Type"]=='KeBugCheckCallbackListHead']),               #Number of callback Type --> KeBugCheckCallbackListHead
    #     'callbacks.nBugCheckReason': len(df[df["Type"]=='KeBugCheckReasonCallbackListHead']),   #Number of callback Type --> KeBugCheckReasonCallbackListHead
    #     'callbacks.nCreateProc': len(df[df["Type"]=='PspCreateProcessNotifyRoutine']),          #Number of callback Type --> PspCreateProcessNotifyRoutine
    #     'callbacks.nCreateThread': len(df[df["Type"]=='PspCreateThreadNotifyRoutine']),         #Number of callback Type --> PspCreateThreadNotifyRoutine
    #     'callbacks.nLoadImg': len(df[df["Type"]=='PspLoadImageNotifyRoutine']),                 #Number of callback Type --> PspLoadImageNotifyRoutine
    #     'callbacks.nRegisterCB': len(df[df["Type"]=='CmRegisterCallback']),                     #Number of callback Type --> CmRegisterCallback
    #     'callback.nUnknownType': df.Callback.size - len(df[df["Type"]=='KeBugCheckCallbackListHead']) - len(df[df["Type"]=='CmRegisterCallback'])\
    #                                               - len(df[df["Type"]=='KeBugCheckReasonCallbackListHead']) - len(df[df["Type"]=='PspLoadImageNotifyRoutine'])\
    #                                               - len(df[df["Type"]=='PspCreateProcessNotifyRoutine']) - len(df[df["Type"]=='PspCreateThreadNotifyRoutine']),
    #                                                                                             #Number of callback Type --> UNKNOWN
                
    # }

# def extract_psxview_features(jsondump):#LATEST
#     psxview = json.load(jsondump)

#     # Print diagnostics on missing fields
#     for k in ['pslist', 'psscan', 'csrss', 'pspcid', 'session', 'deskthrd', 'thrdproc']:
#         missing = [p for p in psxview if k not in p]
#         if missing:
#             print(f"Missing key: {k} in {len(missing)} out of {len(psxview)} entries")

#     def count_false(key):
#         return sum(1 for p in psxview if str(p.get(key, True)) == 'False')

#     total = len(psxview) if psxview else 1  # avoid division by zero

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
# def extract_psxview_features(jsondump):
#     try:
#         psxview = json.load(jsondump)
#     except Exception as e:
#         print(f"[ERROR] Failed to parse JSON: {e}")
#         return {}

#     keys = ['pslist', 'psscan', 'csrss', 'pspcid', 'session', 'deskthrd', 'thrdproc']
#     total = len(psxview) if psxview else 1  # Avoid div by zero
#     features = {}

#     for k in keys:
#         try:
#             missing = [p for p in psxview if k not in p]
#             if missing:
#                 print(f"[INFO] Missing key: {k} in {len(missing)} / {len(psxview)} entries")

#             count_false = sum(1 for p in psxview if str(p.get(k, True)) == 'False')

#             features[f'psxview.not_in_{k}'] = count_false
#             features[f'psxview.not_in_{k}_false_avg'] = count_false / total
#         except Exception as e:
#             print(f"[WARN] psxview.{k} extraction failed: {e}")

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



# def rc2kv(rc):
#     kv = []
#     keys = rc['columns']
#     for r in rc['rows']:
#         entry = {}
#         kv.append(entry)
#         for k, v in zip(keys, r):
#             entry[k] = v
#     return kv


# def extract_psxview_features(jsondump):
#     df = pd.read_json(jsondump)
#     methods = ['pslist', 'psscan', 'thrdscan', 'csrss']
    
#     features = {
#         'psxview.nProcesses': len(df),
#         'psxview.nHidden': 0,
#         'psxview.hidden_ratio': 0
#     }

#     for method in methods:
#         features[f'psxview.hidden_{method}'] = 0
#         features[f'psxview.visible_{method}'] = 0

#     hidden_count = 0
#     visible_counts = []

#     for _, row in df.iterrows():
#         visibility_flags = [row.get(method, False) for method in methods]
#         n_visible = sum(visibility_flags)
#         visible_counts.append(n_visible)

#         for i, method in enumerate(methods):
#             if visibility_flags[i]:
#                 features[f'psxview.visible_{method}'] += 1
#             else:
#                 features[f'psxview.hidden_{method}'] += 1

#         if n_visible == 0:
#             hidden_count += 1

#     features['psxview.nHidden'] = hidden_count
#     features['psxview.hidden_ratio'] = hidden_count / len(df) if len(df) > 0 else 0
#     features['psxview.mean_visibility'] = sum(visible_counts) / len(visible_counts) if visible_counts else 0
#     features['psxview.min_visibility'] = min(visible_counts) if visible_counts else 0
#     features['psxview.max_visibility'] = max(visible_counts) if visible_counts else 0
#     features['psxview.unique_to_one_method'] = sum([1 for count in visible_counts if count == 1])

#     return features



def extract_svcscan_features(jsondump):
    try:
        df = pd.read_json(jsondump)
    except Exception as e:
        print(f"[ERROR] svcscan: Could not read JSON: {e}")
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


# def extract_svcscan_features(jsondump):
#     df=pd.read_json(jsondump)
#     # return{
#     #     'svcscan.nServices': len(df),
#     #     'svcscan.nUniqueServ': df.Name.nunique(),
#     #     'svcscan.State_Run': len(df[df["State"]=="SERVICE_RUNNING"]),
#     #     'svcscan.State_Stop': len(df[df["State"]=="SERVICE_STOPPED"]),
#     #     'svcscan.Start_Sys': len(df[df["Start"]=="SERVICE_SYSTEM_START"]),
#     #     'svcscan.Start_Auto': len(df[df["Start"]=="SERVICE_AUTO_START"]),
#     #     'svcscan.Type_Own_Share': len(df[df["Type"]=="SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS"]),
#     #     'svcscan.Type_Own': len(df[df["Type"]=="SERVICE_WIN32_OWN_PROCESS"]),
#     #     'svcscan.Type_Share': len(df[df["Type"]=="SERVICE_WIN32_SHARE_PROCESS"]),
#     #     'svcscan.Type_Own_Interactive': len(df[df["Type"]=="SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS"]),
#     #     'svcscan.Type_Share_Interactive': len(df[df["Type"]=="SERVICE_WIN32_SHARE_PROCESS|SERVICE_INTERACTIVE_PROCESS"]),
#     #     'svcscan.Type_Kernel_Driver': len(df[df["Type"]=="SERVICE_KERNEL_DRIVER"]),
#     #     'svcscan.Type_FileSys_Driver': len(df[df["Type"]=="SERVICE_FILE_SYSTEM_DRIVER"]),
#     #     'svcscan.Type_Others': len(df[~df['Type'].isin(['SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS','SERVICE_WIN32_OWN_PROCESS','SERVICE_KERNEL_DRIVER','SERVICE_WIN32_SHARE_PROCESS','SERVICE_FILE_SYSTEM_DRIVER','SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS','SERVICE_WIN32_SHARE_PROCESS|SERVICE_INTERACTIVE_PROCESS'])])
#     # }
#     return {
#         'svcscan.nservices': len(df),
#         'svcscan.kernel_drivers': sum(1 if s['ServiceType'] == 'SERVICE_KERNEL_DRIVER' else 0 for s in df),
#         'svcscan.fs_drivers': sum(1 if s['ServiceType'] == 'SERVICE_FILE_SYSTEM_DRIVER' else 0 for s in df),
#         'svcscan.process_services': sum(1 if s['ServiceType'] == 'SERVICE_WIN32_OWN_PROCESS' else 0 for s in df),
#         'svcscan.shared_process_services': sum(1 if s['ServiceType'] == 'SERVICE_WIN32_SHARE_PROCESS' else 0 for s in df),
#         'svcscan.interactive_process_services': sum(1 if s['ServiceType'] == 'SERVICE_INTERACTIVE_PROCESS' else 0 for s in df),
#         'svcscan.nactive': sum(1 if s['State'] == 'SERVICE_RUNNING' else 0 for s in df),
#     }



VOL_MODULES = {
    'pslist': extract_pslist_features,
    'dlllist': extract_dlllist_features,
    'handles': extract_handles_features,
    'ldrmodules': extract_ldrmodules_features,
    'malfind': extract_malfind_features,
    'modules': extract_modules_features,
    'callbacks': extract_callbacks_features,
    'svcscan': extract_svcscan_features,
    'psxview.PsXView':extract_psxview_features
}



def invoke_volatility3(vol_py_path, memdump_path, module, output_to):
    with open(output_to,'w') as f:
        subprocess.run(['python',vol_py_path, '-f', memdump_path, '-r=json', 'windows.'+module],stdout=f,text=True, check=True)




def write_dict_to_csv(filename, dictionary,memdump_path):
    fieldnames = list(dictionary.keys())
    
    # Check if the file already exists
    file_exists = os.path.isfile(filename)
    
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Write header only if the file is empty
        if not file_exists:
            writer.writeheader()
        writer.writerow(dictionary)







def extract_all_features_from_memdump(memdump_path, CSVoutput_path, volatility_path):
    features = {}
    print('=> Outputting to', CSVoutput_path)

    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(invoke_volatility3, volatility_path, memdump_path)
        for module, extractor in VOL_MODULES.items():
            print('=> Executing Volatility module', repr(module))
            output_file_path = os.path.join(workdir, module)
            vol(module, output_file_path)
            with open(output_file_path, 'r') as output:
                features.update(extractor(output))
    
    features_mem = {'mem.name_extn': str(memdump_path).rsplit('/', 1)[-1]}
    features_mem.update(features)

    file_path = os.path.join(CSVoutput_path, 'output.csv')
    write_dict_to_csv(file_path,features_mem,memdump_path)

    print('=> All done')



def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-f','--memdump',default=None, help='Path to folder/directory which has all memdumps',required = True)
    p.add_argument('-o', '--output', default=None, help='Path to the folder where to output the CSV',required = True)
    p.add_argument('-V', '--volatility', default=None, help='Path to the vol.py file in Volatility folder including the extension .py',required = True)
    return p, p.parse_args()





if __name__ == '__main__':
    p, args = parse_args()

    print(args.memdump)
    folderpath = str(args.memdump)
    print(folderpath)

    for filename in os.listdir(folderpath):
        print(filename)
        file_path = os.path.join(folderpath, filename)
        print(file_path)

        if (file_path).endswith('.raw') or (file_path).endswith('.mem') or (file_path).endswith('.vmem') or (file_path).endswith('.mddramimage'):
            extract_all_features_from_memdump((file_path), args.output, args.volatility)

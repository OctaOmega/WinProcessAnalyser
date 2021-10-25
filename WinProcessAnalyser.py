import tabulate
import wmi
import os
import Signaturefinder
import psutil
import time

proc_meta = wmi.WMI()
header_name = ['Process_Name', 'Processs_ID', 'Process_Desc', 'Process_Caption', 'Process_CretionClassName', 'Process_ComputerName', 
                    'Process_Handle', 'Process_ParentPID', 'Process_Priority', 'Process_ThreadCount']

process_list = []
process_list_data = []
exit_value = 'y'

while exit_value.lower() == 'y':
    for process in proc_meta.Win32_Process ():
            process_list = [process.Name, process.ProcessId, process.Description, process.Caption, process.CreationClassName, process.CSName, process.Handle, process.ParentProcessId, process.Priority, 
            process.ThreadCount]
            if process_list not in process_list_data:
                process_list_data.append(process_list)
    os.system('cls')
    print(tabulate.tabulate(process_list_data, header_name, tablefmt="pretty", numalign="right", colalign="right"))
    print(' ')
    exit_value = input ("Would you like to update the process list[Y/N]: ")

print(' ')

process_to_anly = int(input("Enter the PID to analyze: "))
print ('-' * 35)
print (' ')
process_info = []
cmdline_variable = {}
access_rest = 'Permitted'
cw_dir_path = ' '
process_user = ' '
for proc in psutil.process_iter ():
    if process_to_anly == proc.pid:
        execution_module = str(proc.exe())
        created_time = str(time.ctime(proc.create_time()))
        proces_status = str(proc.status())
        try:  
            for i in proc.cmdline():
                print (f'Command line variables: {i} ')
            cw_dir_path = str(proc.cwd ())
            process_user = str(proc.username())
        except psutil.AccessDenied:
            access_rest = 'Access Denied'

print(' ')
process_info_header = ['Process_Created_Time', 'Process_Status', 'EXE_PATH', 'CW_DIR', 'Process[Domain\Owner]', 'Access_status']
process_info = [created_time, proces_status, execution_module, cw_dir_path, process_user, access_rest]

for i in range(6):
    print(f'>>{process_info_header[i]} : {process_info[i]}')

fh=open(str(f'{process_to_anly}.txt'), 'w')
execution_module = execution_module.replace("~", os.path.expanduser("~"))
result = Signaturefinder.Signaturefinder(execution_module)
fh.write(str(result.__dict__['peFile']))
fh.close()

print(' ')
Sig_comp = input("Would you like to check the Binary for packaged signatures[Signature XML file is requried] [Y/N]: ")
print(' ')

if Sig_comp.lower()=='y':
    signature_maped = Signaturefinder.findSignature(execution_module)
    print(signature_maped)
    
print(' ')
print ('-' * 40)
print(f"Detailed analysis of the process available in \CW_DIR\{process_to_anly}.txt ")
print ('-' * 40)
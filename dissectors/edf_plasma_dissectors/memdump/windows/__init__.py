"""Plasma Windows Memory Dissectors

    windows.amcache.Amcache                                     Extract information on executed applications from the AmCache (deprecated).
    windows.bigpools.BigPools                                   List big page pools.
    windows.cachedump.Cachedump                                 Dumps lsa secrets from memory (deprecated)
    windows.callbacks.Callbacks                                 Lists kernel callbacks and notification routines.
    windows.cmdline.CmdLine                                     Lists process command line arguments.
    windows.cmdscan.CmdScan                                     Looks for Windows Command History lists
    windows.consoles.Consoles                                   Looks for Windows console buffers
    windows.crashinfo.Crashinfo                                 Lists the information from a Windows crash dump.
    windows.debugregisters.DebugRegisters
    windows.deskscan.DeskScan                                   Scans for the Desktop instances of each Window Station
    windows.desktops.Desktops                                   Enumerates the Desktop instances of each Window Station
    windows.devicetree.DeviceTree                               Listing tree based on drivers and attached devices in a particular windows memory image.
    windows.direct_system_calls.DirectSystemCalls               Detects the Direct System Call technique used to bypass EDRs (deprecated).
    windows.dlllist.DllList                                     Lists the loaded DLLs in a particular windows memory image.
    windows.driverirp.DriverIrp                                 List IRPs for drivers in a particular windows memory image.
    windows.drivermodule.DriverModule                           Determines if any loaded drivers were hidden by a rootkit (deprecated).
    windows.driverscan.DriverScan                               Scans for drivers present in a particular windows memory image.
    windows.dumpfiles.DumpFiles                                 Dumps cached file contents from Windows memory samples.
    windows.envars.Envars                                       Display process environment variables
    windows.etwpatch.EtwPatch                                   Identifies ETW (Event Tracing for Windows) patching techniques used by malware to evade detection.
    windows.filescan.FileScan                                   Scans for file objects present in a particular windows memory image.
    windows.getservicesids.GetServiceSIDs                       Lists process token sids.
    windows.getsids.GetSIDs                                     Print the SIDs owning each process
    windows.handles.Handles                                     Lists process open handles.
    windows.hashdump.Hashdump                                   Dumps user hashes from memory (deprecated)
    windows.hollowprocesses.HollowProcesses                     Lists hollowed processes (deprecated)
    windows.iat.IAT                                             Extract Import Address Table to list API (functions) used by a program contained in external libraries
    windows.indirect_system_calls.IndirectSystemCalls           Detects the Indirect System Call technique used to bypass EDRs (deprecated).
    windows.info.Info                                           Show OS & kernel details of the memory sample being analyzed.
    windows.joblinks.JobLinks                                   Print process job link information
    windows.kpcrs.KPCRs                                         Print KPCR structure for each processor
    windows.ldrmodules.LdrModules                               Lists the loaded modules in a particular windows memory image.
    windows.lsadump.Lsadump                                     Dumps lsa secrets from memory (deprecated)
    windows.malfind.Malfind                                     Lists process memory ranges that potentially contain injected code (deprecated).
    windows.malware.direct_system_calls.DirectSystemCalls       Detects the Direct System Call technique used to bypass EDRs
    windows.malware.drivermodule.DriverModule                   Determines if any loaded drivers were hidden by a rootkit
    windows.malware.hollowprocesses.HollowProcesses             Lists hollowed processes
    windows.malware.indirect_system_calls.IndirectSystemCalls   Detects the Indirect System Call technique used to bypass EDRs.
    windows.malware.ldrmodules.LdrModules                       Lists the loaded modules in a particular windows memory image.
    windows.malware.malfind.Malfind                             Lists process memory ranges that potentially contain injected code.
    windows.malware.processghosting.ProcessGhosting             Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0 or Vads that are DeleteOnClose
    windows.malware.psxview.PsXView                             Lists all processes found via four of the methods described in "The Art of Memory Forensics" which may help identify processes that are trying to hide themselves.
    windows.malware.skeleton_key_check.Skeleton_Key_Check       Looks for signs of Skeleton Key malware
    windows.malware.suspicious_threads.SuspiciousThreads        Lists suspicious userland process threads
    windows.malware.svcdiff.SvcDiff                             Compares services found through list walking versus scanning to find rootkits
    windows.malware.unhooked_system_calls.UnhookedSystemCalls   Detects hooked ntdll.dll stub functions in Windows processes.
    windows.mbrscan.MBRScan                                     Scans for and parses potential Master Boot Records (MBRs)
    windows.memmap.Memmap                                       Prints the memory map
    windows.mftscan.ADS                                         Scans for Alternate Data Stream
    windows.mftscan.MFTScan                                     Scans for MFT FILE objects present in a particular windows memory image.
    windows.mftscan.ResidentData                                Scans for MFT Records with Resident Data
    windows.modscan.ModScan                                     Scans for modules present in a particular windows memory image.
    windows.modules.Modules                                     Lists the loaded kernel modules.
    windows.mutantscan.MutantScan                               Scans for mutexes present in a particular windows memory image.
    windows.netscan.NetScan                                     Scans for network objects present in a particular windows memory image.
    windows.netstat.NetStat                                     Traverses network tracking structures present in a particular windows memory image.
    windows.orphan_kernel_threads.Threads                       Lists process threads
    windows.pe_symbols.PESymbols                                Prints symbols in PE files in process and kernel memory
    windows.pedump.PEDump                                       Allows extracting PE Files from a specific address in a specific address space
    windows.poolscanner.PoolScanner                             A generic pool scanner plugin.
    windows.privileges.Privs                                    Lists process token privileges
    windows.processghosting.ProcessGhosting                     Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0 or Vads that are DeleteOnClose (deprecated).
    windows.pslist.PsList                                       Lists the processes present in a particular windows memory image.
    windows.psscan.PsScan                                       Scans for processes present in a particular windows memory image.
    windows.pstree.PsTree                                       Plugin for listing processes in a tree based on their parent process ID.
    windows.psxview.PsXView                                     Lists all processes found via four of the methods described in "The Art of Memory Forensics" which may help identify processes that are trying to hide themselves.
    windows.registry.amcache.Amcache                            Extract information on executed applications from the AmCache.
    windows.registry.cachedump.Cachedump                        Dumps lsa secrets from memory
    windows.registry.certificates.Certificates                  Lists the certificates in the registry's Certificate Store.
    windows.registry.getcellroutine.GetCellRoutine              Reports registry hives with a hooked GetCellRoutine handler
    windows.registry.hashdump.Hashdump                          Dumps user hashes from memory
    windows.registry.hivelist.HiveList                          Lists the registry hives present in a particular memory image.
    windows.registry.hivescan.HiveScan                          Scans for registry hives present in a particular windows memory image.
    windows.registry.lsadump.Lsadump                            Dumps lsa secrets from memory
    windows.registry.printkey.PrintKey                          Lists the registry keys under a hive or specific key value.
    windows.registry.scheduled_tasks.ScheduledTasks             Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times.
    windows.registry.userassist.UserAssist                      Print userassist registry keys and information.
    windows.scheduled_tasks.ScheduledTasks                      Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times (deprecated).
    windows.sessions.Sessions                                   Lists Processes with Session information extracted from Environmental Variables
    windows.shimcachemem.ShimcacheMem                           Reads Shimcache entries from the ahcache.sys AVL tree
    windows.skeleton_key_check.Skeleton_Key_Check               Looks for signs of Skeleton Key malware
    windows.ssdt.SSDT                                           Lists the system call table.
    windows.statistics.Statistics                               Lists statistics about the memory space.
    windows.strings.Strings                                     Reads output from the strings command and indicates which process(es) each string belongs to.
    windows.suspended_threads.SuspendedThreads                  Enumerates suspended threads.
    windows.suspicious_threads.SuspiciousThreads                Lists suspicious userland process threads (deprecated).
    windows.svcdiff.SvcDiff                                     Compares services found through list walking versus scanning to find rootkits (deprecated).
    windows.svclist.SvcList                                     Lists services contained with the services.exe doubly linked list of services
    windows.svcscan.SvcScan                                     Scans for windows services.
    windows.symlinkscan.SymlinkScan                             Scans for links present in a particular windows memory image.
    windows.thrdscan.ThrdScan                                   Scans for windows threads.
    windows.threads.Threads                                     Lists process threads
    windows.timers.Timers                                       Print kernel timers and associated module DPCs
    windows.truecrypt.Passphrase                                TrueCrypt Cached Passphrase Finder
    windows.unhooked_system_calls.unhooked_system_calls         Detects hooked ntdll.dll stub functions in Windows processes (deprecated).
    windows.unloadedmodules.UnloadedModules                     Lists the unloaded kernel modules.
    windows.vadinfo.VadInfo
    windows.verinfo.VerInfo
    windows.virtmap.VirtMap
    windows.Windows
    windows.windowstations.WindowStations
"""
from . import (
    pslist,
)

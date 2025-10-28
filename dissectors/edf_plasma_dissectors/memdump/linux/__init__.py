"""Plasma Linux Memory Dissectors

banners.Banners                                     Attempts to identify potential linux banners in an image
linux.bash.Bash                                     Recovers bash command history from memory.
linux.boottime.Boottime                             Shows the time the system was started
linux.capabilities.Capabilities                     Lists process capabilities
linux.ebpf.EBPF                                     Enumerate eBPF programs
linux.elfs.Elfs                                     Lists all memory mapped ELF files for all processes.
linux.envars.Envars                                 Lists processes with their environment variables
linux.graphics.fbdev.Fbdev                          Extract framebuffers from the fbdev graphics subsystem
linux.iomem.IOMem                                   Generates an output similar to /proc/iomem on a running system.
linux.ip.Addr                                       Lists network interface information for all devices
linux.ip.Link                                       Lists information about network interfaces similar to `ip link show`
linux.kallsyms.Kallsyms                             Kallsyms symbols enumeration plugin.
linux.kmsg.Kmsg                                     Kernel log buffer reader
linux.kthreads.Kthreads                             Enumerates kthread functions
linux.library_list.LibraryList                      Enumerate libraries loaded into processes
linux.lsmod.Lsmod                                   Lists loaded kernel modules.
linux.lsof.Lsof                                     Lists open files for each processes.
linux.malware.check_afinfo.Check_afinfo             Verifies the operation function pointers of network protocols.
linux.malware.check_creds.Check_creds               Checks if any processes are sharing credential structures
linux.malware.check_idt.Check_idt                   Checks if the IDT has been altered
linux.malware.check_modules.Check_modules           Compares module list to sysfs info, if available
linux.malware.check_syscall.Check_syscall           Check system call table for hooks.
linux.malware.hidden_modules.Hidden_modules         Carves memory to find hidden kernel modules
linux.malware.keyboard_notifiers.Keyboard_notifiers Parses the keyboard notifier call chain
linux.malware.malfind.Malfind                       Lists process memory ranges that potentially contain injected code.
linux.malware.modxview.Modxview                     Centralize lsmod, check_modules and hidden_modules results to efficiently spot modules presence and taints.
linux.malware.netfilter.Netfilter                   Lists Netfilter hooks.
linux.malware.tty_check.Tty_Check                   Checks tty devices for hooks
linux.module_extract.ModuleExtract                  Recreates an ELF file from a specific address in the kernel
linux.mountinfo.MountInfo                           Lists mount points on processes mount namespaces
linux.pagecache.Files                               Lists files from memory
linux.pagecache.InodePages                          Lists and recovers cached inode pages
linux.pagecache.RecoverFs                           Recovers the cached filesystem (directories, files, symlinks) into a compressed tarball.
linux.pidhashtable.PIDHashTable                     Enumerates processes through the PID hash table
linux.proc.Maps                                     Lists all memory maps for all processes.
linux.psaux.PsAux                                   Lists processes with their command line arguments
linux.pscallstack.PsCallStack                       Enumerates the call stack of each task
linux.pslist.PsList                                 Lists the processes present in a particular linux memory image.
linux.psscan.PsScan                                 Scans for processes present in a particular linux image.
linux.pstree.PsTree                                 Plugin for listing processes in a tree based on their parent process ID.
linux.ptrace.Ptrace                                 Enumerates ptrace's tracer and tracee tasks
linux.sockstat.Sockstat                             Lists all network connections for all processes.
linux.tracing.ftrace.CheckFtrace                    Detect ftrace hooking
linux.tracing.perf_events.PerfEvents                Lists performance events for each process.
linux.tracing.tracepoints.CheckTracepoints          Detect tracepoints hooking
linux.vmaregexscan.VmaRegExScan                     Scans all virtual memory areas for tasks using RegEx.
linux.vmayarascan.VmaYaraScan                       Scans all virtual memory areas for tasks using yara.
linux.vmcoreinfo.VMCoreInfo                         Enumerate VMCoreInfo tables
"""

from ..helper import VOLATILITY3_AVAILABLE

if VOLATILITY3_AVAILABLE:
    from . import (
        pslist,
    )

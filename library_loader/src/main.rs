/*
 * Copyright (c) 2020, Kurt Cancemi (kurt@x64architecture.com)
 *
 * This file is part of Linux Injector.
 *
 *  Linux Injector is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  Linux Injector is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Linux Injector.  If not, see <http://www.gnu.org/licenses/>.
 */

#![feature(asm)]

use std::{ffi::CStr, ffi::CString, fs::File, io::BufRead, io::BufReader, path::PathBuf};

mod remote_process;
use remote_process::RemoteProcess;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "library_loader", about = "A simple lib loader.")]
struct Opt {
    /// library file
    #[structopt(parse(from_os_str))]
    library: PathBuf,

    /// pid of target process
    #[structopt(short, long)]
    pid: libc::pid_t,
}

// System V Calling Convention
// Parameters to functions are passed in the registers rdi, rsi, rdx, rcx,
// r8, r9, and further values are passed on the stack in reverse order.
// Scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11

// rdi: Path length to the shared object to inject
// rsi: Address of malloc()
// rdx: Address of free()
// rcx: Address of __libc_dlopen_mode()
pub unsafe extern "C" fn inject_shared_library(
    _lib_path_len: usize,
    _malloc_address: std::os::raw::c_long,
    _free_address: std::os::raw::c_long,
    _dlopen_address: std::os::raw::c_long,
) {
    asm!(
        //  -------------------------------------------------------------
        // | Call malloc() to allocate space for the shared library path |
        //  -------------------------------------------------------------

        // Preserve registers
        // Contains address of free()
        "push rdx",
        // Contains address of __libc_dlopen_mode()
        "push rcx",
        // First argument is register rdi (_lib_path_len)
        // Call malloc()
        "call rsi",
        // Breakpoint so we can check the return value of malloc() and copy the
        // shared library path to the newly allocated memory
        "int 3",
        //  ------------------------------------------------------
        // | Call __libc_dlopen_mode() to load the shared library |
        //  ------------------------------------------------------

        // Get the address of __libc_dlopen_mode() back from the stack
        "pop rcx",
        // First argument is register rdi
        // Move pointer (shared library path) returned by malloc to rdi
        "mov rdi, rax",
        // Save the pointer to the allocated space for the shared library path
        "push rdi",
        // Second argument is register rsi
        // Move flag 'RTLD_NOW' into rsi
        "movabs rsi, 1",
        // Call __libc_dlopen_mode()
        "call rcx",
        // Breakpoint so we can check the return value of __libc_dlopen_mode()
        "int 3",
        //  ---------------------------------------------------------------------
        // | Call free() to free the allocated space for the shared library path |
        //  ---------------------------------------------------------------------

        // Get the pointer to the allocated space for the shared library path
        // back from the stack
        "pop rdi",
        // Get the address of free back from the stack
        "pop rdx",
        // Breakpoint
        "int 3",
        // First argument is register rdi (saved previously)
        // Call free()
        "call rdx",
    );
}

pub unsafe extern "C" fn inject_shared_library_end() {}

struct MapEntry {
    start_address: u64,
    permissions: String,
    name: String,
}

impl MapEntry {
    fn from(entry: &str, re: &regex::Regex) -> MapEntry {
        let caps = re.captures(&entry).unwrap();

        let start_address = u64::from_str_radix(&caps[1], 16).unwrap();
        let permissions = caps[3].to_string();
        let name = caps[7].to_string();
        MapEntry {
            start_address,
            permissions,
            name,
        }
    }

    fn is_executable_region(&self) -> bool {
        if self.permissions.contains('x') {
            return true;
        }

        return false;
    }

    fn parse_maps_file(pid: libc::pid_t) -> Vec<MapEntry> {
        let re = regex::Regex::new(
            r"([^-]*)-([^\s]*)\s*([^\s]*)\s*([^\s]*)\s*([^\s]*)\s*([^\s]*)\s*([^\s]*)\s*([^~]*)",
        )
        .unwrap();

        let filename = format!("/proc/{}/maps", pid);
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);
        let mut map_entries = Vec::new();
        for line in reader.lines() {
            map_entries.push(MapEntry::from(&line.unwrap(), &re));
        }
        map_entries
    }
}

fn restore_state_and_detach(
    rp: &RemoteProcess,
    addr: u64,
    orig_bytes: *mut libc::c_void,
    orig_bytes_len: usize,
    orig_regs: &libc::user_regs_struct,
) {
    rp.write(addr, orig_bytes_len, orig_bytes);
    rp.set_regs(orig_regs);
    rp.detach();
}

fn check_remote_signals(rp: &RemoteProcess) -> bool {
    fn signal_to_name(signal: i32) -> &'static str {
        unsafe { CStr::from_ptr(libc::strsignal(signal)).to_str().unwrap() }
    }

    // check the signal that the child stopped with.
    let siginfo: Option<libc::siginfo_t> = rp.get_sig_info();
    match siginfo {
        Some(si) => {
            if si.si_signo != libc::SIGTRAP {
                eprintln!(
                    "[!] Recieved signal '{}' ({}) instead of signal 'SIGTRAP' ({})",
                    signal_to_name(si.si_signo),
                    si.si_signo,
                    libc::SIGTRAP
                );
                return false;
            }
        }
        None => {
            return true;
        }
    };

    return true;
}

fn inject(pid: libc::pid_t, path: &str) -> bool {
    let inject_path: CString = CString::new(path).unwrap();
    let lib_path_length: u64 = path.chars().count() as u64;

    // Locate handle to libc.so.6
    let libc_handle: *mut libc::c_void =
        unsafe { libc::dlopen(CString::new("libc.so.6").unwrap().as_ptr(), libc::RTLD_LAZY) };
    if libc_handle == std::ptr::null_mut::<libc::c_void>() {
        eprintln!("[!] Error obtaining handle to libc.so.6\n");
        return false;
    }
    println!("[*] libc.so.6 handle {:p}", libc_handle);

    // Obtain malloc() function address
    let malloc_address: *mut libc::c_void =
        unsafe { libc::dlsym(libc_handle, CString::new("malloc").unwrap().as_ptr()) };
    if malloc_address == std::ptr::null_mut::<libc::c_void>() {
        eprintln!("[!] Error getting malloc() address!\n");
        return false;
    }
    println!("[*] malloc() found at address {:p}", malloc_address);

    // Obtain free() function address
    let free_address: *mut libc::c_void =
        unsafe { libc::dlsym(libc_handle, CString::new("free").unwrap().as_ptr()) };
    if free_address == std::ptr::null_mut::<libc::c_void>() {
        eprintln!("[!] Error getting free() address!\n");
        return false;
    }
    println!("[*] free() found at address {:p}", free_address);

    let dlopen_address: *mut libc::c_void = unsafe {
        libc::dlsym(
            libc_handle,
            CString::new("__libc_dlopen_mode").unwrap().as_ptr(),
        )
    };
    if dlopen_address == std::ptr::null_mut::<libc::c_void>() {
        eprintln!("[!] Error getting __libc_dlopen_mode() address!\n");
        return false;
    }
    println!(
        "[*] __libc_dlopen_mode() found at address {:p}",
        dlopen_address
    );

    // Process local /proc/{id}/maps
    let local_map_entries: Vec<MapEntry> = MapEntry::parse_maps_file(std::process::id() as i32);
    let mut iter = local_map_entries.iter();
    let local_libc: Option<&MapEntry> = iter.find(|&e| e.name.contains("libc-"));
    let local_libc = match local_libc {
        Some(l) => {
            println!(
                "[*] libc located in local process at address 0x{:x}",
                l.start_address
            );
            l
        }
        None => {
            eprintln!("[!] Failed to find libc in the local process!");
            return false;
        }
    };

    // Calculate libc function offsets
    let malloc_offset = malloc_address as u64 - local_libc.start_address;
    let free_offset = free_address as u64 - local_libc.start_address;
    let dlopen_offset = dlopen_address as u64 - local_libc.start_address;

    // Process remote /proc/{id}/maps
    let remote_map_entries: Vec<MapEntry> = MapEntry::parse_maps_file(pid);
    let mut iter = remote_map_entries.iter();
    let remote_libc: Option<&MapEntry> = iter.find(|&e| e.name.contains("libc-"));
    let remote_libc = match remote_libc {
        Some(r) => {
            println!(
                "[*] libc located in remote process (PID: {}) at address 0x{:x}",
                pid, r.start_address
            );
            r
        }
        None => {
            eprintln!("[!] Failed to find libc in the remote process!");
            return false;
        }
    };

    // Calculate libc function address based on calculated local offsets
    let target_libc_address: u64 = remote_libc.start_address;
    let target_malloc_address: u64 = target_libc_address + malloc_offset;
    let target_free_address: u64 = target_libc_address + free_offset;
    let target_dlopen_address: u64 = target_libc_address + dlopen_offset;

    println!("[*] target_libc_address 0x{:x}", target_libc_address);
    println!("[*] target_malloc_address 0x{:x}", target_malloc_address);
    println!("[*] target_free_address 0x{:x}", target_free_address);
    println!("[*] target_dlopen_address 0x{:x}", target_dlopen_address);

    // Attach to remote process
    let rp: Option<RemoteProcess> = RemoteProcess::attach(pid);
    let rp: RemoteProcess = match rp {
        Some(rp) => rp,
        None => {
            eprintln!("[!] Failed to attach to remote process!");
            return false;
        }
    };

    // Save current registers in the remote process
    let old_regs: Option<libc::user_regs_struct> = rp.get_regs();
    let old_regs: libc::user_regs_struct = match old_regs {
        Some(regs) => regs,
        None => {
            eprintln!("[!] Failed to get registers from remote process!");
            return false;
        }
    };
    let mut regs = old_regs.clone();

    // Find first executable region
    let mut iter = remote_map_entries.iter();
    let executable_region: Option<&MapEntry> = iter.find(|&e| e.is_executable_region());
    let executable_region = match executable_region {
        Some(e) => {
            println!(
                "[*] Located executable region in remote process at address 0x{:x}",
                e.start_address
            );
            e
        }
        None => {
            eprintln!("[!] Failed to find executable region in remote process!");
            return false;
        }
    };
    let remote_injection_address: u64 =
        executable_region.start_address + std::mem::size_of::<libc::c_long>() as u64;

    // call instruction uses two bytes
    regs.rip = remote_injection_address + 2;

    // System V Calling Convention
    // Parameters to functions are passed in the registers rdi, rsi, rdx, rcx,
    // r8, r9, and further values are passed on the stack in reverse order.
    regs.rdi = lib_path_length;
    regs.rsi = target_malloc_address;
    regs.rdx = target_free_address;
    regs.rcx = target_dlopen_address;
    if !rp.set_regs(&regs) {
        eprintln!("[!] Failed to set registers in remote process!");
        return false;
    }

    // Calculate the size of inject_shared_library()
    let inject_shared_library_size =
        inject_shared_library_end as usize - inject_shared_library as usize;

    // Save old bytes of the executable region we want to modify
    let mut old_bytes: Vec<u8> = Vec::new();
    old_bytes.resize(inject_shared_library_size, 0);
    let bytes_read: usize = rp.read(
        remote_injection_address,
        inject_shared_library_size,
        old_bytes.as_mut_ptr() as *mut libc::c_void,
    );
    if bytes_read != inject_shared_library_size {
        eprintln!(
            "[!] Failed to read bytes at address 0x{:x}",
            remote_injection_address
        );
        return false;
    } else {
        println!(
            "[*] Sucessfully read {} bytes at address 0x{:x}",
            bytes_read, remote_injection_address
        );
    }

    // Copy our shellcode to the executable region in the remote process
    let bytes_written: usize = rp.write(
        remote_injection_address,
        inject_shared_library_size,
        inject_shared_library as *mut u8 as *mut libc::c_void,
    );
    if bytes_written < inject_shared_library_size {
        eprintln!(
            "[!] Failed to write bytes to address 0x{:x}",
            remote_injection_address
        );
        return false;
    } else {
        println!(
            "[*] Sucessfully wrote {} bytes to address 0x{:x}",
            bytes_written, remote_injection_address
        );
    }

    // Resume execution of the remote process
    if !rp.cont() {
        eprintln!("Failed to resume execution of the remote process");
        return false;
    }
    // Make sure the target process received SIGTRAP after stopping.
    if !check_remote_signals(&rp) {
        return false;
    }

    // At this stage we are calling allocating a buffer to hold the shared
    // library path

    // Check if malloc() succeded in the remote process
    let malloc_regs: Option<libc::user_regs_struct> = rp.get_regs();
    let malloc_regs: libc::user_regs_struct = match malloc_regs {
        Some(regs) => regs,
        None => {
            eprintln!("Failed to get registers from remote process!");
            return false;
        }
    };
    let target_buffer: u64 = malloc_regs.rax;
    if target_buffer == 0 {
        // Restore registers back to their orginal state and restore the
        // original bytes in the executable section we modified
        restore_state_and_detach(
            &rp,
            remote_injection_address,
            old_bytes.as_mut_ptr() as *mut libc::c_void,
            inject_shared_library_size,
            &old_regs,
        );
        eprintln!("malloc() in the remote process failed to allocate memory");
    }
    println!(
        "[*] malloc() allocation in remote process at address 0x{:x}",
        target_buffer
    );

    // Copy the shared library path to the memory allocated by malloc in the
    // remote process
    let bytes_written: usize = rp.write(
        target_buffer,
        lib_path_length as usize,
        inject_path.as_ptr() as *mut libc::c_void,
    );
    if bytes_written < lib_path_length as usize {
        eprintln!("[!] Failed to write bytes to address 0x{:x}", target_buffer);
        return false;
    } else {
        println!(
            "[*] Sucessfully wrote {} bytes to address 0x{:x}",
            bytes_written, target_buffer
        );
    }

    // Resume execution of the remote process
    if !rp.cont() {
        eprintln!("Failed to resume execution of the remote process");
        return false;
    }
    // Make sure the target process received SIGTRAP after stopping.
    if !check_remote_signals(&rp) {
        return false;
    }

    // At this stage we are calling __libc_dlopen_mode(path, RTLD_NOW)

    // Check if __libc_dlopen_mode() succeded in the remote process
    let dlopen_regs: Option<libc::user_regs_struct> = rp.get_regs();
    let dlopen_regs: libc::user_regs_struct = match dlopen_regs {
        Some(regs) => regs,
        None => {
            eprintln!("Failed to get registers from remote process!");
            return false;
        }
    };
    let library_handle: u64 = dlopen_regs.rax;
    if library_handle == 0 {
        // Restore registers back to their orginal state and restore the
        // original bytes in the executable section we modified
        restore_state_and_detach(
            &rp,
            remote_injection_address,
            old_bytes.as_mut_ptr() as *mut libc::c_void,
            inject_shared_library_size,
            &old_regs,
        );
        eprintln!("__libc_dlopen_mode() failed to load");
        return false;
    }
    println!(
        "[*] Handle to shared library injected into remote process 0x{:x}",
        library_handle
    );

    // At this stage we are freeing the memory allocated for the shared
    // library path

    // Resume execution of the remote process
    if !rp.cont() {
        eprintln!("Failed to resume execution of the remote process");
        return false;
    }
    // Make sure the target process received SIGTRAP after stopping.
    if !check_remote_signals(&rp) {
        return false;
    }

    // Restore registers back to their orginal state and restore the
    // original bytes in the executable section we modified
    restore_state_and_detach(
        &rp,
        remote_injection_address,
        old_bytes.as_mut_ptr() as *mut libc::c_void,
        inject_shared_library_size,
        &old_regs,
    );

    return true;
}

fn main() {
    let opt = Opt::from_args();

    let path = opt.library.to_str();
    let path = match path {
        Some(p) => p,
        None => {
            panic!("Failed to convert PathBuf");
        }
    };

    if inject(opt.pid, &path) {
        println!("[*] Sucessfully injected '{}' into PID: {}", path, opt.pid);
    } else {
        eprintln!("[!] Failed to inject '{}' into PID: {}", path, opt.pid)
    }
}

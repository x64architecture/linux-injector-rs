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

use std::{thread, time};

pub(crate) struct RemoteProcess {
    pid: libc::pid_t,
}

impl RemoteProcess {
    pub(crate) fn attach(pid: i32) -> Option<RemoteProcess> {
        let mut waitpidstatus: libc::c_int = 0;

        if unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) == -1 } {
            return None;
        }

        if unsafe { libc::waitpid(pid, &mut waitpidstatus, libc::WUNTRACED) != pid } {
            return None;
        }
        Some(RemoteProcess { pid })
    }

    pub(crate) fn detach(&self) -> bool {
        if unsafe { libc::ptrace(libc::PTRACE_DETACH, self.pid, 0, 0) == -1 } {
            return false;
        }

        return true;
    }

    pub(crate) fn get_regs(&self) -> Option<libc::user_regs_struct> {
        let regs = unsafe { std::mem::zeroed::<libc::user_regs_struct>() };
        if unsafe { libc::ptrace(libc::PTRACE_GETREGS, self.pid, 0, &regs) == -1 } {
            return None;
        }
        Some(regs)
    }

    pub(crate) fn set_regs(&self, regs: &libc::user_regs_struct) -> bool {
        if unsafe { libc::ptrace(libc::PTRACE_SETREGS, self.pid, 0, regs) == -1 } {
            return false;
        }
        return true;
    }

    pub(crate) fn get_sig_info(&self) -> Option<libc::siginfo_t> {
        let siginfo: libc::siginfo_t = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        if unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, self.pid, 0, &siginfo) == -1 } {
            return None;
        }
        Some(siginfo)
    }

    pub(crate) fn cont(&self) -> bool {
        if unsafe { libc::ptrace(libc::PTRACE_CONT, self.pid, 0, 0) == -1 } {
            return false;
        }

        thread::sleep(time::Duration::from_millis(5));

        return true;
    }

    pub(crate) fn read(&self, address: u64, len: usize, buf: *mut libc::c_void) -> usize {
        let mut bytes_read: usize = 0;
        let mut i: isize = 0;
        let word_ptr: *mut libc::c_long = buf as *mut libc::c_long;

        while bytes_read < len {
            unsafe {
                *word_ptr.offset(i) = libc::ptrace(
                    libc::PTRACE_PEEKTEXT,
                    self.pid,
                    address as usize + bytes_read,
                    0,
                );
                if *word_ptr.offset(i) == -1 {
                    break;
                }
            }
            bytes_read += std::mem::size_of::<libc::c_long>();
            i += 1;
        }

        return bytes_read;
    }

    pub(crate) fn write(&self, address: u64, len: usize, buf: *mut libc::c_void) -> usize {
        let mut byte_count: usize = 0;

        while byte_count < len {
            unsafe {
                let word_ptr: *mut libc::c_long = buf.add(byte_count) as *mut libc::c_long;
                if libc::ptrace(
                    libc::PTRACE_POKETEXT,
                    self.pid,
                    address as usize + byte_count,
                    *word_ptr,
                ) == -1
                {
                    break;
                }
            }
            byte_count += std::mem::size_of::<libc::c_long>();
        }

        return byte_count;
    }
}

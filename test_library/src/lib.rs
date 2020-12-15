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

#[used]
#[cfg_attr(any(target_os = "linux"), link_section = ".init_array")]
static TEST_LIBRARY: extern "C" fn() = {
    #[cfg_attr(any(target_os = "linux"), link_section = ".text.startup")]
    extern "C" fn initialize_test_library() {
        // Avoid dependency on libc crate
        extern "C" {
            fn puts(s: *const std::os::raw::c_char) -> std::os::raw::c_int;
        }
        unsafe { puts("Hello from Test Library!\0".as_ptr() as *const i8) };
    };
    initialize_test_library
};

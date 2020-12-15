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

fn main() {
    loop {
        println!("Sleeping...");
        thread::sleep(time::Duration::from_secs(1));
    }
}

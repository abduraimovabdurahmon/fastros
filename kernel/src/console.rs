//! The serial console as a terminal (`/dev/console`, `ttyS0`) with a
//! login prompt (getty), for access without networking.

use crate::errno::KResult;
use crate::fs::file::flags;
use crate::sync::Once;
use crate::tty::{Tty, TtyDriver, TtyFile, WinSize};
use alloc::string::String;
use alloc::sync::Arc;

static CONSOLE: Once<Arc<Tty>> = Once::new();

struct SerialDriver;

impl TtyDriver for SerialDriver {
    fn write(&self, data: &[u8], _echo: bool) -> KResult<()> {
        crate::drivers::serial::write_verbatim(data);
        Ok(())
    }
}

pub fn tty() -> Option<Arc<Tty>> {
    CONSOLE.get().cloned()
}

fn serial_irq() {
    while let Some(b) = crate::drivers::serial::read_byte() {
        if let Some(t) = CONSOLE.get() {
            t.receive(&[b]);
        }
    }
}

pub fn init() {
    let t = Tty::new("console", Arc::new(SerialDriver), WinSize { rows: 24, cols: 80, xpixel: 0, ypixel: 0 });
    CONSOLE.call_once(|| t);
    crate::drivers::serial::enable_rx_irq();
    crate::trap::register_irq(4, serial_irq);
}

/// Login prompt on the console: authenticate, run a login shell, repeat.
pub fn start_getty() {
    crate::sched::spawn("getty", || loop {
        let Some(tty) = tty() else { return };
        let _ = tty.write(alloc::format!("\nFastROS {} {}\n\n", crate::VERSION, crate::proc::host_uts().hostname.lock()).as_bytes());
        let _ = tty.write(b"login: ");
        let name = read_line(&tty, true);
        if name.is_empty() {
            continue;
        }
        let _ = tty.write(b"Password: ");
        let pw = read_line(&tty, false);
        let _ = tty.write(b"\n");
        let user = match crate::users::authenticate(&name, &pw) {
            Ok(u) => u,
            Err(_) => {
                crate::sched::sleep_ms(2000);
                let _ = tty.write(b"Login incorrect\n");
                continue;
            }
        };
        crate::kinfo!("login", "{} logged in on console", user.name);
        let kernel = crate::proc::kernel();
        let mut fds = crate::proc::fdtable::FdTable::new();
        let f: Arc<dyn crate::fs::file::File> = TtyFile::new(tty.clone(), flags::O_RDWR);
        for fd in 0..3 {
            fds.set(fd, f.clone(), false);
        }
        let spawn = crate::proc::Spawn {
            name: String::from("-sh"),
            args: alloc::vec![String::from("-sh")],
            env: alloc::vec![(String::from("TERM"), String::from("vt100")), (String::from("PATH"), String::from("/bin:/usr/local/bin"))],
            cred: crate::users::cred_for(&user),
            fs: kernel.fs.lock().clone(),
            fds,
            parent: kernel.clone(),
            pgid: None,
            new_session: true,
            ctty: Some(tty.clone()),
            uts: kernel.uts.clone(),
            container: None,
            ignored: 0,
        };
        let u = user.clone();
        if let Ok(p) = crate::proc::spawn(spawn, move || crate::shell::login_shell_main(u)) {
            tty.set_session(p.pid);
            tty.set_fg_pgrp(p.pid);
            crate::utmp::login(crate::utmp::Session {
                user: user.name.clone(),
                tty: tty.name.clone(),
                from: String::new(),
                login_unix: crate::time::unix_now(),
                pid: p.pid,
            });
            if let Some(t) = p.tasks().into_iter().next() {
                t.join();
            }
            crate::utmp::logout(p.pid);
        }
    });
}

fn read_line(tty: &Arc<Tty>, echo: bool) -> String {
    let saved = tty.termios();
    let mut t = saved;
    if !echo {
        t.lflag &= !crate::tty::consts::ECHO;
    }
    tty.set_termios(t);
    let mut buf = [0u8; 256];
    let n = tty.read(&mut buf, false).unwrap_or(0);
    tty.set_termios(saved);
    String::from_utf8_lossy(&buf[..n]).trim_end_matches(['\n', '\r']).into()
}

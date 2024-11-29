use libc::pid_t;
use std::io::Error;
// use std::io::RawOsError;

use super::wait;
use super::wait::waitpid;

fn ptrace(
    request: libc::c_uint,
    pid: pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<(), std::io::Error> {
    unsafe {
        match libc::ptrace(request, pid, addr, data) {
            0 => Ok(()),
            _ => Err(Error::last_os_error()),
        }
    }
}

#[allow(dead_code)]
pub fn traceme() -> Result<(), Error> {
    ptrace(
        libc::PTRACE_TRACEME,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

pub fn attach(pid: pid_t) -> Result<(), Error> {
    ptrace(
        libc::PTRACE_ATTACH,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

pub fn detach(pid: pid_t) {
    let _ = ptrace(
        libc::PTRACE_DETACH,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
}

pub fn syscall(pid: pid_t) -> Result<(), Error> {
    ptrace(
        libc::PTRACE_SYSCALL,
        pid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

pub fn peekdata(pid: pid_t, addr: *mut libc::c_void) -> Result<libc::c_long, Error> {
    unsafe {
        *libc::__errno_location() = 0;
        let res = libc::ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            addr,
            std::ptr::null_mut::<libc::c_void>(),
        );
        if res == -1 && *libc::__errno_location() != 0 {
            return Err(Error::last_os_error());
        }
        Ok(res)
    }
}

pub fn pokedata(pid: pid_t, addr: *mut libc::c_void, data: u64) -> Result<(), Error> {
    ptrace(libc::PTRACE_POKEDATA, pid, addr, data as *mut libc::c_void)
}

pub struct Tracee {
    pid: pid_t,
}

impl Tracee {
    pub fn new(pid: pid_t) -> Self {
        Self { pid }
    }

    pub fn new_wait(pid: pid_t) -> Result<Self, Error> {
        let res = waitpid(pid)?;
        if let wait::WaitStatus::Stopped(_) = res {
            return Ok(Self { pid });
        }
        Err(Error::from_raw_os_error(libc::ECHILD))
    }

    pub fn new_attach(pid: pid_t) -> Result<Self, Error> {
        attach(pid)?;
        let res = waitpid(pid)?;
        if let wait::WaitStatus::Stopped(_) = res {
            return Ok(Self { pid });
        }
        Err(Error::from_raw_os_error(libc::ECHILD))
    }

    pub fn wait(&self) -> Result<wait::WaitStatus, Error> {
        waitpid(self.pid)
    }

    pub fn kill(&self) -> Result<(), Error> {
        unsafe {
            if libc::kill(self.pid, libc::SIGKILL) == 0 {
                return Ok(());
            }
            return Err(Error::last_os_error());
        };
    }

    pub fn syscall(&self) -> Result<(), Error> {
        ptrace(
            libc::PTRACE_SYSCALL,
            self.pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }

    pub fn cont(&self) -> Result<(), Error> {
        ptrace(
            libc::PTRACE_CONT,
            self.pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }

    pub fn singlestep(&self) -> Result<(), Error> {
        ptrace(
            libc::PTRACE_SINGLESTEP,
            self.pid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }

    pub fn cont_signal(&self, signal: libc::c_int) -> Result<(), Error> {
        ptrace(
            libc::PTRACE_CONT,
            self.pid,
            std::ptr::null_mut(),
            signal as *mut libc::c_void,
        )
    }

    pub fn getregs(&self) -> Result<libc::user_regs_struct, Error> {
        let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        ptrace(
            libc::PTRACE_GETREGS,
            self.pid,
            std::ptr::null_mut(),
            regs.as_mut_ptr() as *mut libc::c_void,
        )?;
        Ok(unsafe { regs.assume_init() })
    }

    pub fn getsiginfo(&self) -> Result<libc::siginfo_t, Error> {
        let mut siginfo = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        ptrace(
            libc::PTRACE_GETSIGINFO,
            self.pid,
            std::ptr::null_mut(),
            siginfo.as_mut_ptr() as *mut libc::c_void,
        )?;
        Ok(unsafe { siginfo.assume_init() })
    }

    pub fn peekdata(&self, addr: *mut libc::c_void) -> Result<u64, Error> {
        peekdata(self.pid, addr).map(|x| x as u64)
    }

    pub fn pokedata(&self, addr: *mut libc::c_void, data: u64) -> Result<(), Error> {
        pokedata(self.pid, addr, data)
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        detach(self.pid);
    }
}

struct StoppedStatus {
    regs: libc::user_regs_struct,
    signal: libc::c_int,
}

pub struct Debuggee {
    tracee: Tracee,
    last_regs: Option<libc::user_regs_struct>,
    last_signal: Option<libc::siginfo_t>,
    breakpoint: Option<*mut libc::c_void>,
    breakpoint_data: Option<u64>,
}

impl Debuggee {
    pub fn new(pid: pid_t) -> Result<Self, Error> {
        let tracee = Tracee::new(pid);
        Ok(Self {
            tracee,
            last_regs: None,
            last_signal: None,
            breakpoint: None,
            breakpoint_data: None,
        })
    }

    pub fn wait(&mut self) -> Result<wait::WaitStatus, Error> {
        let status = self.tracee.wait()?;
        if let wait::WaitStatus::Stopped(_) = status {
            let regs = self.tracee.getregs()?;
            let siginfo = self.tracee.getsiginfo()?;
            self.last_regs = Some(regs);
            self.last_signal = Some(siginfo);
        }
        Ok(status)
    }

    pub fn cont(&mut self) -> Result<(), Error> {
        if let Some(regs) = self.last_regs {
            if let Some(bp) = self.breakpoint {
                if regs.rip == bp as u64 + 1 {
                    todo!("restore breakpoint");
                }
            }
        }

        if let Some(siginfo) = self.last_signal {
            if siginfo.si_signo != libc::SIGTRAP {
                return self.tracee.cont_signal(siginfo.si_signo);
            }
        }
        self.tracee.cont()
    }

    pub fn set_break_point(&mut self, address: *mut libc::c_void) -> Result<(), Error> {
        let data = self.tracee.peekdata(address)?;
        self.tracee.pokedata(address, (data & !0xff) | 0xcc)?;
        self.breakpoint = Some(address);
        self.breakpoint_data = Some(data);
        Ok(())
    }
}

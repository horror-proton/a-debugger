use libc::pid_t;
use std::io::Error;

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

    pub fn setregs(&self, regs: &libc::user_regs_struct) -> Result<(), Error> {
        ptrace(
            libc::PTRACE_SETREGS,
            self.pid,
            std::ptr::null_mut(),
            regs as *const libc::user_regs_struct as *mut libc::c_void,
        )
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

pub struct Debuggee {
    tracee: Tracee,
    last_status: Option<(libc::user_regs_struct, libc::siginfo_t)>,
    breakpoints: std::collections::HashMap<*mut libc::c_void, u64>,
}

impl Debuggee {
    pub fn new(pid: pid_t) -> Result<Self, Error> {
        let tracee = Tracee::new(pid);
        Ok(Self {
            tracee,
            last_status: None,
            breakpoints: std::collections::HashMap::new(),
        })
    }

    pub fn wait(&mut self) -> Result<wait::WaitStatus, Error> {
        let status = self.tracee.wait()?;
        if let wait::WaitStatus::Stopped(_) = status {
            let regs = self.tracee.getregs()?;
            let siginfo = self.tracee.getsiginfo()?;
            self.last_status = Some((regs, siginfo));
        }
        Ok(status)
    }

    pub fn cont(&mut self) -> Result<(), Error> {
        let regs = self.last_status.unwrap().0;
        if let Some((&addr, &orig_data)) = self
            .breakpoints
            .get_key_value(&((regs.rip - 1) as *mut libc::c_void))
        {
            eprintln!("resuming from breakpoint at {:?}", addr);
            let mut new_regs = regs.clone();
            new_regs.rip -= 1;
            self.tracee.setregs(&new_regs)?;
            self.tracee.pokedata(addr, orig_data)?;
            self.tracee.singlestep()?;
            self.tracee.wait()?; // TODO: assert == Stopped(SIGTRAP)
            self.tracee.pokedata(addr, (orig_data & !0xff) | 0xcc)?;
        }

        if let Some((_, siginfo)) = self.last_status {
            if siginfo.si_signo != libc::SIGTRAP {
                return self.tracee.cont_signal(siginfo.si_signo);
            }
        }
        self.tracee.cont()
    }

    pub fn set_break_point(&mut self, address: *mut libc::c_void) -> Result<(), Error> {
        // TODO: what if another breakpoint is too close and overlaps?
        if !self.breakpoints.contains_key(&address) {
            let data = self.tracee.peekdata(address)?;
            self.tracee.pokedata(address, (data & !0xff) | 0xcc)?;
            self.breakpoints.insert(address, data);
        }
        Ok(())
    }
}

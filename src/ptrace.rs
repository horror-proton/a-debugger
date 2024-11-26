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

pub fn pokedata(pid: pid_t, addr: *mut libc::c_void, data: libc::c_long) -> Result<(), Error> {
    ptrace(libc::PTRACE_POKEDATA, pid, addr, data as *mut libc::c_void)
}

pub struct Tracee {
    pid: pid_t,
}

impl Tracee {
    pub fn new(pid: pid_t) -> Result<Self, Error> {
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

    pub fn drop(self) {
        detach(self.pid);
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

    pub fn peekdata(&self, addr: *mut libc::c_void) -> Result<libc::c_long, Error> {
        peekdata(self.pid, addr)
    }

    pub fn pokedata(&self, addr: *mut libc::c_void, data: libc::c_long) -> Result<(), Error> {
        pokedata(self.pid, addr, data)
    }
}

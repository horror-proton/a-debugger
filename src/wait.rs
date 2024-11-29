use std::io::Error;
use std::io::ErrorKind;

pub fn waitpid_impl(pid: libc::pid_t) -> Result<libc::c_int, Error> {
    unsafe {
        let mut status = 0;
        match libc::waitpid(pid, &mut status, 0) {
            -1 => Err(Error::last_os_error()),
            _ => Ok(status),
        }
    }
}

#[derive(Debug)]
pub enum WaitStatus {
    Exited(i32),
    Signaled(i32),
    Stopped(i32),
    Continued,
    CoreDump,
}

impl WaitStatus {
    pub fn from(status: libc::c_int) -> Result<WaitStatus, Error> {
        if libc::WIFEXITED(status) {
            Ok(WaitStatus::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            if libc::WCOREDUMP(status) {
                Ok(WaitStatus::CoreDump)
            } else {
                Ok(WaitStatus::Signaled(libc::WTERMSIG(status)))
            }
        } else if libc::WIFSTOPPED(status) {
            Ok(WaitStatus::Stopped(libc::WSTOPSIG(status)))
        } else if libc::WIFCONTINUED(status) {
            Ok(WaitStatus::Continued)
        } else {
            Err(Error::new(ErrorKind::Other, "Unknown wait status"))
        }
    }
}

pub fn waitpid(pid: libc::pid_t) -> Result<WaitStatus, Error> {
    WaitStatus::from(waitpid_impl(pid)?)
}

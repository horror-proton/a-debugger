mod ptrace;
mod wait;
use std::io::Error;

fn main() -> Result<(), Error> {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        args.push(std::ffi::OsString::from("./a.out"));
    }

    let child = unsafe { libc::fork() };
    if child < 0 {
        eprintln!("fork failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    if child == 0 {
        ptrace::traceme().unwrap();
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(args[0].to_str().unwrap())
            .args(&args[1..])
            .exec();
        return Err(err);
    }

    let tracee = ptrace::Tracee::new(child)?;

    let foo_addr = 0x555555555149 as *mut libc::c_void;

    // tracee.pokedata(foo_addr, 0xccccccccccccccc)?;
    let data = tracee.peekdata(foo_addr)?;
    println!("data at {:?}: {:#16x}", foo_addr, data);

    tracee.syscall()?;

    while let Ok(status) = wait::waitpid(child) {
        if let wait::WaitStatus::Exited(s) = status {
            println!("child exited with status: {}", s);
            tracee.drop();
            break;
        }
        let regs = tracee.getregs()?;
        let rax = regs.orig_rax;
        let rip = regs.rip;
        println!("child syscall: {} at {:x}, continuing...", rax, rip);

        // tracee.kill()?;
        tracee.cont()?;
    }
    Ok(())
}

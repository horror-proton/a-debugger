mod elfread;
mod procfs;
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

    let mut debuggee = ptrace::Debuggee::new(child)?;
    debuggee.wait()?;

    let maps = procfs::parse_maps(&std::path::Path::new("/proc").join(child.to_string()));
    for map in maps {
        if let Some(path) = map.path {
            println!("path: {:?}", path);
            elfread::elf_get_symtab(path.as_path());
        }
    }

    debuggee.set_break_point(0x555555555159 as *mut libc::c_void)?;
    debuggee.set_break_point(0x55555555516f as *mut libc::c_void)?;

    loop {
        debuggee.cont()?;
        let status = debuggee.wait()?;
        println!("status: {:?}", status);
        if let wait::WaitStatus::Stopped(_) = status {
        } else {
            break;
        }
    }
    Ok(())
}

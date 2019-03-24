use libc::{self, c_char, c_void, pid_t};
use std::ffi::CString;
use std::mem::transmute;
use std::thread;

#[derive(Debug)]
enum Error {
    Io(::std::io::Error),
    Nix(::nix::Error),
    Msg(String),
}

impl From<::std::io::Error> for Error {
    fn from(v: ::std::io::Error) -> Error {
        Error::Io(v)
    }
}

impl From<::nix::Error> for Error {
    fn from(v: ::nix::Error) -> Error {
        Error::Nix(v)
    }
}

const REMOTE_MEM_SIZE: u32 = 0x11000;
const LIBC_PATH: &str = "/system/lib/libc.so";
const LINKER_PATH: &str = "/system/bin/linker";
const INJECT_LIB_PATH: &str = "/vendor/libyyxbridge_x86.so";
const PACKAGE_NAMES: &[&str] = &[
    "com.netease.onmyoji.netease_simulator",
    "com.netease.onmyoji",
];

#[cfg(not(debug_assertions))]
macro_rules! debug {
    ($($expr:expr),*) => {
        ()
    };
}

#[cfg(debug_assertions)]
macro_rules! debug {
  ($fmt:literal) => {
    println!($fmt)
  };

  ($fmt:literal, $($args:expr),+) => {
    println!($fmt, $($args),*)
  };
}

#[allow(unused)]
#[cfg(feature = "android")]
extern "C" {
    fn get_code_length() -> u32;
    fn get_code_addr() -> extern "C" fn() -> u32;
    fn ptrace_attach(pid: pid_t) -> bool;
    fn ptrace_detach(pid: pid_t) -> bool;
    fn ptrace_new_regs() -> *const c_void;
    fn ptrace_clone_regs(regs: *const c_void) -> *const c_void;
    fn ptrace_get_regs(pid: pid_t, regs: *const c_void) -> bool;
    fn ptrace_set_regs(pid: pid_t, regs: *const c_void) -> bool;
    fn ptrace_get_esp(regs: *const c_void) -> u32;
    fn ptrace_free_regs(regs: *const c_void);
    fn ptrace_read(pid: pid_t, addr: *const c_void, buf: *mut c_void, buf_size: i32) -> bool;
    fn ptrace_write(pid: pid_t, addr: *const c_void, buf: *const c_void, buf_size: i32) -> bool;
    fn ptrace_system_call(
        pid: pid_t,
        addr: *const c_void,
        args: *const u32,
        argc: u32,
        regs: *const c_void,
        rv: *mut u32,
    ) -> bool;
    fn remote_load_lib(params: *const RemoteLoadLibParams) -> bool;
}

fn get_proc_cmdline(pid: pid_t) -> Result<String, Error> {
    use std::fs;
    let path = format!("/proc/{}/cmdline", pid);
    Ok(fs::read(path).map(|data| {
        String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_string()
    })?)
}

#[derive(Debug)]
struct Process {
    pid: pid_t,
    cmdline: String,
}

fn list_procs() -> Result<Vec<Process>, Error> {
    use std::fs;
    let mut r = vec![];
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;

        let pid = if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<pid_t>().ok())
        {
            pid
        } else {
            continue;
        };

        let cmdline = if let Ok(cmdline) = get_proc_cmdline(pid) {
            cmdline
        } else {
            continue;
        };

        if !cmdline.is_empty() {
            // debug!("cmdline = {}", cmdline);
            r.push(Process { pid, cmdline })
        }
    }
    Ok(r)
}

fn find_target_pid() -> Result<Option<pid_t>, Error> {
    let procs = list_procs()?;
    Ok(procs
        .iter()
        .find(|p| PACKAGE_NAMES.contains(&(&p.cmdline as &str)))
        .map(|p| p.pid))
}

fn parse_lib_base_addr(maps: &str, path: &str) -> Option<(u32, u32)> {
    for line in maps.lines() {
        let columns = line.split_whitespace().collect::<Vec<&str>>();
        if columns.len() == 6 {
            let lib_path = columns[5];
            if lib_path == path {
                let range: Vec<_> = columns[0]
                    .split('-')
                    .filter_map(|addr| u32::from_str_radix(addr, 16).ok())
                    .collect();
                if range.len() == 2 {
                    debug!("lib base: {} 0x{:x} - 0x{:x}", path, range[0], range[1]);
                    return Some((range[0], range[1]));
                }
            }
        }
    }
    None
}

fn get_proc_lib_base(pid: pid_t, path: &str) -> Result<Option<u32>, Error> {
    use std::fs;
    let maps = fs::read(format!("/proc/{}/maps", pid))?;
    let maps = String::from_utf8_lossy(&maps);
    Ok(parse_lib_base_addr(&maps, path).map(|(s, _)| s))
}

#[derive(Debug)]
struct Lib {
    path: String,
    range_start: u32,
    range_end: u32,
}

fn get_proc_libs(pid: pid_t) -> Result<Vec<Lib>, Error> {
    use std::fs;
    let maps = fs::read(format!("/proc/{}/maps", pid))?;
    let maps = String::from_utf8_lossy(&maps);
    Ok(maps
        .lines()
        .filter_map(|line| {
            let columns = line.split_whitespace().collect::<Vec<&str>>();
            if columns.len() == 6 {
                let range: Vec<_> = columns[0]
                    .split('-')
                    .filter_map(|addr| u32::from_str_radix(addr, 16).ok())
                    .collect();
                if range.len() == 2 {
                    let path = columns[5];
                    return Some(Lib {
                        path: path.to_string(),
                        range_start: range[0],
                        range_end: range[1],
                    });
                }
            }
            None
        })
        .collect())
}

#[repr(C)]
struct RemoteLoadLibParams {
    pid: pid_t,
    regs: *const c_void,
    mem: *const c_void,
    mem_size: u32,
    dlopen_addr: *const c_void,
    lib_path: *const c_char,
    flags: i32,
}

fn main() {
    if let Err(err) = run() {
        let msg = match err {
            Error::Io(io) => format!("io: {}", io),
            Error::Nix(nix) => format!("system: {}", nix),
            Error::Msg(msg) => msg,
        };
        print!(r#"{{"error":"{}"}}"#, msg.replace("\"", "\\\""))
    }
    cleanup_files();
}

fn run() -> Result<(), Error> {
    extract_files()?;

    unsafe {
        let self_pid = libc::getpid();

        let pid =
            find_target_pid()?.ok_or_else(|| Error::Msg(format!("YYS process was not found.")))?;
        debug!("pid = {}", pid);

        let pipe_worker = thread::spawn(move || wait_data(pid));

        let local_libc_base = get_proc_lib_base(self_pid, LIBC_PATH)?
            .ok_or_else(|| Error::Msg(format!("Local libc was not found.")))?;

        debug!("local libc base = 0x{:x}", local_libc_base);

        let remote_libc_base = get_proc_lib_base(pid, LIBC_PATH)?
            .ok_or_else(|| Error::Msg(format!("Remote libc was not found.")))?;
        debug!("remote libc base = 0x{:x}", remote_libc_base);

        let local_linker_base = get_proc_lib_base(self_pid, LINKER_PATH)?
            .ok_or_else(|| Error::Msg(format!("Local linker was not found.")))?;

        debug!("local linker base = 0x{:x}", local_linker_base);

        let remote_linker_base = get_proc_lib_base(pid, LINKER_PATH)?
            .ok_or_else(|| Error::Msg(format!("Remote linker was not found.")))?;

        debug!("remote linker base = 0x{:x}", remote_linker_base);

        let libc_lib_path = CString::new(LIBC_PATH).unwrap();
        let local_libc = libc::dlopen(libc_lib_path.as_ptr(), libc::RTLD_LAZY);

        let dlopen_symbol = CString::new("dlopen").unwrap();
        let dlopen = libc::dlsym(local_libc, dlopen_symbol.as_ptr());
        debug!("dlopen: 0x{:x}", dlopen as u32);

        let remote_dlopen_addr: u32 = remote_linker_base + (dlopen as u32 - local_linker_base);
        debug!("remote_dlopen_addr: 0x{:x}", remote_dlopen_addr);

        let mmap_symbol = CString::new("mmap").unwrap();
        let mmap = libc::dlsym(local_libc, mmap_symbol.as_ptr());
        debug!("mmap: 0x{:x}", mmap as u32);
        debug!("mmap lib: {:?}", {
            let mmap_addr = mmap as u32;
            get_proc_libs(self_pid)?
                .iter()
                .find(|l| l.range_start <= mmap_addr && l.range_end > mmap_addr)
        });

        let remote_mmap_addr: u32 = remote_libc_base + (mmap as u32 - local_libc_base);
        debug!("remote_mmap_addr: 0x{:x}", remote_mmap_addr);

        #[cfg(debug_asserts)]
        {
            let remote_libs = get_proc_libs(pid)?;
            debug!("remote mmap lib: {:?}", {
                remote_libs
                    .iter()
                    .find(|l| l.range_start <= remote_mmap_addr && l.range_end > remote_mmap_addr)
            });
        }

        assert!(ptrace_attach(pid));
        debug!("ptrace attached");

        let regs = ptrace_new_regs();
        if !ptrace_get_regs(pid.into(), regs) {
            panic!("ptrace get regs failed.");
        }

        let mut remote_buffer: u32 = 0;

        let mmap_args: [u32; 6] = [
            0,
            REMOTE_MEM_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32,
            (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u32,
            0,
            0,
        ];

        assert!(ptrace_system_call(
            pid,
            transmute(remote_mmap_addr),
            &mmap_args as *const u32,
            mmap_args.len() as u32,
            regs,
            &mut remote_buffer as *mut u32,
        ));

        debug!("mmap called, remote_buffer = 0x{:x}", remote_buffer);

        let lib_path = CString::new(INJECT_LIB_PATH).unwrap();
        assert!(remote_load_lib(&RemoteLoadLibParams {
            pid,
            regs,
            mem: transmute(remote_buffer),
            mem_size: REMOTE_MEM_SIZE,
            dlopen_addr: transmute(remote_dlopen_addr),
            lib_path: lib_path.as_ptr(),
            flags: libc::RTLD_LAZY,
        }));

        assert!(ptrace_set_regs(pid, regs));

        assert!(ptrace_detach(pid));
        debug!("ptrace detached");

        ptrace_free_regs(regs);

        let data = pipe_worker.join().unwrap()?;
        print!("{}", data);

        libc::kill(pid, libc::SIGKILL);
    }

    Ok(())
}

fn wait_data(pid: pid_t) -> Result<String, Error> {
    use nix::sys::stat::Mode;
    use nix::unistd;
    use std::fs;
    let fifo_path = format!("/data/local/tmp/yyx_{}.pipe", pid);
    unistd::mkfifo(
        &fifo_path as &str,
        Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO,
    )?;
    debug!("waiting fifo: {}", fifo_path);
    let content = fs::read_to_string(&fifo_path)?;
    fs::remove_file(&fifo_path)?;
    Ok(content)
}

#[cfg(debug_assertions)]
fn extract_files() -> Result<(), Error> {
    Ok(())
}

#[cfg(debug_assertions)]
fn cleanup_files() {}

#[cfg(not(debug_assertions))]
const INJECT_LIB_ARM_PATH: &str = "/vendor/libyyxbridge_arm.so";

#[cfg(not(debug_assertions))]
fn extract_files() -> Result<(), Error> {
    use std::fs;
    fs::remove_file(INJECT_LIB_PATH).ok();
    fs::remove_file(INJECT_LIB_ARM_PATH).ok();
    fs::write(
        INJECT_LIB_PATH,
        include_bytes!("../bridge-x86/target/i686-linux-android/release/libbridge_x86.so")
            as &[u8],
    )?;
    fs::write(
        INJECT_LIB_ARM_PATH,
        include_bytes!("../bridge-arm/target/armv7-linux-androideabi/release/libbridge_arm.so")
            as &[u8],
    )?;
    Ok(())
}

#[cfg(not(debug_assertions))]
fn cleanup_files() {
    use std::fs;
    use std::time::Duration;

    for _ in 0..3 {
        if fs::remove_file(INJECT_LIB_PATH)
            .ok()
            .into_iter()
            .chain(fs::remove_file(INJECT_LIB_ARM_PATH).ok().into_iter())
            .count()
            == 2
        {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

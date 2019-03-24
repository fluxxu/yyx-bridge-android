use libc::*;
use std::ffi::{CString};
use std::mem::transmute;
use std::io::Error;

mod assets;

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
#[allow(non_camel_case_types)]
type PyGILState_Ensure = extern "C" fn() -> *const ();
#[allow(non_camel_case_types)]
type PyGILState_Release = extern "C" fn(*const ());
#[allow(non_camel_case_types)]
type PyRun_SimpleStringFlags = extern "C" fn(*const c_char, i32) -> i32;

#[no_mangle]
extern "C" fn _init() {
  unsafe {
    debug!("bridge init.");

    let pid = getpid();
    let path = if let Ok(Some(path)) = get_lib_path(pid, "lib/arm/libclient.so") {
      path
    } else {
      return fail(pid, "Resolve lib path failed.")
    };

    let path = CString::new(path).unwrap();
    let handle = dlopen(path.as_ptr(), libc::RTLD_LAZY);
    debug!("yys dl handle = {:?}", handle);

    let sym = CString::new("PyGILState_Ensure").unwrap();
    let ensure: PyGILState_Ensure = transmute(libc::dlsym(handle, sym.as_ptr()));
    debug!("PyGILState_Ensure addr = {:?}", ensure);

    let sym = CString::new("PyGILState_Release").unwrap();
    let release: PyGILState_Release = transmute(libc::dlsym(handle, sym.as_ptr()));
    debug!("PyGILState_Release addr = {:?}", release);

    let sym = CString::new("PyRun_SimpleStringFlags").unwrap();
    let run: PyRun_SimpleStringFlags = transmute(libc::dlsym(handle, sym.as_ptr()));
    debug!("PyRun_SimpleStringFlags addr = {:?}", run);

    let code_cstr = CString::new(assets::get_code()).unwrap();
    let gil = ensure();
    let rv = run(code_cstr.as_ptr(), 0);
    release(gil);
    
    if rv != 0 {
      return fail(pid, "Runtime error.")
    }
  }
}

fn get_lib_path(pid: pid_t, name: &str) -> Result<Option<String>, Error> {
    use std::fs;
    let maps = fs::read(format!("/proc/{}/maps", pid))?;
    let maps = String::from_utf8_lossy(&maps);
    for line in maps.lines() {
        let columns = line.split_whitespace().collect::<Vec<&str>>();
        if columns.len() == 6 {
            let lib_path = columns[5];
            if lib_path.ends_with(name) {
              return Ok(Some(lib_path.to_string()))
            }
        }
    }
    Ok(None)
}

fn fail(pid: pid_t, msg: &str) {
  use std::fs;
  let path = format!("/data/local/tmp/yyx_{}.pipe", pid);
  fs::write(path, format!(r#"{{"error":"{}"}}"#, msg.replace("\"", "\\\""))).unwrap();
}
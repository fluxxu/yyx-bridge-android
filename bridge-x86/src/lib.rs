use libc::{self, c_char, c_int, c_void};
use std::ffi::CString;
use std::ptr;

#[allow(unused)]
extern "C" {
  fn set_errno(value: i32);
}

type Initialize = extern "C" fn(
  itf: *const c_void,
  app_code_cache_dir: *const c_char,
  instruction_set: *const c_char,
) -> bool;
type LoadLibrary = extern "C" fn(filename: *const c_char, flag: c_int) -> *mut c_void;
type IsCompatibleWith = extern "C" fn(version: u32) -> bool;

#[no_mangle]
pub extern "C" fn _init() {
  // load libnb
  unsafe {
    let path = CString::new("/system/lib/libnb.so").unwrap();
    let handle = libc::dlopen(path.as_ptr(), libc::RTLD_LAZY);
    println!("libnb handle = {:?}", handle);

    let sym = CString::new("NativeBridgeItf").unwrap();
    let itf = libc::dlsym(handle, sym.as_ptr());

    println!(
      "NativeBridgeItf addr = {:?}, version = {}",
      itf,
      ptr::read::<i32>(itf as *const i32)
    );

    let initialize = ((itf as *const u32).offset(1) as *const Initialize).read();
    let load_library = ((itf as *const u32).offset(2) as *const LoadLibrary).read();
    let is_compatible_with = ((itf as *const u32).offset(6) as *const IsCompatibleWith).read();

    println!("is_compatible_with = {:?}", is_compatible_with(1));

    let cache_path = CString::new("/vendor").unwrap();
    let isa = CString::new("arm").unwrap();

    let ok = initialize(itf, cache_path.as_ptr(), isa.as_ptr());
    println!("init: {}", ok);

    // let path = CString::new("/data/app/com.netease.onmyoji-2/lib/arm/libclient.so").unwrap();
    let path = CString::new("/vendor/libyyxbridge_arm.so").unwrap();
    let handle = load_library(path.as_ptr(), libc::RTLD_LAZY);
    println!("libclient handle = {:?}", handle);

    println!("done");
  }
}

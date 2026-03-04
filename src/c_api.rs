use crate::{parse, ResolvedProtocol};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Parse a DSL file and return a pointer to the ResolvedProtocol.
/// Returns null pointer if parsing or resolution fails.
#[no_mangle]
pub extern "C" fn aiprotodsl_load_dsl(filepath: *const c_char) -> *mut ResolvedProtocol {
    if filepath.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(filepath) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let dsl_src = match std::fs::read_to_string(path_str) {
        Ok(src) => src,
        Err(_) => return std::ptr::null_mut(),
    };

    let ast = match parse(&dsl_src) {
        Ok(protocol) => protocol,
        Err(_) => return std::ptr::null_mut(),
    };

    let resolved = match ResolvedProtocol::resolve(ast) {
        Ok(res) => res,
        Err(_) => return std::ptr::null_mut(),
    };

    // Box it and return a raw pointer
    Box::into_raw(Box::new(resolved))
}

/// Frees the ResolvedProtocol created by `aiprotodsl_load_dsl`
#[no_mangle]
pub extern "C" fn aiprotodsl_free_dsl(ptr: *mut ResolvedProtocol) {
    if !ptr.is_null() {
        unsafe {
            // Re-box and drop
            let _ = Box::from_raw(ptr);
        }
    }
}

/// A simplified dissect function that just prints for now to prove FFI works.
/// In the future, this will hook into `vm.rs` or `walk.rs`.
#[no_mangle]
pub extern "C" fn aiprotodsl_dissect_packet(
    ptr: *const ResolvedProtocol,
    data: *const u8,
    len: usize,
) -> i32 {
    if ptr.is_null() || data.is_null() {
        return -1;
    }

    let _protocol = unsafe { &*ptr };
    let _packet_slice = unsafe { std::slice::from_raw_parts(data, len) };

    println!("[Rust FFI] Receiving packet of length {} bytes", len);

    // TODO: integrate with `frame::decode_frame` or `vm::Machine::run` here.

    0 // success
}

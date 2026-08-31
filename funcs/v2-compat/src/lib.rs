//! Frozen, dependency-free ABI v2 function used to prove that a v3 Gatekeeper
//! continues serving already-deployed buffered functions.

use std::ffi::{c_char, c_void};

#[repr(C)]
struct GkHeaderV2 {
    name_ptr: *const c_char,
    name_len: usize,
    value_ptr: *const c_char,
    value_len: usize,
}

#[repr(C)]
struct GkRequestV2 {
    method_ptr: *const c_char,
    method_len: usize,
    path_ptr: *const c_char,
    path_len: usize,
    query_ptr: *const c_char,
    query_len: usize,
    headers_ptr: *const GkHeaderV2,
    header_count: usize,
    body_ptr: *const u8,
    body_len: usize,
}

#[repr(C)]
struct GkResponseV2 {
    status: u16,
    headers_ptr: *mut GkHeaderV2,
    header_count: usize,
    body_ptr: *mut u8,
    body_len: usize,
}

#[repr(C)]
struct OwnedResponseV2 {
    wire: GkResponseV2,
    body: Vec<u8>,
}

fn response(status: u16, body: impl Into<Vec<u8>>) -> *mut GkResponseV2 {
    let mut owned = Box::new(OwnedResponseV2 {
        wire: GkResponseV2 {
            status,
            headers_ptr: std::ptr::null_mut(),
            header_count: 0,
            body_ptr: std::ptr::null_mut(),
            body_len: 0,
        },
        body: body.into(),
    });
    owned.wire.body_ptr = owned.body.as_mut_ptr();
    owned.wire.body_len = owned.body.len();
    Box::into_raw(owned).cast::<GkResponseV2>()
}

#[no_mangle]
extern "C" fn gk_abi_version() -> u32 {
    2
}

#[no_mangle]
unsafe extern "C" fn gk_handle(request: *const GkRequestV2) -> *mut GkResponseV2 {
    if request.is_null() {
        return response(500, b"null request".to_vec());
    }
    let request = &*request;
    let path = if request.path_ptr.is_null() || request.path_len == 0 {
        ""
    } else {
        let bytes = std::slice::from_raw_parts(request.path_ptr.cast::<u8>(), request.path_len);
        std::str::from_utf8(bytes).unwrap_or("<invalid utf-8>")
    };
    response(200, format!("v2 buffered response for {path}"))
}

#[no_mangle]
extern "C" fn gk_describe() -> *mut GkResponseV2 {
    response(
        200,
        br#"{"name":"v2-compat","summary":"Frozen ABI v2 fixture","endpoints":[]}"#.to_vec(),
    )
}

#[no_mangle]
unsafe extern "C" fn gk_free(response: *mut c_void) {
    if !response.is_null() {
        drop(Box::from_raw(response.cast::<OwnedResponseV2>()));
    }
}

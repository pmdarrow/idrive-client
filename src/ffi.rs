//! C interface for embedding the IDrive client.
//! Calls block; dispatch them to a background queue. One handle can serve concurrent calls.
use crate::{Client, Credentials};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr,
    sync::Mutex,
};
use zeroize::Zeroizing;

pub struct IdriveHandle {
    runtime: tokio::runtime::Runtime,
    client: Mutex<Client>,
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
    private_key: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    List { path: String },
    Mkdir { path: String },
    Upload { local: String, remote: String },
    Download { remote: String, local: String },
}
fn response(value: Value) -> *mut c_char {
    CString::new(value.to_string())
        .expect("JSON contains no literal NUL")
        .into_raw()
}

/// Create and authenticate a client. Returns null on invalid input or login failure.
///
/// # Safety
/// `credentials_json` must point to a valid NUL-terminated UTF-8 JSON string
/// until this function returns. Input is borrowed, never retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn idrive_client_open(credentials_json: *const c_char) -> *mut IdriveHandle {
    catch_unwind(AssertUnwindSafe(|| {
        if credentials_json.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: required by this function's caller contract.
        let input = unsafe { CStr::from_ptr(credentials_json) };
        let input = match input.to_str() {
            Ok(s) if s.len() <= 65536 => Zeroizing::new(s.to_owned()),
            _ => return ptr::null_mut(),
        };
        let login: Login = match serde_json::from_str(&input) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let client = match runtime.block_on(Client::login(Credentials::new(
            login.username,
            login.password,
            login.private_key,
        ))) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        Box::into_raw(Box::new(IdriveHandle {
            runtime,
            client: Mutex::new(client),
        }))
    }))
    .unwrap_or(ptr::null_mut())
}

/// Execute an operation and return owned UTF-8 JSON. Free it with `idrive_string_free`.
///
/// # Safety
/// `handle` must be a live handle returned by `idrive_client_open`. `request_json`
/// must be a valid NUL-terminated string. Do not close the handle during any call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn idrive_client_call(
    handle: *mut IdriveHandle,
    request_json: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || request_json.is_null() {
            return response(json!({"ok":false,"error":"null argument"}));
        }
        // SAFETY: both pointers are valid for this call by contract.
        let handle = unsafe { &*handle };
        let request = unsafe { CStr::from_ptr(request_json) };
        let operation: Operation = match request
            .to_str()
            .ok()
            .filter(|s| s.len() <= 65536)
            .and_then(|s| serde_json::from_str(s).ok())
        {
            Some(v) => v,
            None => return response(json!({"ok":false,"error":"invalid request"})),
        };
        let client = match handle.client.lock() {
            Ok(v) => v.clone(),
            Err(_) => return response(json!({"ok":false,"error":"client lock poisoned"})),
        };
        let result: crate::Result<Value> = handle.runtime.block_on(async {
            match operation {
                Operation::List { path } => Ok(json!({"entries":client.list(&path).await?})),
                Operation::Mkdir { path } => {
                    client.mkdir(&path).await?;
                    Ok(json!({"created":true}))
                }
                Operation::Upload { local, remote } => {
                    Ok(json!({"bytes":client.upload(Path::new(&local), &remote).await?}))
                }
                Operation::Download { remote, local } => {
                    Ok(json!({"bytes":client.download(&remote, Path::new(&local)).await?}))
                }
            }
        });
        response(match result {
            Ok(value) => json!({"ok":true,"result":value}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        })
    }))
    .unwrap_or_else(|_| response(json!({"ok":false,"error":"internal panic"})))
}

/// # Safety
/// `handle` must be null or a live handle from `idrive_client_open`, passed once.
/// No other call may be running on this handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn idrive_client_close(handle: *mut IdriveHandle) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}
/// # Safety
/// `text` must be null or an owned result of `idrive_client_call`, passed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn idrive_string_free(text: *mut c_char) {
    if !text.is_null() {
        drop(unsafe { CString::from_raw(text) });
    }
}

//! The JNI surface: `org.sharenet.transport.vpn.BridgeNative` — the
//! Kotlin-side entry points. Thin by law: every function converts,
//! delegates to [`crate::bridge`], and maps errors to a typed Java
//! exception (`java.lang.IllegalStateException`) — the loop's
//! BackhaulFailure path (fail closed, the seam's own contract).
//!
//! The exported symbol names are ABI-frozen (Java_ + package + class
//! + method): `BridgeNative.kt` declares the matching `external fun`s.

use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobjectArray};
use jni::JNIEnv;

use crate::bridge::{BridgeError, BridgeSession, BRIDGE_API_VERSION};

/// Parse a 64-hex-char node id (the Kotlin side passes the hex string
/// it discovered/pinned).
fn parse_node_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Bridge the typed error to the Java exception (fail closed).
fn throw(env: &mut JNIEnv<'_>, error: &BridgeError) {
    // Best effort: if throwing itself fails there is nothing sane to
    // do (the caller sees the default return value).
    let _ = env.throw_new("java/lang/IllegalStateException", error.to_string());
}

unsafe fn handle_from_raw(handle: jlong) -> Result<&'static mut BridgeSession, BridgeError> {
    if handle == 0 {
        Err(BridgeError::NotOpen)
    } else {
        Ok(&mut *(handle as *mut BridgeSession))
    }
}

/// The ABI version (bumped on any contract change; Kotlin checks it
/// after loadLibrary).
#[no_mangle]
pub extern "system" fn Java_org_sharenet_transport_vpn_BridgeNative_nativeVersion(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    BRIDGE_API_VERSION
}

/// Open a session. Returns the opaque handle (0 = failure, with the
/// typed Java exception set).
///
/// SAFETY (JNI contract): called from the JVM with a valid JNIEnv;
/// `seed` is a jbyteArray of exactly 32 bytes, `gateway_addr` a
/// `java.lang.String` holding a SocketAddr, `gateway_node_hex` a
/// `java.lang.String` of 64 hex chars, `idle_ms` >= 100.
#[no_mangle]
pub unsafe extern "system" fn Java_org_sharenet_transport_vpn_BridgeNative_nativeOpen(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    seed: jbyteArray,
    gateway_addr: JString<'_>,
    gateway_node_hex: JString<'_>,
    idle_ms: jlong,
) -> jlong {
    let seed_arr = JByteArray::from_raw(seed);
    let Ok(seed_vec) = env.convert_byte_array(&seed_arr) else {
        throw(&mut env, &BridgeError::BadSeed);
        return 0;
    };
    let Ok(seed_bytes): Result<[u8; 32], _> = seed_vec.try_into() else {
        throw(&mut env, &BridgeError::BadSeed);
        return 0;
    };
    let Ok(addr_str) = env.get_string(&gateway_addr) else {
        throw(&mut env, &BridgeError::BadAddress);
        return 0;
    };
    let addr_str: String = addr_str.into();
    let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() else {
        throw(&mut env, &BridgeError::BadAddress);
        return 0;
    };
    let Ok(node_str) = env.get_string(&gateway_node_hex) else {
        throw(&mut env, &BridgeError::BadNodeId);
        return 0;
    };
    let node_str: String = node_str.into();
    let Some(node) = parse_node_hex(&node_str) else {
        throw(&mut env, &BridgeError::BadNodeId);
        return 0;
    };
    match BridgeSession::open(seed_bytes, addr, node, idle_ms.max(100) as u64) {
        Ok(session) => Box::into_raw(Box::new(session)) as jlong,
        Err(e) => {
            throw(&mut env, &e);
            0
        }
    }
}

/// Forward one complete packet; returns the response packets as a
/// `[[B` (null = failure, with the typed Java exception set).
///
/// SAFETY (JNI contract): `handle` came from `nativeOpen` on this
/// library; `packet` is a jbyteArray (the loop's filter-accepted IP
/// packet). Single loop thread by the seam contract.
#[no_mangle]
pub unsafe extern "system" fn Java_org_sharenet_transport_vpn_BridgeNative_nativeForward(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    packet: jbyteArray,
) -> jobjectArray {
    let session = match handle_from_raw(handle) {
        Ok(s) => s,
        Err(e) => {
            throw(&mut env, &e);
            return std::ptr::null_mut();
        }
    };
    let packet_arr = JByteArray::from_raw(packet);
    let packet_vec = match env.convert_byte_array(&packet_arr) {
        Ok(v) => v,
        Err(err) => {
            throw(&mut env, &BridgeError::Forward(format!("packet read: {err}")));
            return std::ptr::null_mut();
        }
    };
    let responses = match session.forward(&packet_vec) {
        Ok(r) => r,
        Err(e) => {
            throw(&mut env, &e);
            return std::ptr::null_mut();
        }
    };
    // Build the [[B array (byte_array_from_slice copies into the JVM).
    let byte_array_class = match env.find_class("[B") {
        Ok(c) => c,
        Err(err) => {
            throw(&mut env, &BridgeError::Forward(format!("class lookup: {err}")));
            return std::ptr::null_mut();
        }
    };
    let arr: JObjectArray<'_> = match env.new_object_array(
        responses.len() as i32,
        byte_array_class,
        JObject::null(),
    ) {
        Ok(a) => a,
        Err(err) => {
            throw(&mut env, &BridgeError::Forward(format!("response array: {err}")));
            return std::ptr::null_mut();
        }
    };
    for (i, response) in responses.iter().enumerate() {
        let bytes = match env.byte_array_from_slice(response) {
            Ok(b) => b,
            Err(err) => {
                throw(&mut env, &BridgeError::Forward(format!("response copy: {err}")));
                return std::ptr::null_mut();
            }
        };
        if let Err(err) = env.set_object_array_element(&arr, i as i32, bytes) {
            throw(&mut env, &BridgeError::Forward(format!("response store: {err}")));
            return std::ptr::null_mut();
        }
    }
    arr.into_raw()
}

/// Destroy the session (terminal). Returns true on success.
///
/// SAFETY (JNI contract): `handle` came from `nativeOpen` on this
/// library and is consumed exactly once.
#[no_mangle]
pub unsafe extern "system" fn Java_org_sharenet_transport_vpn_BridgeNative_nativeDestroy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    reason: JString<'_>,
) -> jboolean {
    if handle == 0 {
        throw(&mut env, &BridgeError::NotOpen);
        return 0;
    }
    let reason_str: String = match env.get_string(&reason) {
        Ok(s) => s.into(),
        Err(_) => "unspecified".to_string(),
    };
    let mut boxed = Box::from_raw(handle as *mut BridgeSession);
    match boxed.destroy(&reason_str) {
        Ok(()) => 1,
        Err(e) => {
            throw(&mut env, &e);
            0
        }
    }
}

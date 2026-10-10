// SPDX-License-Identifier: MIT
// Copyright (c) 2026 AnthoDingo

//! KMDF lower filter under BTHUSB: port of `kmdf/filter/generic/filter.c` (Jack-R1/SiriRemoteDriver, MIT),
//! itself based on the Toaster sample from Microsoft's Windows Driver Samples (MS-PL). See the LICENSE* files.
//!
//! The filter sees, between BTHUSB and the controller, the HCI traffic of every Bluetooth device on the adapter. It fixes
//! the Siri Remote gen 1's so that the Windows stack keeps it and its HID collection receives the reports:
//! - outgoing: unlock (0xAF written by the app to the battery level 0x28 -> 0xF0 report at 0x1d), subscription to the
//!   reports (CCCD 0x29 -> 0x24), read of the Apple characteristic 0x3A that is never acknowledged (-> 0x28);
//! - incoming: voice (Siri button) truncated to the remote's ATT MTU, short reports (buttons) padded to 20 bytes.
//!
//! Only the remote's connection is touched: the filter learns its address at the first unlock (kept in
//! `Services\AppleRemoteDriver\Parameters`, values `RemoteAddressLow`/`RemoteAddressHigh`) and finds its ACL connection in the
//! HCI connection events. To switch remotes: delete these two values (or reinstall the filter).
#![no_std]
#![allow(non_snake_case)]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: WdkAllocator = WdkAllocator;

use core::{ffi::c_void, mem::size_of, ptr::null_mut, sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering}};
use wdk_sys::{
    call_unsafe_wdf_function_binding as wdf, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    PWDFDEVICE_INIT, PWDF_REQUEST_COMPLETION_PARAMS, ULONG, UNICODE_STRING, WDFCONTEXT, WDFDEVICE,
    WDFDRIVER, WDFIOTARGET, WDFQUEUE, WDFREQUEST, WDF_DRIVER_CONFIG, WDF_IO_QUEUE_CONFIG, WDF_REQUEST_SEND_OPTIONS,
    _WDF_EXECUTION_LEVEL, _WDF_IO_QUEUE_DISPATCH_TYPE, _WDF_SYNCHRONIZATION_SCOPE, _WDF_TRI_STATE, WDFWORKITEM, WDF_OBJECT_ATTRIBUTES,
    WDF_WORKITEM_CONFIG,
};

const IOCTL_INTERNAL_USB_SUBMIT_URB: u32 = 0x0022_0003;
const URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER: u16 = 0x0009;
const USBD_TRANSFER_DIRECTION_IN: u32 = 1;
const WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET: ULONG = 0x0000_0002;
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_SET_VALUE: u32 = 0x0002;

/// ATT MTU of the remote: it answers 23 to the exchange, whatever MTU Windows requests.
const REMOTE_ATT_MTU: u32 = 23;
/// ATT PDU of a full-length 0xFC report: opcode + handle + 20-byte value (size declared in the Report Map).
const FULL_REPORT_PDU: u32 = 3 + 20;

/// Start of `_URB_BULK_OR_INTERRUPT_TRANSFER` (amd64); only the fields read here.
#[repr(C)]
struct UrbBulk {
    length: u16,
    function: u16,
    status: i32,
    _usbd_device_handle: *mut c_void,
    _usbd_flags: u32,
    _pipe_handle: *mut c_void,
    transfer_flags: u32,
    transfer_buffer_length: u32,
    transfer_buffer: *mut u8,
    transfer_buffer_mdl: *mut c_void,
}

/// `WDF_OBJECT_ATTRIBUTES` is opaque in wdk-sys: same layout (amd64, 56 bytes) written by hand.
#[repr(C)]
struct ObjectAttributes {
    size: u32,
    evt_cleanup_callback: *mut c_void,
    evt_destroy_callback: *mut c_void,
    execution_level: u32,
    synchronization_scope: u32,
    parent_object: *mut c_void,
    context_size_override: usize,
    context_type_info: *mut c_void,
}

// ---- IRP, URB, MDL ------------------------------------------------------------------------------------------------------

/// System address of an already-mapped MDL (MDL_MAPPED_TO_SYSTEM_VA or MDL_SOURCE_IS_NONPAGED_POOL), otherwise null.
/// amd64 layout: MdlFlags at 0x0A, MappedSystemVa at 0x18. MmGetSystemAddressForMdlSafe is inline: rewritten here.
unsafe fn mdl_system_va(mdl: *const c_void) -> *mut u8 {
    if mdl.is_null() {
        return null_mut();
    }
    let mdl = mdl as *const u8;
    let flags = *(mdl.add(0x0A) as *const u16);
    if flags & 0x0005 != 0 { *(mdl.add(0x18) as *const *mut u8) } else { null_mut() }
}

/// The URB is `Parameters.Others.Argument1` of the IRP's current stack location. `WdfRequestGetParameters` does NOT give it
/// for an internal IOCTL (it fills `DeviceIoControl`, which overlaps Argument1 with truncated lengths).
/// `_IRP` is opaque in wdk-sys: amd64 offsets (IRP.Tail.Overlay.CurrentStackLocation = 0xB8, IO_STACK_LOCATION.Parameters = 0x08).
unsafe fn current_stack(request: WDFREQUEST) -> *const u8 {
    const IRP_CURRENT_STACK_LOCATION: usize = 0xB8;
    let irp = wdf!(WdfRequestWdmGetIrp, request) as *const u8;
    if irp.is_null() { null_mut() } else { *(irp.add(IRP_CURRENT_STACK_LOCATION) as *const *const u8) }
}

unsafe fn urb_of(request: WDFREQUEST) -> *mut UrbBulk {
    const STACK_ARGUMENT1: usize = 0x08;
    let stack = current_stack(request);
    if stack.is_null() {
        return null_mut();
    }
    *(stack.add(STACK_ARGUMENT1) as *const *mut UrbBulk)
}

/// IOCTL code read from the IRP stack (Parameters.DeviceIoControl.IoControlCode = 0x08 + 0x10): the one from the WDF completion parameters
/// is unreliable for an internal IOCTL (the completion ran without recognising anything).
unsafe fn ioctl_of(request: WDFREQUEST) -> u32 {
    let stack = current_stack(request);
    if stack.is_null() { 0 } else { *(stack.add(0x18) as *const u32) }
}

/// Bulk/interrupt URB of an IOCTL_INTERNAL_USB_SUBMIT_URB request, otherwise null.
unsafe fn bulk_urb(request: WDFREQUEST, ioctl: u32) -> *mut UrbBulk {
    if ioctl != IOCTL_INTERNAL_USB_SUBMIT_URB {
        return null_mut();
    }
    let urb = urb_of(request);
    if urb.is_null() || (*urb).function != URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER { null_mut() } else { urb }
}

// ---- Registre (PASSIVE_LEVEL uniquement) --------------------------------------------------------------------------------

const fn wide<const N: usize>(ascii: &[u8; N]) -> [u16; N] {
    let mut w = [0u16; N];
    let mut i = 0;
    while i < N {
        w[i] = ascii[i] as u16;
        i += 1;
    }
    w
}

static STAGE_NAME: [u16; 5] = wide(b"Stage");
static ADDRESS_LOW_NAME: [u16; 16] = wide(b"RemoteAddressLow");
static ADDRESS_HIGH_NAME: [u16; 17] = wide(b"RemoteAddressHigh");
static HIT_UNLOCK_NAME: [u16; 9] = wide(b"HitUnlock");
static HIT_CCCD_NAME: [u16; 7] = wide(b"HitCccd");
static HIT_READ_NAME: [u16; 7] = wide(b"HitRead");
static HIT_TRUNC_NAME: [u16; 8] = wide(b"HitTrunc");
static HIT_PAD_NAME: [u16; 6] = wide(b"HitPad");

fn unicode(name: &'static [u16]) -> UNICODE_STRING {
    let bytes = (name.len() * 2) as u16;
    UNICODE_STRING { Length: bytes, MaximumLength: bytes, Buffer: name.as_ptr() as *mut u16 }
}

/// Opens `Services\AppleRemoteDriver\Parameters`, runs `f`, closes it.
unsafe fn with_parameters(driver: WDFDRIVER, access: u32, f: impl FnOnce(*mut c_void)) {
    if driver.is_null() {
        return;
    }
    let mut key = null_mut();
    if wdf!(WdfDriverOpenParametersRegistryKey, driver, access, null_mut(), &mut key) >= 0 {
        f(key as _);
        wdf!(WdfRegistryClose, key);
    }
}

unsafe fn set_dword(key: *mut c_void, name: &'static [u16], value: u32) {
    let mut name = unicode(name);
    let _ = wdf!(WdfRegistryAssignULong, key as _, &mut name, value);
}

unsafe fn get_dword(key: *mut c_void, name: &'static [u16]) -> u32 {
    let mut name = unicode(name);
    let mut value: ULONG = 0;
    if wdf!(WdfRegistryQueryULong, key as _, &mut name, &mut value) >= 0 { value } else { 0 }
}

/// Milestone readable without a debugger: `reg query HKLM\SYSTEM\CurrentControlSet\Services\AppleRemoteDriver\Parameters /v Stage`
/// (1 = DriverEntry, 2 = EvtDeviceAdd, 3 = I/O queue ready; 0x80000000 | NTSTATUS = failure).
unsafe fn stage(driver: WDFDRIVER, value: u32) {
    with_parameters(driver, KEY_SET_VALUE, |key| set_dword(key, &STAGE_NAME, value));
}

// ---- Remote connection -----------------------------------------------------------------------------------------

const NO_ACL: u32 = u32::MAX;
const MAX_LINKS: usize = 8;

/// Bluetooth address of the remote (48 bits, HCI event order), 0 = not learned yet.
static REMOTE_ADDRESS: AtomicU64 = AtomicU64::new(0);
/// ACL handle of its current connection, NO_ACL = none.
static REMOTE_ACL: AtomicU32 = AtomicU32::new(NO_ACL);
/// Open LE connections (ACL handle -> peer address), from LE (Enhanced) Connection Complete / Disconnection Complete.
static LINK_HANDLE: [AtomicU32; MAX_LINKS] = [const { AtomicU32::new(NO_ACL) }; MAX_LINKS];
static LINK_ADDRESS: [AtomicU64; MAX_LINKS] = [const { AtomicU64::new(0) }; MAX_LINKS];

/// ACL connection handle (12 bits) of an ACL packet.
fn acl_of(b: &[u8]) -> u32 {
    u32::from(b[0]) | (u32::from(b[1] & 0x0F) << 8)
}

fn is_remote(acl: u32) -> bool {
    REMOTE_ACL.load(Ordering::Relaxed) == acl
}

/// As long as the address isn't learned (first pairing), any connection may be the remote.
fn may_be_remote(acl: u32) -> bool {
    REMOTE_ADDRESS.load(Ordering::Relaxed) == 0 || is_remote(acl)
}

fn on_connected(acl: u32, address: u64) {
    for i in 0..MAX_LINKS {
        if LINK_HANDLE[i].compare_exchange(NO_ACL, acl, Ordering::Relaxed, Ordering::Relaxed).is_ok() || LINK_HANDLE[i].load(Ordering::Relaxed) == acl {
            LINK_ADDRESS[i].store(address, Ordering::Relaxed);
            break;
        }
    }
    if address != 0 && address == REMOTE_ADDRESS.load(Ordering::Relaxed) {
        REMOTE_ACL.store(acl, Ordering::Relaxed);
    }
}

fn on_disconnected(acl: u32) {
    for i in 0..MAX_LINKS {
        if LINK_HANDLE[i].load(Ordering::Relaxed) == acl {
            LINK_ADDRESS[i].store(0, Ordering::Relaxed);
            LINK_HANDLE[i].store(NO_ACL, Ordering::Relaxed);
        }
    }
    let _ = REMOTE_ACL.compare_exchange(acl, NO_ACL, Ordering::Relaxed, Ordering::Relaxed);
}

fn address_of(acl: u32) -> u64 {
    (0..MAX_LINKS)
        .find(|&i| LINK_HANDLE[i].load(Ordering::Relaxed) == acl)
        .map_or(0, |i| LINK_ADDRESS[i].load(Ordering::Relaxed))
}

/// Our unlock goes through `acl`: that's the remote; we remember its address (kept in the registry).
unsafe fn learn_remote(acl: u32) {
    REMOTE_ACL.store(acl, Ordering::Relaxed);
    let address = address_of(acl);
    if address != 0 && REMOTE_ADDRESS.swap(address, Ordering::Relaxed) != address {
        request_flush();
    }
}

/// HCI events (interrupt endpoint): LE Connection Complete (0x3E/0x01), LE Enhanced Connection Complete
/// (0x3E/0x0A), Disconnection Complete (0x05). The announced length must match exactly: an ACL packet doesn't look like that.
fn track_links(b: &[u8]) {
    if b.len() < 2 || b.len() != 2 + usize::from(b[1]) {
        return;
    }
    match b[0] {
        0x3E if b.len() >= 14 && (b[2] == 0x01 || b[2] == 0x0A) && b[3] == 0x00 => {
            let acl = u32::from(b[4]) | (u32::from(b[5] & 0x0F) << 8);
            let address = b[8..14].iter().rev().fold(0u64, |a, &byte| (a << 8) | u64::from(byte));
            on_connected(acl, address);
        }
        0x05 if b.len() >= 6 && b[2] == 0x00 => on_disconnected(u32::from(b[3]) | (u32::from(b[4] & 0x0F) << 8)),
        _ => {}
    }
}

// ---- Compteurs ------------------------------------------------------------------------------------------------------------

/// Rules applied, written to `Parameters` by a work item (the registry is off-limits at DISPATCH_LEVEL).
static HIT_UNLOCK: AtomicU32 = AtomicU32::new(0);
static HIT_CCCD: AtomicU32 = AtomicU32::new(0);
static HIT_READ: AtomicU32 = AtomicU32::new(0);
static HIT_TRUNC: AtomicU32 = AtomicU32::new(0);
static HIT_PAD: AtomicU32 = AtomicU32::new(0);

static WORK_ITEM: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static DRIVER: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

unsafe extern "C" fn flush_counters(_item: WDFWORKITEM) {
    with_parameters(DRIVER.load(Ordering::Relaxed) as _, KEY_SET_VALUE, |key| {
        let address = REMOTE_ADDRESS.load(Ordering::Relaxed);
        if address != 0 {
            set_dword(key, &ADDRESS_LOW_NAME, address as u32);
            set_dword(key, &ADDRESS_HIGH_NAME, (address >> 32) as u32);
        }
        set_dword(key, &HIT_UNLOCK_NAME, HIT_UNLOCK.load(Ordering::Relaxed));
        set_dword(key, &HIT_CCCD_NAME, HIT_CCCD.load(Ordering::Relaxed));
        set_dword(key, &HIT_READ_NAME, HIT_READ.load(Ordering::Relaxed));
        set_dword(key, &HIT_TRUNC_NAME, HIT_TRUNC.load(Ordering::Relaxed));
        set_dword(key, &HIT_PAD_NAME, HIT_PAD.load(Ordering::Relaxed));
    });
}

/// Requests writing the counters (usable at DISPATCH_LEVEL).
unsafe fn request_flush() {
    let item = WORK_ITEM.load(Ordering::Relaxed);
    if !item.is_null() {
        wdf!(WdfWorkItemEnqueue, item as _);
    }
}

/// Counts an applied rule; counters are only written on the first occurrences, then now and then.
unsafe fn hit(counter: &AtomicU32) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || n % 256 == 0 {
        request_flush();
    }
}

// ---- Pilote --------------------------------------------------------------------------------------------------------------

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut config: WDF_DRIVER_CONFIG = core::mem::zeroed();
    config.Size = size_of::<WDF_DRIVER_CONFIG>() as ULONG;
    config.EvtDriverDeviceAdd = Some(filter_evt_device_add);

    let mut wdf_driver: WDFDRIVER = null_mut();
    let status = wdf!(WdfDriverCreate, driver, registry_path, null_mut(), &mut config, &mut wdf_driver);
    if status >= 0 {
        DRIVER.store(wdf_driver as _, Ordering::Relaxed);
        stage(wdf_driver, 1);
    }
    status
}

unsafe extern "C" fn filter_evt_device_add(
    driver: WDFDRIVER,
    mut device_init: PWDFDEVICE_INIT,
) -> NTSTATUS {
    with_parameters(driver, KEY_QUERY_VALUE, |key| {
        let address = u64::from(get_dword(key, &ADDRESS_LOW_NAME)) | (u64::from(get_dword(key, &ADDRESS_HIGH_NAME)) << 32);
        REMOTE_ADDRESS.store(address, Ordering::Relaxed);
    });
    stage(driver, 2);
    wdf!(WdfFdoInitSetFilter, device_init);

    let mut device: WDFDEVICE = null_mut();
    let status = wdf!(WdfDeviceCreate, &mut device_init, null_mut(), &mut device);
    if status < 0 {
        stage(driver, 0x8000_0000 | status as u32);
        return status;
    }

    let mut cfg: WDF_IO_QUEUE_CONFIG = core::mem::zeroed();
    cfg.Size = size_of::<WDF_IO_QUEUE_CONFIG>() as ULONG;
    cfg.PowerManaged = _WDF_TRI_STATE::WdfUseDefault;
    cfg.DefaultQueue = 1;
    cfg.DispatchType = _WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchParallel;
    // WDF_IO_QUEUE_CONFIG_INIT sets NumberOfPresentedRequests to -1 (unlimited) for a parallel queue; at 0 the queue can
    // block on the USB interrupt reads that stay pending, hence BTHUSB's init timeout.
    cfg.Settings.Parallel.NumberOfPresentedRequests = u32::MAX;
    cfg.EvtIoInternalDeviceControl = Some(filter_evt_io_internal_device_control);
    cfg.EvtIoDefault = Some(filter_evt_io_default); // everything else (read/write/IOCTL): forwarded as is

    let status = wdf!(WdfIoQueueCreate, device, &mut cfg, null_mut(), null_mut());

    // Work item (PASSIVE_LEVEL) that writes the learned address and the counters; without it the filter works, with no memory or trace.
    let mut work: WDF_WORKITEM_CONFIG = core::mem::zeroed();
    work.Size = size_of::<WDF_WORKITEM_CONFIG>() as ULONG;
    work.EvtWorkItemFunc = Some(flush_counters);
    let mut attributes: ObjectAttributes = core::mem::zeroed();
    attributes.size = size_of::<ObjectAttributes>() as ULONG;
    attributes.execution_level = _WDF_EXECUTION_LEVEL::WdfExecutionLevelInheritFromParent as u32;
    attributes.synchronization_scope = _WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeInheritFromParent as u32;
    attributes.parent_object = device as _;
    let mut item = null_mut();
    if wdf!(WdfWorkItemCreate, &mut work, &mut attributes as *mut ObjectAttributes as *mut WDF_OBJECT_ATTRIBUTES, &mut item) >= 0 {
        WORK_ITEM.store(item as _, Ordering::Relaxed);
    }
    stage(driver, if status >= 0 { 3 } else { 0x8000_0000 | status as u32 });
    status
}

unsafe extern "C" fn filter_evt_io_default(queue: WDFQUEUE, request: WDFREQUEST) {
    let target = wdf!(WdfDeviceGetIoTarget, wdf!(WdfIoQueueGetDevice, queue));
    let mut options: WDF_REQUEST_SEND_OPTIONS = core::mem::zeroed();
    options.Size = size_of::<WDF_REQUEST_SEND_OPTIONS>() as ULONG;
    options.Flags = WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET;
    if wdf!(WdfRequestSend, request, target, &mut options) == 0 {
        wdf!(WdfRequestComplete, request, wdf!(WdfRequestGetStatus, request));
    }
}

unsafe extern "C" fn filter_evt_io_internal_device_control(
    queue: WDFQUEUE,
    request: WDFREQUEST,
    _output_len: usize,
    _input_len: usize,
    ioctl: ULONG,
) {
    let target = wdf!(WdfDeviceGetIoTarget, wdf!(WdfIoQueueGetDevice, queue));
    let urb = bulk_urb(request, ioctl);

    // Capacity of a read buffer, passed as context: on completion, TransferBufferLength only holds the received length.
    let mut capacity: usize = 0;
    if !urb.is_null() {
        let (flags, flat, length) = ((*urb).transfer_flags, (*urb).transfer_buffer, (*urb).transfer_buffer_length);
        if flags & USBD_TRANSFER_DIRECTION_IN != 0 {
            capacity = length as usize;
        } else if !flat.is_null() && length >= 11 {
            rewrite_outbound(core::slice::from_raw_parts_mut(flat, length as usize));
        }
    }

    // Always with a completion routine (FORWARD_REQUEST_WITH_COMPLETION = 1 in the original).
    let _ = wdf!(WdfRequestFormatRequestUsingCurrentType, request);
    wdf!(WdfRequestSetCompletionRoutine, request, Some(filter_request_completion), capacity as *mut c_void);
    if wdf!(WdfRequestSend, request, target, null_mut()) == 0 {
        wdf!(WdfRequestComplete, request, wdf!(WdfRequestGetStatus, request));
    }
}

/// Outgoing ACL packet (ATT, channel 4). The connection handle (b[0..2]) depends on the controller and changes on every connection:
/// the patterns don't contain it.
unsafe fn rewrite_outbound(b: &mut [u8]) {
    let acl = acl_of(b);
    match b.len() {
        // Unlock: write without response (0x52) of 0xAF to 0x28 -> write with response (0x12) of the 0xF0 report (0x1d).
        // Pattern specific to our app: it identifies the remote's connection.
        12 if b[2..] == [0x08, 0x00, 0x04, 0x00, 0x04, 0x00, 0x52, 0x28, 0x00, 0xAF] => {
            b[8] = 0x12;
            b[9] = 0x1d;
            learn_remote(acl);
            hit(&HIT_UNLOCK);
        }
        // Subscription: battery-level CCCD (0x29) -> the HID reports one (0x24).
        13 if b[2..] == [0x09, 0x00, 0x05, 0x00, 0x04, 0x00, 0x12, 0x29, 0x00, 0x01, 0x00] && may_be_remote(acl) => {
            b[9] = 0x24;
            hit(&HIT_CCCD);
        }
        // Windows reads the Apple characteristic 0x3A (ce5ad0bc…) that the remote never acknowledges: 30 s ATT timeout, link
        // dropped, bond key deleted, no HID collection. We read the battery level (0x28) instead: immediate answer.
        11 if b[2..] == [0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x0A, 0x3A, 0x00] && may_be_remote(acl) => {
            b[9] = 0x28;
            hit(&HIT_READ);
        }
        _ => {}
    }
}

unsafe extern "C" fn filter_request_completion(
    request: WDFREQUEST,
    _target: WDFIOTARGET,
    params: PWDF_REQUEST_COMPLETION_PARAMS,
    context: WDFCONTEXT,
) {
    let status = (*params).IoStatus.__bindgen_anon_1.Status;
    let urb = bulk_urb(request, ioctl_of(request));
    if status >= 0 && !urb.is_null() && (*urb).transfer_flags & USBD_TRANSFER_DIRECTION_IN != 0 {
        let flat = (*urb).transfer_buffer;
        // BTHUSB may describe its read buffers with an MDL rather than a flat pointer.
        let data = if flat.is_null() { mdl_system_va((*urb).transfer_buffer_mdl) } else { flat };
        let length = (*urb).transfer_buffer_length;
        if !data.is_null() && length >= 6 {
            let capacity = context as usize as u32;
            if let Some(new_length) = rewrite_inbound(data, length, capacity) {
                (*urb).transfer_buffer_length = new_length;
            }
        }
    }
    wdf!(WdfRequestComplete, request, status);
}

/// Incoming packet (HCI event or ACL packet). Returns the new transfer length if it was modified.
unsafe fn rewrite_inbound(data: *mut u8, length: u32, capacity: u32) -> Option<u32> {
    let b = core::slice::from_raw_parts_mut(data, length as usize);
    track_links(b);

    // ATT notification (0x1b) from the remote, at the start of an L2CAP packet (0x20), on the ATT channel (CID 4).
    if length < 11 || b[1] & 0x30 != 0x20 || b[6] != 0x04 || b[7] != 0x00 || b[8] != 0x1b || !is_remote(acl_of(b)) {
        return None;
    }
    let l2cap = u32::from(b[4]) | (u32::from(b[5]) << 8);
    let hci = u32::from(b[2]) | (u32::from(b[3]) << 8);
    let set_lengths = |b: &mut [u8], pdu: u32| {
        b[2] = (4 + pdu) as u8;
        b[3] = ((4 + pdu) >> 8) as u8;
        b[4] = pdu as u8;
        b[5] = (pdu >> 8) as u8;
    };

    // Voice (Siri button): notification longer than the MTU, which Windows refuses by dropping the link. Truncated to the MTU
    // (like FIX_HCI_L2CAP_HEADERS in the C driver); the continuation fragments that follow are ignored by the stack.
    if l2cap > REMOTE_ATT_MTU && hci >= 4 + REMOTE_ATT_MTU {
        set_lengths(b, REMOTE_ATT_MTU);
        hit(&HIT_TRUNC);
        return Some(8 + REMOTE_ATT_MTU);
    }

    // Short report (buttons: 2 to 4 bytes, touchpad: 13): Windows' HID driver rejects any report shorter than the declared
    // size (20 bytes for 0xFC). Padded with zeros (the decoder only reads what byte 1 announces).
    if b[9] == 0x23 && b[10] == 0x00 && l2cap >= 3 && l2cap < FULL_REPORT_PDU && hci == 4 + l2cap && length == 4 + hci
        && capacity >= 8 + FULL_REPORT_PDU
    {
        let full = core::slice::from_raw_parts_mut(data, (8 + FULL_REPORT_PDU) as usize);
        full[(8 + l2cap) as usize..].fill(0);
        set_lengths(full, FULL_REPORT_PDU);
        hit(&HIT_PAD);
        return Some(8 + FULL_REPORT_PDU);
    }
    None
}

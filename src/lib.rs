//! Filtre inférieur KMDF sous BTHUSB : port de `kmdf/filter/generic/filter.c` (Jack-R1/SiriRemoteDriver, MIT),
//! lui-même basé sur l'exemple Toaster des Windows Driver Samples de Microsoft (MS-PL). Voir les fichiers LICENSE*.
//! Sortant : redirige l'écriture « déverrouillage » (0xAF) et l'abonnement vers les handles HID de la télécommande.
//! Entrant (optionnel, désactivé par défaut) : réécrit le handle de notification HID 0x23 en 0x2b (batterie), pour une appli qui
//! lit le service batterie ; à ne pas activer quand Windows expose lui-même la collection HID (il ne verrait plus les rapports).
// ponytail: pas de périphérique de contrôle ni d'IOCTL de debug (FIX_HCI_L2CAP_HEADERS reste à FALSE comme dans l'original).
#![no_std]
#![allow(non_snake_case)]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: WdkAllocator = WdkAllocator;

use core::{ffi::c_void, mem::size_of, ptr::null_mut, sync::atomic::{AtomicBool, Ordering}};
use wdk_sys::{
    call_unsafe_wdf_function_binding as wdf, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    PWDFDEVICE_INIT, PWDF_REQUEST_COMPLETION_PARAMS, ULONG, UNICODE_STRING, WDFCONTEXT, WDFDEVICE,
    WDFDRIVER, WDFIOTARGET, WDFQUEUE, WDFREQUEST, WDF_DRIVER_CONFIG, WDF_IO_QUEUE_CONFIG, WDF_REQUEST_SEND_OPTIONS,
    _WDF_IO_QUEUE_DISPATCH_TYPE, _WDF_TRI_STATE,
};

const IOCTL_INTERNAL_USB_SUBMIT_URB: u32 = 0x0022_0003;
const URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER: u16 = 0x0009;
const USBD_TRANSFER_DIRECTION_IN: u32 = 1;
const WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET: ULONG = 0x0000_0002;

/// Début de `_URB_BULK_OR_INTERRUPT_TRANSFER` (amd64) ; seuls les champs lus ici.
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
    _transfer_buffer_mdl: *mut c_void,
}

/// L'URB est `Parameters.Others.Argument1` de l'emplacement de pile courant de l'IRP. `WdfRequestGetParameters` ne le donne
/// PAS pour un IOCTL interne (il remplit `DeviceIoControl`, qui recouvre Argument1 avec des longueurs tronquées).
/// `_IRP` est opaque dans wdk-sys : décalages amd64 (IRP.Tail.Overlay.CurrentStackLocation = 0xB8, IO_STACK_LOCATION.Parameters = 0x08).
unsafe fn urb_of(request: WDFREQUEST) -> *mut UrbBulk {
    const IRP_CURRENT_STACK_LOCATION: usize = 0xB8;
    const STACK_ARGUMENT1: usize = 0x08;
    let irp = wdf!(WdfRequestWdmGetIrp, request) as *const u8;
    let stack = *(irp.add(IRP_CURRENT_STACK_LOCATION) as *const *const u8);
    if stack.is_null() {
        return null_mut();
    }
    *(stack.add(STACK_ARGUMENT1) as *const *mut UrbBulk)
}

/// Jalon lisible sans débogueur : `reg query HKLM\SYSTEM\CurrentControlSet\Services\AppleRemoteDriver\Parameters /v Stage`
/// (1 = DriverEntry, 2 = EvtDeviceAdd, 3 = file d'E/S prête ; 0x80000000 | NTSTATUS = échec). À appeler à PASSIVE_LEVEL.
unsafe fn stage(driver: WDFDRIVER, value: u32) {
    static NAME: [u16; 5] = [b'S' as u16, b't' as u16, b'a' as u16, b'g' as u16, b'e' as u16];
    let mut key = null_mut();
    if wdf!(WdfDriverOpenParametersRegistryKey, driver, 0x0002 /* KEY_SET_VALUE */, null_mut(), &mut key) >= 0 {
        let mut name = UNICODE_STRING { Length: 10, MaximumLength: 10, Buffer: NAME.as_ptr() as *mut u16 };
        let _ = wdf!(WdfRegistryAssignULong, key, &mut name, value);
        wdf!(WdfRegistryClose, key);
    }
}

/// Réécriture entrante 0x23 -> 0x2b : valeur DWORD `RewriteInbound` (0/1) dans `Services\AppleRemoteDriver\Parameters`, lue à chaque
/// EvtDeviceAdd (redémarrer le périphérique pour l'appliquer). Absente = désactivée.
static REWRITE_INBOUND: AtomicBool = AtomicBool::new(false);

unsafe fn load_settings(driver: WDFDRIVER) {
    static NAME: [u16; 14] = {
        let src = *b"RewriteInbound";
        let mut w = [0u16; 14];
        let mut i = 0;
        while i < 14 { w[i] = src[i] as u16; i += 1; }
        w
    };
    let mut key = null_mut();
    if wdf!(WdfDriverOpenParametersRegistryKey, driver, 0x0001 /* KEY_QUERY_VALUE */, null_mut(), &mut key) >= 0 {
        let mut name = UNICODE_STRING { Length: 28, MaximumLength: 28, Buffer: NAME.as_ptr() as *mut u16 };
        let mut value: ULONG = 0;
        if wdf!(WdfRegistryQueryULong, key, &mut name, &mut value) >= 0 {
            REWRITE_INBOUND.store(value != 0, Ordering::Relaxed);
        }
        wdf!(WdfRegistryClose, key);
    }
}

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut config: WDF_DRIVER_CONFIG = core::mem::zeroed();
    config.Size = size_of::<WDF_DRIVER_CONFIG>() as ULONG;
    config.EvtDriverDeviceAdd = Some(filter_evt_device_add);

    wdk::println!("AppleRemoteDriver: DriverEntry");

    let mut wdf_driver: WDFDRIVER = null_mut();
    let status = wdf!(WdfDriverCreate, driver, registry_path, null_mut(), &mut config, &mut wdf_driver);
    if status >= 0 {
        stage(wdf_driver, 1);
    }
    status
}

unsafe extern "C" fn filter_evt_device_add(
    driver: WDFDRIVER,
    mut device_init: PWDFDEVICE_INIT,
) -> NTSTATUS {
    wdk::println!("AppleRemoteDriver: EvtDeviceAdd");
    load_settings(driver);
    stage(driver, 2);
    wdf!(WdfFdoInitSetFilter, device_init);

    let mut device: WDFDEVICE = null_mut();
    let status = wdf!(WdfDeviceCreate, &mut device_init, null_mut(), &mut device);
    if status < 0 {
        wdk::println!("AppleRemoteDriver: WdfDeviceCreate a échoué : {:#x}", status);
        stage(driver, 0x8000_0000 | status as u32);
        return status;
    }

    let mut cfg: WDF_IO_QUEUE_CONFIG = core::mem::zeroed();
    cfg.Size = size_of::<WDF_IO_QUEUE_CONFIG>() as ULONG;
    cfg.PowerManaged = _WDF_TRI_STATE::WdfUseDefault;
    cfg.DefaultQueue = 1;
    cfg.DispatchType = _WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchParallel;
    // WDF_IO_QUEUE_CONFIG_INIT met NumberOfPresentedRequests à -1 (illimité) pour une file parallèle ; à 0 la file peut
    // se bloquer sur les lectures d'interruption USB qui restent en attente, d'où le timeout d'init de BTHUSB.
    cfg.Settings.Parallel.NumberOfPresentedRequests = u32::MAX;
    cfg.EvtIoInternalDeviceControl = Some(filter_evt_io_internal_device_control);
    cfg.EvtIoDefault = Some(filter_evt_io_default); // tout le reste (lecture/écriture/IOCTL) : transmis tel quel

    let status = wdf!(WdfIoQueueCreate, device, &mut cfg, null_mut(), null_mut());
    wdk::println!("AppleRemoteDriver: file d'E/S créée : {:#x}", status);
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

    if ioctl == IOCTL_INTERNAL_USB_SUBMIT_URB {
        let urb = urb_of(request);
        if !urb.is_null() && (*urb).function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER {
            let u = &*urb;
            if u.transfer_flags & USBD_TRANSFER_DIRECTION_IN == 0 && !u.transfer_buffer.is_null() {
                let b = core::slice::from_raw_parts_mut(u.transfer_buffer, u.transfer_buffer_length as usize);
                match b.len() {
                    // écriture sans réponse (0x52) sur 0x28 -> écriture avec réponse (0x12) sur 0x1d (déverrouillage)
                    12 if b[..] == [0x80, 0x00, 0x08, 0x00, 0x04, 0x00, 0x04, 0x00, 0x52, 0x28, 0x00, 0xAF] => {
                        wdk::println!("AppleRemoteDriver: déverrouillage 0xAF -> handle 0x1d");
                        b[8] = 0x12;
                        b[9] = 0x1d;
                    }
                    // abonnement CCCD : handle 0x29 -> 0x24 (notifications HID)
                    13 if b[..] == [0x80, 0x00, 0x09, 0x00, 0x05, 0x00, 0x04, 0x00, 0x12, 0x29, 0x00, 0x01, 0x00] => {
                        b[9] = 0x24;
                    }
                    // Windows lit la caractéristique Apple 0x3A (ce5ad0bc…) que la télécommande n'acquitte jamais : timeout ATT de 30 s,
                    // liaison coupée, clé d'appairage supprimée. On lit à la place le niveau de batterie (0x28) : réponse valide et immédiate.
                    11 if b[2..] == [0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x0A, 0x3A, 0x00] => {
                        wdk::println!("AppleRemoteDriver: lecture ATT 0x3A -> 0x28");
                        b[9] = 0x28;
                    }
                    _ => {}
                }
            }
        }
    }

    // Toujours avec routine de complétion (FORWARD_REQUEST_WITH_COMPLETION = 1 dans l'original).
    let _ = wdf!(WdfRequestFormatRequestUsingCurrentType, request);
    wdf!(WdfRequestSetCompletionRoutine, request, Some(filter_request_completion), null_mut());
    if wdf!(WdfRequestSend, request, target, null_mut()) == 0 {
        wdf!(WdfRequestComplete, request, wdf!(WdfRequestGetStatus, request));
    }
}

unsafe extern "C" fn filter_request_completion(
    request: WDFREQUEST,
    _target: WDFIOTARGET,
    params: PWDF_REQUEST_COMPLETION_PARAMS,
    _context: WDFCONTEXT,
) {
    let status = (*params).IoStatus.__bindgen_anon_1.Status;
    if status >= 0 && (*params).Parameters.Ioctl.IoControlCode == IOCTL_INTERNAL_USB_SUBMIT_URB {
        let urb = urb_of(request) as *const UrbBulk;
        if !urb.is_null() && (*urb).function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER {
            let u = &*urb;
            if REWRITE_INBOUND.load(Ordering::Relaxed)
                && u.transfer_flags & USBD_TRANSFER_DIRECTION_IN != 0
                && !u.transfer_buffer.is_null()
                && u.transfer_buffer_length > 10
            {
                let b = core::slice::from_raw_parts_mut(u.transfer_buffer, u.transfer_buffer_length as usize);
                // notification ATT (0x1b) du handle 0x23 sur le canal ATT (CID 4)
                if b[0] == 0x80 && b[1] == 0x20 && b[3] == 0x00 && b[5] == 0x00 && b[6] == 0x04
                    && b[7] == 0x00 && b[8] == 0x1b && b[9] == 0x23 && b[10] == 0x00
                {
                    b[9] = 0x2b; // 0x23 (HID) -> 0x2b (BatteryPowerState)
                }
            }
        }
    }

    wdf!(WdfRequestComplete, request, status);
}

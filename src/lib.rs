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

use core::{ffi::c_void, mem::size_of, ptr::null_mut, sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering}};
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
    transfer_buffer_mdl: *mut c_void,
}

/// `WDF_OBJECT_ATTRIBUTES` est opaque dans wdk-sys : même disposition (amd64, 56 octets) écrite à la main.
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

/// Adresse système d'un MDL déjà mappé (MDL_MAPPED_TO_SYSTEM_VA ou MDL_SOURCE_IS_NONPAGED_POOL), sinon nul.
/// Disposition amd64 : MdlFlags en 0x0A, MappedSystemVa en 0x18. MmGetSystemAddressForMdlSafe est inline : réécrit ici.
unsafe fn mdl_system_va(mdl: *const c_void) -> *mut u8 {
    if mdl.is_null() {
        return null_mut();
    }
    let mdl = mdl as *const u8;
    let flags = *(mdl.add(0x0A) as *const u16);
    if flags & 0x0005 != 0 { *(mdl.add(0x18) as *const *mut u8) } else { null_mut() }
}

/// L'URB est `Parameters.Others.Argument1` de l'emplacement de pile courant de l'IRP. `WdfRequestGetParameters` ne le donne
/// PAS pour un IOCTL interne (il remplit `DeviceIoControl`, qui recouvre Argument1 avec des longueurs tronquées).
/// `_IRP` est opaque dans wdk-sys : décalages amd64 (IRP.Tail.Overlay.CurrentStackLocation = 0xB8, IO_STACK_LOCATION.Parameters = 0x08).
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

/// Code IOCTL lu dans la pile IRP (Parameters.DeviceIoControl.IoControlCode = 0x08 + 0x10) : celui des paramètres de complétion WDF
/// n'est pas fiable pour un IOCTL interne (le pilote C d'origine ne l'utilise pas non plus).
unsafe fn ioctl_of(request: WDFREQUEST) -> u32 {
    let stack = current_stack(request);
    if stack.is_null() { 0 } else { *(stack.add(0x18) as *const u32) }
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

/// Compteurs de diagnostic, écrits dans `Parameters` par un work item (le registre est interdit à DISPATCH_LEVEL) :
/// `HitUnlock`, `HitCccd`, `HitRead` = règles sortantes appliquées ; `LastAcl` = handle de connexion ACL du dernier paquet réécrit ;
/// `InNotify` = notifications ATT entrantes vues ; `LastNotifyHandle` = handle ATT de la dernière.
static HIT_UNLOCK: AtomicU32 = AtomicU32::new(0);
static HIT_CCCD: AtomicU32 = AtomicU32::new(0);
static HIT_READ: AtomicU32 = AtomicU32::new(0);
static LAST_ACL: AtomicU32 = AtomicU32::new(0);
static IN_NOTIFY: AtomicU32 = AtomicU32::new(0);
static LAST_NOTIFY_HANDLE: AtomicU32 = AtomicU32::new(0);
/// Trafic entrant : `InAny` = transferts IN reçus, `InAtt` = paquets ATT (canal 4) ; `LastAttLen` et `LastAttW0..2` = longueur et octets 8..20
/// du dernier paquet ATT (W0 = opcode ATT, handle... ; opcode 0x13 = réponse d'écriture, 0x01 = erreur : opcode requête, handle, code).
static IN_ANY: AtomicU32 = AtomicU32::new(0);
static IN_ATT: AtomicU32 = AtomicU32::new(0);
static LAST_ATT_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_ATT_W0: AtomicU32 = AtomicU32::new(0);
static LAST_ATT_W1: AtomicU32 = AtomicU32::new(0);
static LAST_ATT_W2: AtomicU32 = AtomicU32::new(0);
/// Lectures entrantes : `InAll` = tous les URB IN complétés, `InMdl` = ceux dont le tampon est décrit par un MDL (pas de tampon plat),
/// `InNoBuf` = IN sans tampon exploitable.
/// `CompAll` = complétions vues par le filtre, `CompUrb` = celles d'un IOCTL_INTERNAL_USB_SUBMIT_URB (lu dans la pile IRP).
static COMP_ALL: AtomicU32 = AtomicU32::new(0);
static COMP_URB: AtomicU32 = AtomicU32::new(0);
static IN_ALL: AtomicU32 = AtomicU32::new(0);
static IN_MDL: AtomicU32 = AtomicU32::new(0);
static IN_NO_BUF: AtomicU32 = AtomicU32::new(0);
static WORK_ITEM: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static DRIVER: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

const fn wide<const N: usize>(ascii: &[u8; N]) -> [u16; N] {
    let mut w = [0u16; N];
    let mut i = 0;
    while i < N { w[i] = ascii[i] as u16; i += 1; }
    w
}

unsafe fn set_dword(key: *mut c_void, name: &'static [u16], value: u32) {
    let mut unicode = UNICODE_STRING { Length: (name.len() * 2) as u16, MaximumLength: (name.len() * 2) as u16, Buffer: name.as_ptr() as *mut u16 };
    let _ = wdf!(WdfRegistryAssignULong, key as _, &mut unicode, value);
}

unsafe extern "C" fn flush_counters(_item: WDFWORKITEM) {
    static HIT_UNLOCK_NAME: [u16; 9] = wide(b"HitUnlock");
    static HIT_CCCD_NAME: [u16; 7] = wide(b"HitCccd");
    static HIT_READ_NAME: [u16; 7] = wide(b"HitRead");
    static LAST_ACL_NAME: [u16; 7] = wide(b"LastAcl");
    static IN_NOTIFY_NAME: [u16; 8] = wide(b"InNotify");
    static LAST_NOTIFY_NAME: [u16; 16] = wide(b"LastNotifyHandle");
    static IN_ANY_NAME: [u16; 5] = wide(b"InAny");
    static IN_ALL_NAME: [u16; 5] = wide(b"InAll");
    static COMP_ALL_NAME: [u16; 7] = wide(b"CompAll");
    static COMP_URB_NAME: [u16; 7] = wide(b"CompUrb");
    static IN_MDL_NAME: [u16; 5] = wide(b"InMdl");
    static IN_NO_BUF_NAME: [u16; 7] = wide(b"InNoBuf");
    static IN_ATT_NAME: [u16; 5] = wide(b"InAtt");
    static LAST_ATT_LEN_NAME: [u16; 10] = wide(b"LastAttLen");
    static LAST_ATT_W0_NAME: [u16; 9] = wide(b"LastAttW0");
    static LAST_ATT_W1_NAME: [u16; 9] = wide(b"LastAttW1");
    static LAST_ATT_W2_NAME: [u16; 9] = wide(b"LastAttW2");
    let driver = DRIVER.load(Ordering::Relaxed);
    if driver.is_null() { return; }
    let mut key = null_mut();
    if wdf!(WdfDriverOpenParametersRegistryKey, driver as _, 0x0002 /* KEY_SET_VALUE */, null_mut(), &mut key) >= 0 {
        set_dword(key as _, &HIT_UNLOCK_NAME, HIT_UNLOCK.load(Ordering::Relaxed));
        set_dword(key as _, &HIT_CCCD_NAME, HIT_CCCD.load(Ordering::Relaxed));
        set_dword(key as _, &HIT_READ_NAME, HIT_READ.load(Ordering::Relaxed));
        set_dword(key as _, &LAST_ACL_NAME, LAST_ACL.load(Ordering::Relaxed));
        set_dword(key as _, &IN_NOTIFY_NAME, IN_NOTIFY.load(Ordering::Relaxed));
        set_dword(key as _, &LAST_NOTIFY_NAME, LAST_NOTIFY_HANDLE.load(Ordering::Relaxed));
        set_dword(key as _, &IN_ANY_NAME, IN_ANY.load(Ordering::Relaxed));
        set_dword(key as _, &IN_ALL_NAME, IN_ALL.load(Ordering::Relaxed));
        set_dword(key as _, &COMP_ALL_NAME, COMP_ALL.load(Ordering::Relaxed));
        set_dword(key as _, &COMP_URB_NAME, COMP_URB.load(Ordering::Relaxed));
        set_dword(key as _, &IN_MDL_NAME, IN_MDL.load(Ordering::Relaxed));
        set_dword(key as _, &IN_NO_BUF_NAME, IN_NO_BUF.load(Ordering::Relaxed));
        set_dword(key as _, &IN_ATT_NAME, IN_ATT.load(Ordering::Relaxed));
        set_dword(key as _, &LAST_ATT_LEN_NAME, LAST_ATT_LEN.load(Ordering::Relaxed));
        set_dword(key as _, &LAST_ATT_W0_NAME, LAST_ATT_W0.load(Ordering::Relaxed));
        set_dword(key as _, &LAST_ATT_W1_NAME, LAST_ATT_W1.load(Ordering::Relaxed));
        set_dword(key as _, &LAST_ATT_W2_NAME, LAST_ATT_W2.load(Ordering::Relaxed));
        wdf!(WdfRegistryClose, key);
    }
}

/// Demande l'écriture des compteurs (utilisable à DISPATCH_LEVEL).
unsafe fn request_flush() {
    let item = WORK_ITEM.load(Ordering::Relaxed);
    if !item.is_null() {
        wdf!(WdfWorkItemEnqueue, item as _);
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
        DRIVER.store(wdf_driver as _, Ordering::Relaxed);
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

    // Work item (PASSIVE_LEVEL) qui écrit les compteurs de diagnostic ; sans lui le filtre fonctionne, mais sans trace.
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
                    // (le handle de connexion ACL, b[0..2], dépend du contrôleur : on ne le teste pas)
                    12 if b[2..] == [0x08, 0x00, 0x04, 0x00, 0x04, 0x00, 0x52, 0x28, 0x00, 0xAF] => {
                        wdk::println!("AppleRemoteDriver: déverrouillage 0xAF -> handle 0x1d");
                        b[8] = 0x12;
                        b[9] = 0x1d;
                        HIT_UNLOCK.fetch_add(1, Ordering::Relaxed);
                        LAST_ACL.store(u32::from(b[0]) | (u32::from(b[1] & 0x0F) << 8), Ordering::Relaxed);
                        request_flush();
                    }
                    // abonnement CCCD : handle 0x29 -> 0x24 (notifications HID)
                    13 if b[2..] == [0x09, 0x00, 0x05, 0x00, 0x04, 0x00, 0x12, 0x29, 0x00, 0x01, 0x00] => {
                        b[9] = 0x24;
                        HIT_CCCD.fetch_add(1, Ordering::Relaxed);
                        request_flush();
                    }
                    // Windows lit la caractéristique Apple 0x3A (ce5ad0bc…) que la télécommande n'acquitte jamais : timeout ATT de 30 s,
                    // liaison coupée, clé d'appairage supprimée. On lit à la place le niveau de batterie (0x28) : réponse valide et immédiate.
                    11 if b[2..] == [0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x0A, 0x3A, 0x00] => {
                        wdk::println!("AppleRemoteDriver: lecture ATT 0x3A -> 0x28");
                        b[9] = 0x28;
                        HIT_READ.fetch_add(1, Ordering::Relaxed);
                        request_flush();
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
    let completed = COMP_ALL.fetch_add(1, Ordering::Relaxed) + 1;
    if completed <= 4 {
        request_flush();
    }
    if status >= 0 && ioctl_of(request) == IOCTL_INTERNAL_USB_SUBMIT_URB {
        let urb = urb_of(request) as *const UrbBulk;
        if COMP_URB.fetch_add(1, Ordering::Relaxed) < 4 {
            request_flush();
        }
        if !urb.is_null() && (*urb).function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER {
            let u = &*urb;
            let in_ptr = if u.transfer_flags & USBD_TRANSFER_DIRECTION_IN == 0 {
                null_mut()
            } else {
                let all = IN_ALL.fetch_add(1, Ordering::Relaxed) + 1;
                let ptr = if !u.transfer_buffer.is_null() {
                    u.transfer_buffer
                } else {
                    // BTHUSB décrit parfois ses tampons de lecture par un MDL plutôt que par un pointeur plat.
                    let mapped = mdl_system_va(u.transfer_buffer_mdl);
                    if mapped.is_null() { IN_NO_BUF.fetch_add(1, Ordering::Relaxed); } else { IN_MDL.fetch_add(1, Ordering::Relaxed); }
                    mapped
                };
                if all <= 8 || all % 256 == 0 {
                    request_flush();
                }
                ptr
            };
            if !in_ptr.is_null() && u.transfer_buffer_length > 10 {
                let b = core::slice::from_raw_parts_mut(in_ptr, u.transfer_buffer_length as usize);
                IN_ANY.fetch_add(1, Ordering::Relaxed);
                // Tout paquet ATT entrant (réponses d'écriture 0x13, erreurs 0x01, notifications 0x1b…) : on garde le dernier tel quel.
                if b[3] == 0x00 && b[5] == 0x00 && b[6] == 0x04 && b[7] == 0x00 {
                    let word = |at: usize| b.get(at..at + 4).map_or(0, |w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
                    LAST_ATT_LEN.store(b.len() as u32, Ordering::Relaxed);
                    LAST_ATT_W0.store(word(8), Ordering::Relaxed);
                    LAST_ATT_W1.store(word(12), Ordering::Relaxed);
                    LAST_ATT_W2.store(word(16), Ordering::Relaxed);
                    let seen = IN_ATT.fetch_add(1, Ordering::Relaxed) + 1;
                    if seen <= 16 || seen % 64 == 0 || b[8] == 0x01 || b[8] == 0x13 {
                        request_flush();
                    }
                }
                // Notification ATT (0x1b) sur le canal ATT (CID 4), quel que soit le handle de connexion ACL (b[0..2]).
                if b[3] == 0x00 && b[5] == 0x00 && b[6] == 0x04 && b[7] == 0x00 && b[8] == 0x1b {
                    let handle = u32::from(b[9]) | (u32::from(b[10]) << 8);
                    LAST_NOTIFY_HANDLE.store(handle, Ordering::Relaxed);
                    let seen = IN_NOTIFY.fetch_add(1, Ordering::Relaxed) + 1;
                    if seen <= 8 || seen % 64 == 0 {
                        request_flush();
                    }
                    if REWRITE_INBOUND.load(Ordering::Relaxed) && handle == 0x23 {
                        b[9] = 0x2b; // 0x23 (HID) -> 0x2b (BatteryPowerState)
                    }
                }
            }
        }
    }

    wdf!(WdfRequestComplete, request, status);
}

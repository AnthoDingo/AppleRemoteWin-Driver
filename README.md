# AppleRemoteDriver

This is a Rust port of the `Jack-R1/SiriRemoteDriver` KMDF lower filter driver for Windows. 

The original C driver sits below the `BTHUSB` stack and intercepts `URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER` URBs to:
1. Modify outgoing BLE ATT write requests (replacing handle IDs) to unlock the Siri Remote and subscribe to notifications.
2. Modify incoming BLE ATT notifications, rewriting the HID notification handle (0x23) to a Battery service handle (0x2b) so that Windows doesn't drop the packet and user-mode applications can receive it.

## Rust Implementation details

This project uses the official `windows-drivers` crates from Microsoft (`wdk`, `wdk-sys`, `wdk-build`, `wdk-alloc`).

- `DriverEntry` sets up the driver object and registers the `EvtDeviceAdd` callback.
- `FilterEvtDeviceAdd` initializes the WDF device as a filter (`WdfFdoInitSetFilter`) and configures a default parallel queue.
- `FilterEvtIoInternalDeviceControl` intercepts `IOCTL_INTERNAL_USB_SUBMIT_URB`. On outgoing requests (direction OUT), it inspects the transfer buffer and modifies the ATT handles.
- `FilterRequestCompletionRoutine` intercepts the responses (direction IN). It rewrites incoming HID notification handles before they reach the Windows Bluetooth stack.

## Building

Building Windows Drivers in Rust requires:
- Visual Studio 2022 with the "Desktop development with C++" workload
- Windows 11 SDK (e.g., 10.0.22621.0)
- Windows 11 WDK (Windows Driver Kit)
- `cargo` and `rustc` (Nightly might be required for some `wdk` features)

To build the driver:
```powershell
cargo build --release
```

The resulting `.sys` file will be in `target/release/`. You will then need to create an `.inf` file (you can adapt `filter.inx` from the original project) and sign the driver or enable test-signing mode on your Windows machine to install it.

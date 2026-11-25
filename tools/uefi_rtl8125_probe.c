#include "rtl8125_probe.h"

#include <efi.h>
#include <efilib.h>
#include <efipciio.h>

enum {
    REALTEK_8125 = 0x812510ecu, INTEL_82540 = 0x100e8086u,
    QWORD_DESCRIPTOR = 0x8a, QWORD_PAYLOAD = 0x2b, END_TAG = 0x79,
    MEMORY_RESOURCE = 0,
};

static bool config32(void *context, unsigned offset, uint32_t *value) {
    EFI_PCI_IO_PROTOCOL *pci = context;
    return !EFI_ERROR(uefi_call_wrapper(pci->Pci.Read, 5, pci, EfiPciIoWidthUint32, offset, 1, value));
}

static uint64_t little64(const UINT8 *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

static bool memory_bar(void *context, unsigned index, uint64_t base, bool wide, uint64_t *size) {
    EFI_PCI_IO_PROTOCOL *pci = context;
    VOID *resources = NULL;
    EFI_STATUS status = uefi_call_wrapper(pci->GetBarAttributes, 4, pci, (UINT8)index, NULL, &resources);
    if (EFI_ERROR(status) || !resources) return false;

    /* Принимаем один назначенный диапазон без трансляции. Размер берём у UEFI. */
    const UINT8 *bytes = resources;
    bool valid = bytes[0] == QWORD_DESCRIPTOR && bytes[1] == QWORD_PAYLOAD && !bytes[2] &&
                 bytes[3] == MEMORY_RESOURCE && bytes[46] == END_TAG &&
                 little64(bytes + 6) == (wide ? 64u : 32u) &&
                 little64(bytes + 14) == base && little64(bytes + 30) == 0;
    if (valid) *size = little64(bytes + 38);
    uefi_call_wrapper(BS->FreePool, 1, resources);
    return valid;
}

static bool mmio32(void *context, unsigned index, unsigned offset, uint32_t *value) {
    EFI_PCI_IO_PROTOCOL *pci = context;
    return !EFI_ERROR(uefi_call_wrapper(pci->Mem.Read, 6, pci, EfiPciIoWidthUint32,
                                        (UINT8)index, offset, 1, value));
}

static const CHAR16 *status_text(enum rtl8125_probe_status status) {
    switch (status) {
    case RTL8125_PROBE_CONFIG_READ: return L"PCI configuration read failed";
    case RTL8125_PROBE_NOT_DEVICE: return L"PCI identity changed";
    case RTL8125_PROBE_CLASS: return L"unexpected Ethernet class or PCI header";
    case RTL8125_PROBE_BAR: return L"BAR2 unassigned, too short, or not described by firmware";
    case RTL8125_PROBE_MEMORY_DISABLED: return L"PCI memory decode disabled";
    case RTL8125_PROBE_POWER: return L"PCI power state D0 not verified";
    case RTL8125_PROBE_MMIO_READ: return L"EFI PCI I/O could not read TxConfig";
    case RTL8125_PROBE_INVALID_TX_CONFIG: return L"TxConfig read returned ffffffff";
    default: return L"unknown result";
    }
}

static void describe_device(EFI_PCI_IO_PROTOCOL *pci, uint32_t id) {
    UINTN segment, bus, slot, function;
    EFI_STATUS status = uefi_call_wrapper(pci->GetLocation, 5, pci, &segment, &bus, &slot, &function);
    if (!EFI_ERROR(status))
        Print(L"PCI %04x:%02x:%02x.%x %04x:%04x\r\n", segment, bus, slot, function,
              (UINTN)(id & 0xffff), (UINTN)(id >> 16));
    else
        Print(L"PCI %04x:%04x location unavailable (%r)\r\n", (UINTN)(id & 0xffff),
              (UINTN)(id >> 16), status);

    uint32_t identity, subsystem;
    if (config32(pci, 8, &identity) && config32(pci, 0x2c, &subsystem))
        Print(L"Revision=%02x Class=%06x Subsystem=%04x:%04x\r\n", (UINTN)(identity & 0xff),
              (UINTN)(identity >> 8), (UINTN)(subsystem & 0xffff), (UINTN)(subsystem >> 16));
}

static void describe_intel_bar(EFI_PCI_IO_PROTOCOL *pci) {
    uint32_t raw;
    if (!config32(pci, 0x10, &raw) || (raw & 7)) return;
    uint64_t base = raw & ~UINT32_C(15), size;
    if (base && memory_bar(pci, 0, base, false, &size))
        Print(L"BAR0 MEM base=%lx length=%lx\r\n", (UINT64)base, (UINT64)size);
}

static bool observe_realtek(EFI_PCI_IO_PROTOCOL *pci) {
    const struct rtl8125_probe_io io = {
        .context = pci, .config32 = config32, .memory_bar = memory_bar, .mmio32 = mmio32,
    };
    struct rtl8125_probe_result result;
    enum rtl8125_probe_status status = rtl8125_probe(&io, &result);
    if (result.bar_size)
        Print(L"BAR2 MEM base=%lx length=%lx\r\n", (UINT64)result.bar_base, (UINT64)result.bar_size);
    if (status != RTL8125_PROBE_OK) {
        Print(L"RTL8125 TxConfig skipped or unreadable: %s\r\n", status_text(status));
        return false;
    }
    Print(L"RTL8125 BAR2 TxConfig=%08x XID=%03x\r\n", (UINTN)result.tx_config, (UINTN)result.xid);
    return true;
}

static void wait_for_console(EFI_SYSTEM_TABLE *system_table) {
    if (!system_table->ConIn || !system_table->ConIn->WaitForKey) return;
    EFI_EVENT timer;
    if (EFI_ERROR(uefi_call_wrapper(BS->CreateEvent, 5, EVT_TIMER, TPL_CALLBACK, NULL, NULL, &timer)))
        return;
    if (!EFI_ERROR(uefi_call_wrapper(BS->SetTimer, 3, timer, TimerRelative, 300000000ULL))) {
        EFI_EVENT events[] = {system_table->ConIn->WaitForKey, timer};
        UINTN event_index;
        Print(L"Press a key to return. Waits up to 30 seconds.\r\n");
        EFI_STATUS waited = uefi_call_wrapper(BS->WaitForEvent, 3, 2, events, &event_index);
        if (!EFI_ERROR(waited) && event_index == 0) {
            EFI_INPUT_KEY key;
            uefi_call_wrapper(system_table->ConIn->ReadKeyStroke, 2, system_table->ConIn, &key);
        }
    }
    uefi_call_wrapper(BS->CloseEvent, 1, timer);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system_table) {
    InitializeLib(image, system_table);
    Print(L"RTL8125 PCI probe start\r\n");
    EFI_GUID guid = EFI_PCI_IO_PROTOCOL_GUID;
    EFI_HANDLE *handles = NULL;
    UINTN count = 0, scanned = 0, targets = 0, xids = 0, intel = 0;
    EFI_STATUS status = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol,
                                         &guid, NULL, &count, &handles);
    if (EFI_ERROR(status) && status != EFI_NOT_FOUND) {
        Print(L"RTL8125 PCI probe enumeration failed (%r)\r\n", status);
        return status;
    }
    for (UINTN i = 0; i < count; ++i) {
        EFI_PCI_IO_PROTOCOL *pci = NULL;
        status = uefi_call_wrapper(BS->HandleProtocol, 3, handles[i], &guid, (VOID **)&pci);
        if (EFI_ERROR(status)) continue;
        uint32_t id;
        if (!config32(pci, 0, &id) || (id & 0xffff) == 0xffff) continue;
        ++scanned;
        if (id != REALTEK_8125 && id != INTEL_82540) continue;
        describe_device(pci, id);
        if (id == REALTEK_8125) {
            ++targets;
            if (observe_realtek(pci)) ++xids;
        } else {
            ++intel;
            describe_intel_bar(pci);
        }
    }
    if (handles) uefi_call_wrapper(BS->FreePool, 1, handles);
    Print(L"RTL8125 PCI probe complete: PCI=%u RTL8125=%u XID=%u E1000=%u\r\n",
          scanned, targets, xids, intel);
    if (targets) wait_for_console(system_table);
    return EFI_SUCCESS;
}

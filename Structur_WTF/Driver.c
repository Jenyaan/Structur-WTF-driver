#include <ntddk.h>
#include "Trigger.h"

#define IOCTL_ADD_FILTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DEL_FILTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


NTSTATUS DriverDeviceControl(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    UINT64 id_ip;


    irpSp = IoGetCurrentIrpStackLocation(irp);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ADD_FILTER: {
        ULONG* inputIp = (ULONG*)irp->AssociatedIrp.SystemBuffer;
        if (inputIp) {
            KdPrint(("IOCTL_ADD_RULE received: 0x%X\n", *inputIp));
            id_ip = FilterAdd(*inputIp);

            if (id_ip != 0) {
                KdPrint(("Filter added successfully. ID: 0x%llX\n", id_ip));

                ULONG filterIdLower = (ULONG)(id_ip & 0xFFFFFFFF);

                ULONG* outputBuffer = (ULONG*)irp->AssociatedIrp.SystemBuffer;
                if (outputBuffer) {
                    *outputBuffer = filterIdLower;
                    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &filterIdLower, sizeof(ULONG));
                    irp->IoStatus.Information = sizeof(ULONG);
                    status = STATUS_SUCCESS;
                }

            }
            else {
                KdPrint(("Failed to add filter.\n"));
                status = STATUS_UNSUCCESSFUL;
            }
        }

        break;
    }

    case IOCTL_DEL_FILTER: {
        UINT64* inputIp = (UINT64*)irp->AssociatedIrp.SystemBuffer;
        KdPrint(("IOCTL_DEL_RULE received: 0x%llX\n", *inputIp));
        FilterDel(*inputIp);
        irp->IoStatus.Information = 0;
        status = STATUS_SUCCESS;
        break;
    }

    default:
        KdPrint(("Unknown IOCTL code: 0x%X\n", irpSp->Parameters.DeviceIoControl.IoControlCode));
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}


NTSTATUS DriverCreateClose(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(_In_ PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);

    WfpCleanup();
    KdPrint(("Unloading the driver...\n"));

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    KdPrint(("Loading the driver...\n"));
    driverObject->DriverUnload = UnloadDriver;

    driverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

    if (!(NT_SUCCESS(WfpInit(driverObject)))) {
        KdPrint(("Driver failed to load!\n"));
        return STATUS_UNSUCCESSFUL;
    }
    KdPrint(("Driver loaded!\n"));

    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\WTF_FILTER");
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\WTF_FILTER");

    NTSTATUS status = IoCreateDevice(
        driverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (NT_SUCCESS(status)) {
        status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    }

    return STATUS_SUCCESS;
}

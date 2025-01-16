#include "Trigger.h"
#include "Config.h"

NTSTATUS WfpInit(PDRIVER_OBJECT driverObject) {
	engineHandle = NULL;
	filterDeviceObject = NULL;

	// Create a device object (used in the callout registration)
	NTSTATUS status = IoCreateDevice(driverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &filterDeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create the filter device object (0x%X).\n", status));
		return status;
	}

	// Open a session to the filter engine (https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to open the filter engine (0x%X).\n", status));
		return status;
	}

	// Register a callout with the filter engine
	status = CalloutRegister();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to register the filter callout (0x%X).\n", status));
		return status;
	}

	// Add the callout to the system (FWPM_LAYER_INBOUND_TRANSPORT_V4 layer)
	status = CalloutAdd();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to add the filter callout (0x%X).\n", status));
		return status;
	}

	// Add a sublayer to the system
	status = SublayerAdd();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to add the sublayer (0x%X).\n", status));
		return status;
	}

	//status = Filter_func();
	//if (!NT_SUCCESS(status)) {
	//	KdPrint(("Failed to add the filter (0x%X).\n", status));
	//	return status;
	//}
	return TRUE;
}

NTSTATUS CalloutRegister() {
	registerCalloutId = 0;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout0_
	FWPS_CALLOUT callout = {
		.calloutKey = CALLOUT_GUID,		// Unique GUID that identifies the callout
		.flags = 0,					// None
		.classifyFn = CalloutFilter,		// Callout function used to process network data (our ICMP packets)
		.notifyFn = CalloutNotify,		// Callout function used to receive notifications from the filter engine, not needed in our case (but needs to be defined)
		.flowDeleteFn = NULL,				// Callout function used to process terminated data, not needed in our case (does't need to be defined)
	};

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
	return FwpsCalloutRegister(filterDeviceObject, &callout, &registerCalloutId);
}

NTSTATUS CalloutAdd() {
	addCalloutId = 0;

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
	FWPM_CALLOUT callout = {
		.flags = 0,								 // None
		.displayData.name = L"MaliciousCalloutName",
		.displayData.description = L"MaliciousCalloutDescription",
		.calloutKey = CALLOUT_GUID,					 // Unique GUID that identifies the callout, should be the same as the registered FWPS_CALLOUT GUID
		.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4,  // https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmcalloutadd0
	return FwpmCalloutAdd(engineHandle, &callout, NULL, &addCalloutId);
}

VOID CalloutFilter(
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	//UNREFERENCED_PARAMETER(inFixedValues);
	//UNREFERENCED_PARAMETER(inMetaValues);
	//UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	/* Only accept packets which:
		*   1) Have a valid layerData pointer
		*   2) Use ICMP
		*   3) Have a valid IP header (size > 0)
	*/
	if (
		!layerData ||
		inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8 != IPPROTO_ICMP ||
		inMetaValues->ipHeaderSize <= 0
		) {

		return;
	}
	KdPrint(("Received an ICMP packet!\n"));

	return;
}

NTSTATUS CalloutNotify(
	FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
	const GUID* filterKey,
	FWPS_FILTER* filter
) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	// Needs to be defined, but isn't required for anything.
	return STATUS_SUCCESS;
}

NTSTATUS SublayerAdd() {
	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
	FWPM_SUBLAYER sublayer = {
		.displayData.name = L"MaliciousSublayerName",
		.displayData.name = L"MaliciousSublayerDescription",
		.subLayerKey = SUB_LAYER_GUID,			// Unique GUID that identifies the sublayer
		.weight = 65535,					// Max UINT16 value, higher weight means higher priority
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayeradd0
	return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

NTSTATUS FilterDel(UINT64 inputIp) {

	NTSTATUS status = FwpmFilterDeleteById(engineHandle, inputIp);
	if (NT_SUCCESS(status)) {
		KdPrint(("Filter removed successfully for IP: %lu\n", inputIp));
	}
	else {
		KdPrint(("Failed to remove filter. Status: 0x%08X\n", status));
	}

	return status;
}

UINT64 FilterAdd(ULONG blockedIp) {
	filterId = 0; // Initialize the filterId to 0
	UINT64 weightValue = 0xFFFFFFFFFFFFFFFF; // Max UINT64 value
	FWP_VALUE weight = { .type = FWP_UINT64, .uint64 = &weightValue }; // Weight variable, higher weight means higher priority

	// Условие для блокировки удалённого IP-адреса
	FWPM_FILTER_CONDITION conditions[1] = { 0 };
	conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS; // Условие для удалённого IP
	conditions[0].matchType = FWP_MATCH_EQUAL; // Сравнение на равенство
	conditions[0].conditionValue.type = FWP_UINT32; // Тип значения: 32-битный адрес
	conditions[0].conditionValue.uint32 = blockedIp; // Заблокированный IP-адрес

	// Настройка фильтра
	FWPM_FILTER filter = {
		.displayData.name = L"MaliciousFilterCalloutName",
		.displayData.description = L"MaliciousFilterCalloutDescription",
		.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4, // Фильтрация на транспортном уровне (IPv4)
		.subLayerKey = SUB_LAYER_GUID, // GUID подслоя
		.weight = weight, // Приоритет фильтра
		.numFilterConditions = 1, // Количество условий
		.filterCondition = conditions, // Условия фильтрации
		.action.type = FWP_ACTION_BLOCK, // Инспекция пакета
		.action.calloutKey = CALLOUT_GUID, // GUID коллаута
	};
	KdPrint(("IOCTL_ADD_RULE Block received\n"));
	FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);

	// Добавление фильтра в систему
	return filterId;
}

VOID TermFilterDeviceObject() {
	KdPrint(("Terminating the device object.\n"));

	if (filterDeviceObject) {
		// Remove the filter device object
		IoDeleteDevice(filterDeviceObject);
		filterDeviceObject = NULL;
	}
}

VOID TermCalloutData() {
	KdPrint(("Terminating filters, sublayers and callouts.\n"));

	if (engineHandle) {

		// Remove the added filters and sublayers 
		if (filterId) {
			FwpmFilterDeleteById(engineHandle, filterId);
			FwpmSubLayerDeleteByKey(engineHandle, &SUB_LAYER_GUID);
			filterId = 0;
		}

		// Remove the callout from the FWPM_LAYER_INBOUND_TRANSPORT_V4 layer
		if (addCalloutId) {
			FwpmCalloutDeleteById(engineHandle, addCalloutId);
			addCalloutId = 0;
		}

		// Unregister the callout
		if (registerCalloutId) {
			FwpsCalloutUnregisterById(registerCalloutId);
			registerCalloutId = 0;
		}
	}
}

VOID TermWfpEngine() {
	KdPrint(("Terminating the filter engine handle.\n"));

	if (engineHandle) {

		// Close the filter engine handle
		FwpmEngineClose(engineHandle);
		engineHandle = NULL;
	}
}

VOID WfpCleanup() {
	TermCalloutData();
	TermWfpEngine();
	TermFilterDeviceObject();
}
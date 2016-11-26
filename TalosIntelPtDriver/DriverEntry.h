/**********************************************************************
 *  Driver Model 2016
 *	Filename: DriverEntry.h
 *	Implement Driver Entry point and startup functions prototypes
 *	Last revision: 10/07/2016
 *
 *  Copyright� 2016 Andrea Allievi, Richard Johnson
 *	TALOS Research and Intelligence Group and Microsoft Ltd
 *	All right reserved
 **********************************************************************/
#pragma once
#include "IntelPt.h"

// The PMI Handler function prototype
typedef VOID (*PMIHANDLER)(PKTRAP_FRAME TrapFrame);

typedef struct _DRIVER_GLOBAL_DATA {
	BOOLEAN bPtSupported;								// TRUE if the Intel Pt are supported
	BOOLEAN bPmiInstalled;								// TRUE if I have correctly installed the PMI Handler routine
	BOOLEAN bCpuX2ApicMode;								// TRUE if the system processors are in x2Apic Mode
	DWORD dwNumProcs;									// The number of the system processors
	PDEVICE_OBJECT pMainDev;							// The main device object 
	PMIHANDLER pOldPmiHandler;							// The OLD PMI handler routine (if any)
	TCHAR pmiEventName[0x80];							// The PMI event name shared between user and kernel mode
	PRKEVENT pPmiEvent;									// The PMI event 
	HANDLE hPmiEvent;									// The PMI event kernel handle
	DWORD * lpApicBase;									// The APIC I/O memory VA
	LVT_Entry pmiVectDesc;								// The starting PMI LVT Vector descriptor
	PER_PROCESSOR_PT_DATA procData[ANYSIZE_ARRAY];		// An array of PER_PROCESSOR_PT_DATA structure (1 per processor)
	// INTEL_PT_CAPABILITIES ptCapabilities;				// The Intel Processor Trace capabilities
	// PKINTERRUPT pkPmiInterrupt = NULL;				// The PMI Interrupt Object
}DRIVER_GLOBAL_DATA, *PDRIVER_GLOBAL_DATA;
extern DRIVER_GLOBAL_DATA * g_pDrvData;

// Driver entry point
DDKBUILD NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);

// Driver unload routine
VOID DriverUnload(PDRIVER_OBJECT pDrvObj);

// Create the shared PMI event
NTSTATUS CreateSharedPmiEvent(LPTSTR lpEvtName);

// The Inter-processor DPC type
enum DPC_TYPE {
	DPC_TYPE_START_PT,
	DPC_TYPE_PAUSE_PT,
	DPC_TYPE_CLEAR_PT
};
// The Inter-processor DPC structure
struct IPI_DPC_STRUCT {
	DPC_TYPE Type;
	DWORD dwCpu;
	IO_STATUS_BLOCK ioSb;
	KEVENT kEvt;
};

// DPC routine (needed by start/stop/pause the PT on a target CPU)
VOID IoCpuIpiDpc(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

/**********************************************************************
 *  Intel Processor Trace Driver
 *	Filename: IntelPt.cpp
 *	Defines the Intel Processor Trace driver function prototypes
 *	Last revision: 10/07/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *	TALOS Research and Intelligence Group and Microsoft Ltd
 *	All right reserved
 **********************************************************************/

#pragma once
#include "Intel_Defs.h"

struct INTEL_PT_CAPABILITIES {
	BOOLEAN bCr3Filtering : 1;						// [0] - CR3 Filtering Support (Indicates that IA32_RTIT_CTL.CR3Filter can be set to 1)
	BOOLEAN bConfPsbAndCycSupported : 1;			// [1] - Configurable PSB and Cycle-Accurate Mode Supported (IA32_RTIT_CTL.PSBFreq can be set to a non-zero value, IA32_RTIT_STATUS.PacketByteCnt can be set to a non-zero value)
	BOOLEAN bIpFiltering : 1;						// [2] - IP Filtering and TraceStop	supported, and Preserve Intel PT MSRs across warm reset
	BOOLEAN bMtcSupport : 1;						// [3] - IA32_RTIT_CTL.MTCEn can be set to 1, and MTC packets will be generated (section 36.2.5)
	BOOLEAN bTopaOutput : 1;						// [4] - Tracing can be enabled with IA32_RTIT_CTL.ToPA = 1, hence utilizing the ToPA output scheme (section 36.2.4.2)
	BOOLEAN bTopaMultipleEntries : 1;				// [5] - ToPA tables can hold any number of output entries, up to the maximum allowed by the MaskOrTableOffset field of IA32_RTIT_OUTPUT_MASK_PTRS
	BOOLEAN bSingleRangeSupport : 1;				// [6] - Single-Range Output Supported
	BOOLEAN bTransportOutputSupport : 1;			// [7] - Output to Trace Transport Subsystem Supported (Setting IA32_RTIT_CTL.FabricEn to 1 is supported)
	BOOLEAN bIpPcksAreLip : 1;						// [8] - IP Payloads are LIP (Specifies if the generated packets that contain IP payloads have LIP values or RIP values)	<-- Very important
	BYTE numOfAddrRanges;							// + 0x01 - Number of Address Ranges - specifies the number ADDRn_CFG field supported in IA32_RTIT_CTL for IP filtering	and IP TraceStop
	SHORT mtcPeriodBmp;								// + 0x02 - Bitmap of supported MTC Period Encodings
	SHORT cycThresholdBmp;							// + 0x04 - Bitmap of supported Cycle Threshold values
	SHORT psbFreqBmp;								// + 0x06 - Bitmap of supported	Configurable PSB Frequency encoding
};

enum PT_PROCESSOR_STATE {
	PT_PROCESSOR_STATE_ERROR = -1,
	PT_PROCESSOR_STATE_DISABLED = 0,
	PT_PROCESSOR_STATE_STOPPED,
	PT_PROCESSOR_STATE_TRACING,
	PT_PROCESSOR_STATE_PAUSED
};

// Describe a processor trace range
struct PT_TRACE_RANGE {
	LPVOID lpStartVa;
	LPVOID lpEndVa;
	BOOLEAN bStopTrace;
};

// Data structure that describe the trace type request
struct PT_TRACE_DESC {
	PEPROCESS peProc;						// The Process to trace (if any)
	DWORD dwNumOfRanges;					// Number of range to trace
	BOOLEAN bTraceKernel;					// TRUE if I need to trace even Kernel mode components
	struct PT_TRACE_RANGE Ranges[4];
};

// The trace options Bitmask
union TRACE_OPTIONS {
	struct {
		BOOLEAN bTraceCycPcks : 1;					// [0] - Enables/disables CYC Packet (Cycle Count Packet - default is 0)
		BOOLEAN bTraceMtcPcks : 1;					// [1] - Enables/disables MTC Packet (Wall-clock time packets - default is 0)
		BOOLEAN bTraceTscPcks : 1;					// [2] - Enables/disables TSC Packet (Time Stamp packets - default is 0)
		BOOLEAN bTraceBranchPcks : 1;				// [3] - Enables/disables COFI-based packets: FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec, MODE.TSX.		(default is 1)
		BOOLEAN bUseTopa : 1;						// [4] - Enable/disable the usage of Table of Physical Address (if available, default is 1)
		BOOLEAN bEnableRetCompression : 1;			// [5] - Enables/disables RET compression (default is 1)
		BOOLEAN Reserved : 2;						// [6:7] - Reserved
		BYTE MTCFreq : 4;							// [8:11] - MTC packet Frequency, which is based on the core crystal clock, or Always Running Timer (ART)
		BYTE CycThresh : 4;							// [12:15] - CYC packet threshold. CYC packets will be sent with the first eligible packet after N cycles have passed since the last CYC packet
		BYTE PSBFreq : 4;							// [16:19] - The frequency of PSB packets. PSB packet frequency is based on the number of Intel PT packet bytes output
	} Fields;
	DWORD All;
};

struct PER_PROCESSOR_PT_DATA {
	union {
		struct {
			LPVOID lpTraceBuffVa;					// + 0x00 - Kernel VA Pointer to a contiguous memory buffer
			ULONG_PTR lpTraceBuffPhysAddr;			// + 0x08 - The physical address of the contiguous memory buffer
		} Simple;
		struct {
			LPVOID lpTopaVa;
			ULONG_PTR lpTopaPhysAddr;
		} ToPA;
	} u;

	TRACE_OPTIONS TraceOptions;						// + 0x10 - The trace packets options bitmask
	QWORD qwBuffSize;								// + 0x18 - The physical buffer size
	PMDL pTraceMdl;									// + 0x20 - The MDL used for mapping pages
	LPVOID lpUserVa;								// + 0x28 - The User Mode VA
	PEPROCESS lpMappedProc;							// + 0x30 - The process for witch the User VA belongs to (usually the user-mode controlling app)	
	PT_PROCESSOR_STATE curState;					// + 0x38 - Current processor state
	BOOLEAN bUseTopa;								// + 0x3C - TRUE if this processor uses ToPa
	BOOLEAN bBuffIsFull;							// + 0x3D - TRUE if the ToPa or Simple buffer is full
	ULONGLONG PacketByteCount;						// + 0x40 - The total number of TRACE packets acquired by this processor

	// Tracing state data:
	PEPROCESS lpTargetProc;							// + 0x48 - The target process to monitor (NULL if All process are going to be traced)
	ULONG_PTR lpTargetProcCr3;						// + 0x50 - The process to monitor CR3 (NULL if All process are going to be traced)
	DWORD dwNumOfActiveRanges;						// + 0x58 - Number of active ranges
	PT_TRACE_RANGE IpRanges[4];						// + 0x60
};

// Define the number of trailing zeroes in a page aligned virtual address.
// This is used as the shift count when shifting virtual addresses to
// virtual page numbers.
#define PAGE_SHIFT 12L
#define PAGE_SIZE 0x1000

// Check the Intel Processor Trace support on this processor
NTSTATUS CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap);

// Enable the Intel PT for current processor
NTSTATUS StartProcessTrace(PT_TRACE_DESC trace_desc, QWORD qwBuffSize = 0ui64);
NTSTATUS StartProcessTrace(DWORD dwProcId, QWORD qwBuffSize = 0ui64);
// Disable Intel PT for the current processor
NTSTATUS StopAndDisablePt();
// Put the tracing in PAUSE mode
NTSTATUS PauseResumeTrace(BOOLEAN bPause);
// Map a physical page buffer to the current User-mode process 
NTSTATUS MapTracePhysBuffToUserVa(DWORD dwCpuId);
// Unmap the memory-mapped physical memory from User mode
NTSTATUS UnmapTraceBuffToUserVa(DWORD dwCpuId);
// Allocate a Trace buffer for the current CPU
NTSTATUS AllocPtBuffer(QWORD qwSize, BOOLEAN bUseToPA = TRUE);
// Free the Trace buffer resources for current CPU
NTSTATUS FreePtResources();
// Allocate and set a ToPA for the current CPU
NTSTATUS AllocAndSetCpuTopa(DWORD dwCpuId, QWORD qwReqBuffSize);
// Set the trace options for a particular CPU
NTSTATUS SetTraceOptions(DWORD dwCpuId, TRACE_OPTIONS options);
// Get the active Trace options for a particular CPU
NTSTATUS GetTraceOptions(DWORD dwCpuId, TRACE_OPTIONS * pOptions);
// Allocate and set a ToPA for the current CPU (with the Windows API)
NTSTATUS AllocAndSetCpuTopaSlow(DWORD dwCpuId, QWORD qwReqBuffSize);

// Register the LVT (Local Vector Table) PMI interrupt
NTSTATUS RegisterPmiInterrupt();
// Deregister and remove the LVT PMI interrupt 
NTSTATUS UnregisterPmiInterrupt();

// The PMI LVT handler routine (Warning! This should run at very high IRQL)
VOID IntelPtPmiHandler(PKTRAP_FRAME pTrapFrame);
BOOLEAN PmiInterruptHandler(struct _KINTERRUPT *Interrupt, PVOID ServiceContext);
// The PMI DPC routine
VOID IntelPmiDpc(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
// The PMI Work Item
VOID IntelPmiWorkItem(PVOID Parameter);



// Undocumented NT functions
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Process);
NTKERNELAPI NTSTATUS ZwCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
NTKERNELAPI BOOLEAN HalEnableInterrupt(PKINTERRUPT pkInterrupt);
NTKERNELAPI BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS Process);
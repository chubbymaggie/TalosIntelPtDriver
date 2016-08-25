/**********************************************************************
*   Intel Processor Trace Driver
*	Filename: IntelPt.cpp
*	Implement the Intel Processor Trace driver
*	Last revision: 08/15/2016
*
*   Copyright© 2016 Andrea Allievi, Richard Johnson
*	TALOS Research and Intelligence Group
*	All right reserved
**********************************************************************/

#include "stdafx.h"
#include "DriverEntry.h"
#include "IntelPt.h"
#include "Debug.h"
#include <intrin.h>

#define DirectoryTableBaseOffset 0x28

#pragma region Intel PT management functions
#pragma code_seg(".nonpaged")
NTSTATUS CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap)
{
	INTEL_PT_CAPABILITIES ptCap = { 0 };		// The processor PT capabilities
	int cpuid_ctx[4] = { 0 };					// EAX, EBX, ECX, EDX

	// Processor support for Intel Processor Trace is indicated by CPUID.(EAX=07H,ECX=0H):EBX[bit 25] = 1.
	__cpuidex(cpuid_ctx, 0x07, 0);
	if ((cpuid_ctx[1] & (1 << 25)) == 0) 
		return STATUS_NOT_SUPPORTED;

	// We can return now if capability struct was not requested
	if (!lpPtCap)
		return STATUS_SUCCESS;

	// Enumerate the Intel Processor Trace capabilities
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 0);
	ptCap.bCr3Filtering = (cpuid_ctx[1] & (1 << 0)) != 0;					// EBX
	ptCap.bConfPsbAndCycSupported = (cpuid_ctx[1] & (1 << 1)) != 0;
	ptCap.bIpFiltering = (cpuid_ctx[1] & (1 << 2)) != 0;
	ptCap.bMtcSupport = (cpuid_ctx[1] & (1 << 3)) != 0;
	ptCap.bTopaOutput = (cpuid_ctx[2] & (1 << 0)) != 0;						// ECX
	ptCap.bTopaMultipleEntries = (cpuid_ctx[2] & (1 << 1)) != 0;
	ptCap.bSingleRangeSupport = (cpuid_ctx[2] & (1 << 2)) != 0;
	ptCap.bTransportOutputSupport = (cpuid_ctx[2] & (1 << 3)) != 0;
	ptCap.bIpPcksAreLip = (cpuid_ctx[2] & (1 << 31)) != 0;

	// Enumerate secondary capabilities (sub-leaf 1)
	if (cpuid_ctx[0] != 0)
	{
		RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
		__cpuidex(cpuid_ctx, 0x14, 1);
		ptCap.numOfAddrRanges = (BYTE)(cpuid_ctx[0] & 0x7);
		ptCap.mtcPeriodBmp = (SHORT)((cpuid_ctx[0] >> 16) & 0xFFFF);
		ptCap.cycThresholdBmp = (SHORT)(cpuid_ctx[1] & 0xFFFF);
		ptCap.psbFreqBmp = (SHORT)((cpuid_ctx[1] >> 16) & 0xFFFF);
	}
 
	*lpPtCap = ptCap;
	return STATUS_SUCCESS;
}

// Enable the Intel PT trace for current processor
NTSTATUS StartProcessTrace(PEPROCESS pTargetEproc, QWORD qwBuffSize) 
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;				// Returned NTSTATUS value
	INTEL_PT_CAPABILITIES ptCap = { 0 };					// The per-processor PT capabilities
	PER_PROCESSOR_PT_DATA * lpProcPtData = NULL;			// The per processor data structure
	BOOLEAN bBuffAllocated = FALSE;							// TRUE if I have allocated the Trace Buffer
	ULONG_PTR targetCr3 = 0;								// The target CR3 value
	KIRQL kOldIrql = KeGetCurrentIrql();					// The current IRQL
	ULONG curProcId = KeGetCurrentProcessorNumber();		// Current processor number

	// PT data structures
	MSR_RTIT_CTL_DESC rtitCtlDesc = { 0 };
	MSR_RTIT_STATUS_DESC rtitStatusDesc = { 0 };
	MSR_RTIT_OUTPUTBASE_DESC rtitOutBaseDesc = { 0 };
	MSR_RTIT_OUTPUT_MASK_PTRS_DESC rtitOutMasksDesc = { 0 };

	if (!pTargetEproc) return STATUS_INVALID_PARAMETER;

	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	if (!ptCap.bSingleRangeSupport) return STATUS_NOT_SUPPORTED;
	if (!ptCap.bCr3Filtering) return STATUS_NOT_SUPPORTED;	

	// To proper read the value of the CR3 register of a target process, the KiSwapProcess routines does this:
	// From KTHREAD go to ETHREAD, then use the ApcState field to return back to a EPROCESS
	// Finally grab it from peProc->DirectoryTableBase (offset + 0x28) 
	targetCr3 = ((ULONG_PTR *)pTargetEproc)[5];

	// Check the found target CR3 (it should have the last 12 bits set to 0, due to the PFN standard)
	if ((targetCr3 & 0xFFF) != 0) return STATUS_INVALID_ADDRESS;
	DbgPrint("[TalosIntelPT] Starting Intel Processor Trace for processor %i. Target CR3: 0x%llX\r\n", curProcId, targetCr3);
	
	lpProcPtData = &g_pDrvData->procData[curProcId];
	lpProcPtData->lpTargetProcCr3 = targetCr3;
	lpProcPtData->lpTargetProc = pTargetEproc;

	// Set the default trace options if needed
	if (lpProcPtData->TraceOptions.All == 0)
	{
		lpProcPtData->TraceOptions.Fields.bTraceBranchPcks = TRUE;
		lpProcPtData->TraceOptions.Fields.bUseTopa = TRUE;
	}

	//Step 0. Allocate the pysical continuous memory
	if (!qwBuffSize) return STATUS_INVALID_PARAMETER_2;
	if (!lpProcPtData->qwBuffSize || lpProcPtData->qwBuffSize != qwBuffSize)
	{
		BOOLEAN bUseTopa = (lpProcPtData->TraceOptions.Fields.bUseTopa == 1);

		ntStatus = AllocPtBuffer(qwBuffSize, bUseTopa);
		if (!NT_SUCCESS(ntStatus)) 
		{
			DbgPrint("[TalosIntelPT] Error: unable to allocate the trace buffer.\r\n");
			lpProcPtData->lpTargetProcCr3 = NULL;
			return STATUS_INVALID_PARAMETER_2;
		}

		bBuffAllocated = TRUE;
	}

	// Raise the IRQL (we don't want to be swapped out)
	if (kOldIrql < DISPATCH_LEVEL)
		KeRaiseIrql(DISPATCH_LEVEL, &kOldIrql);

	// Step 1. Disable all the previous PT flags
	rtitCtlDesc.All = __readmsr(MSR_IA32_RTIT_CTL);
	rtitCtlDesc.Fields.TraceEn = 0;
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	// Clear IA32_RTIT_STATUS MSR
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	rtitStatusDesc.Fields.Error = 0;						// See Intel's manuals, section 36.3.2.1
	rtitStatusDesc.Fields.Stopped = 0;
	rtitStatusDesc.Fields.ContextEn = 0;
	rtitStatusDesc.Fields.PacketByteCnt = 0;				// Restore the Byte counter to 0
	lpProcPtData->PacketByteCount = 0;						// In both values
	__writemsr(MSR_IA32_RTIT_STATUS, rtitStatusDesc.All);

	// Set the IA32_RTIT_OUTPUT and IA32_RTIT_OUTPUT_MASK_PTRS MSRs
	if (lpProcPtData->bUseTopa) 
	{
		// Use Table of Physical Addresses 
		rtitCtlDesc.Fields.ToPA = 1;

		// Set the proc_trace_table_base
		rtitOutBaseDesc.All = (ULONGLONG)lpProcPtData->u.ToPA.lpTopaPhysAddr;
		__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, rtitOutBaseDesc.All);

		// Set the proc_trace_table_offset: indicates the entry of the current table that is currently in use
		rtitOutMasksDesc.Fields.LowerMask = 0x7F;
		rtitOutMasksDesc.Fields.MaskOrTableOffset = 0;		// Start from the first entry in the table
		rtitOutMasksDesc.Fields.OutputOffset = 0;			// Start at offset 0
		__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, rtitOutMasksDesc.All);
	}
	else 
	{
		// Use the single range output implementation
		rtitCtlDesc.Fields.ToPA = 0;						// We use the single-range output scheme
		rtitOutBaseDesc.All = (ULONGLONG)lpProcPtData->u.Simple.lpTraceBuffPhysAddr;
		__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, rtitOutBaseDesc.All);

		rtitOutMasksDesc.All = (1 << PAGE_SHIFT) - 1;		// The physical page always has low 12 bits NULL
		__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, rtitOutMasksDesc.All);
	}

	// Set the page table filter for the target process 
	__writemsr(MSR_IA32_RTIT_CR3_MATCH, (ULONGLONG)targetCr3);

	// Set the TRACE options
	TRACE_OPTIONS & options = lpProcPtData->TraceOptions;
	rtitCtlDesc.Fields.CR3Filter = 1;
	rtitCtlDesc.Fields.FabricEn = 0;
	rtitCtlDesc.Fields.Os = 0;								// XXX: Currently hardcoding single usermode process tracing
	rtitCtlDesc.Fields.User = 1;							// Trace the user mode process
	rtitCtlDesc.Fields.BranchEn = options.Fields.bTraceBranchPcks;

	if (ptCap.bMtcSupport) 
	{
		rtitCtlDesc.Fields.MTCEn = options.Fields.bTraceMtcPcks;
		if ((1 << options.Fields.MTCFreq) & ptCap.mtcPeriodBmp)
			rtitCtlDesc.Fields.MTCFreq = options.Fields.MTCFreq;
	}
	if (ptCap.bConfPsbAndCycSupported) 
	{
		rtitCtlDesc.Fields.CycEn = options.Fields.bTraceCycPcks;
		if ((1 << options.Fields.CycThresh) & ptCap.cycThresholdBmp)
			rtitCtlDesc.Fields.CycThresh = options.Fields.CycThresh;
		if ((1 << options.Fields.PSBFreq) & ptCap.psbFreqBmp)
			rtitCtlDesc.Fields.PSBFreq = options.Fields.PSBFreq;
	}
	rtitCtlDesc.Fields.DisRETC = (options.Fields.bEnableRetCompression == 0);
	rtitCtlDesc.Fields.TSCEn = options.Fields.bTraceTscPcks;

	// Switch the tracing to ON dude :-)
	rtitCtlDesc.Fields.TraceEn = 1;
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	// XXX: should not be needed
	// Wait some microseconds:
	// KeStallExecutionProcessor(42); 

	// Read the status register
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);

	// Finally lower the IRQL
	if (kOldIrql < DISPATCH_LEVEL)
		KeLowerIrql(kOldIrql);

	if (rtitStatusDesc.Fields.TriggerEn) 
	{
		DbgPrint("[TalosIntelPT] Successfully enabled Intel PT tracing for processor %i. Log Virtual Address: 0x%llX. :-)\r\n", 
			curProcId, lpProcPtData->bUseTopa ? lpProcPtData->u.ToPA.lpTopaVa : lpProcPtData->u.Simple.lpTraceBuffVa);
		lpProcPtData->curState = PT_PROCESSOR_STATE_TRACING;
		return STATUS_SUCCESS;
	}
	else 
	{
		DbgPrint("[TalosIntelPT] Error: unable to successfully enable Intel PT tracing for processor %i.", curProcId);
		//__writemsr(MSR_IA32_RTIT_STATUS, 0);
		if (bBuffAllocated) FreePtResources();
		lpProcPtData->curState = PT_PROCESSOR_STATE_ERROR;
		lpProcPtData->lpTargetProc = NULL;
		lpProcPtData->lpTargetProcCr3 = NULL;
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS StartProcessTrace(DWORD dwProcId, DWORD dwBuffSize) 
{
	NTSTATUS ntStatus = 0;
	PEPROCESS peProc = NULL;

	// PsLookupProcessByProcessId should be executed at IRQL < DISPATCH_LEVEL
	ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);				
	ntStatus = PsLookupProcessByProcessId((HANDLE)dwProcId, &peProc);

	if (!NT_SUCCESS(ntStatus)) 
		return ntStatus;
	else 
		return StartProcessTrace(peProc, dwBuffSize);
}

// Put the tracing in PAUSE mode
NTSTATUS PauseResumeTrace(BOOLEAN bPause) 
{
	MSR_RTIT_CTL_DESC rtitCtlDesc = { 0 };					// The RTIT MSR descriptor
	MSR_RTIT_STATUS_DESC rtitStatusDesc = { 0 };			// The Status MSR descriptor
	MSR_RTIT_OUTPUTBASE_DESC rtitOutBaseDesc = { 0 };		// IA32_RTIT_OUTPUT_BASE Model specific Register
	MSR_RTIT_OUTPUT_MASK_PTRS_DESC rtitOutMasksDesc = { 0 };	// IA32_RTIT_OUTPUT_MASK_PTRS Model specific Register
	DWORD dwCurCpu = 0;										// Current running CPU
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;				// Returned NTSTATUS value

	ntStatus = CheckIntelPtSupport(NULL);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	dwCurCpu = KeGetCurrentProcessorNumber();
	PER_PROCESSOR_PT_DATA & curCpuData = g_pDrvData->procData[dwCurCpu];

	// Read the current state
	rtitCtlDesc.All = __readmsr(MSR_IA32_RTIT_CTL);
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);

	// XXX: This seems unnecessary 
	// Update the STATUS register 
	if (rtitCtlDesc.Fields.TraceEn == 0) 
	{
		rtitStatusDesc.Fields.Stopped = 0;
		rtitStatusDesc.Fields.Error = 0;
		__writemsr(MSR_IA32_RTIT_STATUS, rtitStatusDesc.All);
	}

	if (bPause)
	{
		// Pause Intel PT tracing 
		rtitCtlDesc.Fields.TraceEn = 0;
	}
	else 
	{
		// If we paused to dump buffer lets reset it 
		if (curCpuData.bUseTopa && curCpuData.bBuffIsFull) 
		{
			// Restore the Topa Buffer, Set the proc_trace_table_base
			rtitOutBaseDesc.All = (ULONGLONG)curCpuData.u.ToPA.lpTopaPhysAddr;
			__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, rtitOutBaseDesc.All);

			// Set the proc_trace_table_offset: indicates the entry of the table that is currently in use
			rtitOutMasksDesc.Fields.LowerMask = 0x7F;
			rtitOutMasksDesc.Fields.MaskOrTableOffset = 0;	// Start from the first entry in the table
			rtitOutMasksDesc.Fields.OutputOffset = 0;		// Start at offset 0
			__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, rtitOutMasksDesc.All);
			curCpuData.bBuffIsFull = FALSE;
		}

		// Resume Intel PT tracing
		rtitCtlDesc.Fields.TraceEn = 1;
	}

	// Update the Control register
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	/* XXX: should not be needed 
	if (kIrql <= DISPATCH_LEVEL) {
		// STALL the execution for a little time
		KeStallExecutionProcessor(42);
	} // else ... Interrupt routine should be VERY FAST
	*/

	// Read the final status
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	
	if (rtitStatusDesc.Fields.Error) 
	{
		curCpuData.curState = PT_PROCESSOR_STATE_ERROR;
		return STATUS_UNSUCCESSFUL;
	}

	if (bPause) 
	{
		// Copy and reset the current number of packets
		curCpuData.PacketByteCount += (QWORD)rtitStatusDesc.Fields.PacketByteCnt;
		rtitStatusDesc.Fields.PacketByteCnt = 0;
		__writemsr(MSR_IA32_RTIT_STATUS, rtitStatusDesc.All);
		curCpuData.curState = PT_PROCESSOR_STATE_PAUSED;
	}
	else
		curCpuData.curState = PT_PROCESSOR_STATE_TRACING;

	return STATUS_SUCCESS;
}

// Disable Intel PT for the current processor
NTSTATUS StopAndDisablePt() 
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;				// Returned NTSTATUS value
	PER_PROCESSOR_PT_DATA * lpProcPtData = NULL;			// The per processor data structure
	MSR_RTIT_CTL_DESC rtitCtlDesc = { 0 };
	MSR_RTIT_STATUS_DESC rtitStatusDesc = { 0 };			// The Status MSR descriptor
	ULONG dwCurProc = 0;

	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	dwCurProc = KeGetCurrentProcessorNumber();
	lpProcPtData = &g_pDrvData->procData[dwCurProc];

	ntStatus = CheckIntelPtSupport(NULL);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Stop and disable the Intel PT
	rtitCtlDesc.All = __readmsr(MSR_IA32_RTIT_CTL);
	rtitCtlDesc.Fields.TraceEn = 0;
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	// Copy the final number of Acquired packets
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	lpProcPtData->PacketByteCount += (QWORD)rtitStatusDesc.Fields.PacketByteCnt;

	// Reset all the configuration registers
	__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, 0);
	__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0);
	__writemsr(MSR_IA32_RTIT_CR3_MATCH, 0);

	lpProcPtData->lpTargetProcCr3 = NULL;
	lpProcPtData->lpTargetProc = NULL;

	lpProcPtData->curState = PT_PROCESSOR_STATE_STOPPED;
	return STATUS_SUCCESS;
}

// Get the active Trace options for a particular CPU
NTSTATUS GetTraceOptions(DWORD dwCpuId, TRACE_OPTIONS * pOptions) 
{
	DWORD dwNumCpus = KeQueryActiveProcessorCount(NULL);
	if (dwCpuId >= dwNumCpus) 
		return STATUS_INVALID_PARAMETER;

	if (pOptions)
		*pOptions = g_pDrvData->procData[dwCpuId].TraceOptions;

	return STATUS_SUCCESS;
}

// Set the trace options for a particular CPU
NTSTATUS SetTraceOptions(DWORD dwCpuId, TRACE_OPTIONS opts) 
{
	KAFFINITY curCpuAffinity = 0;
	DWORD dwNumCpus = 0;
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	NTSTATUS ntStatus = 0;

	dwNumCpus = KeQueryActiveProcessorCount(&curCpuAffinity);
	if (dwCpuId >= dwNumCpus) return STATUS_INVALID_PARAMETER;
	PER_PROCESSOR_PT_DATA & cpuData = g_pDrvData->procData[dwCpuId];
	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Check the options now
	if (opts.Fields.bTraceMtcPcks && (ptCap.bMtcSupport == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.bTraceCycPcks && (ptCap.bConfPsbAndCycSupported == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.bUseTopa && !(ptCap.bTopaOutput && ptCap.bTopaMultipleEntries)) return STATUS_NOT_SUPPORTED;

	// Check now the frequency bitmaps:
	if (opts.Fields.MTCFreq && ((1 << opts.Fields.MTCFreq) & (ptCap.mtcPeriodBmp == 0))) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.PSBFreq && (ptCap.bConfPsbAndCycSupported == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.PSBFreq && ((1 << opts.Fields.PSBFreq) & (ptCap.psbFreqBmp == 0))) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.CycThresh && (ptCap.bConfPsbAndCycSupported == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.CycThresh && ((1 << opts.Fields.CycThresh) & (ptCap.cycThresholdBmp == 0))) return STATUS_NOT_SUPPORTED;

	// Copy the options
	cpuData.TraceOptions = opts;
	return STATUS_SUCCESS;
}
#pragma endregion

#pragma region Trace Buffer memory management Code
// Allocate a Trace buffer for the current CPU
NTSTATUS AllocPtBuffer(QWORD qwSize, BOOLEAN bUseToPA) 
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS value
	ULONG dwCurCpu = 0;										// Current CPU number
	INTEL_PT_CAPABILITIES ptCap = { 0 };					// Current processor capabilities
	PHYSICAL_ADDRESS MaxAddr; MaxAddr.QuadPart = -1ll;		// Maximum physical address

	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	dwCurCpu = KeGetCurrentProcessorNumber();
	PER_PROCESSOR_PT_DATA & perCpuData = g_pDrvData->procData[dwCurCpu];

	// Get this processor capabilities
	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	if (bUseToPA && !(ptCap.bTopaOutput && ptCap.bTopaMultipleEntries))
		return STATUS_NOT_SUPPORTED;
	if (!bUseToPA && !ptCap.bSingleRangeSupport)
		return STATUS_NOT_SUPPORTED;

	if (bUseToPA) 
	{
		if (perCpuData.u.ToPA.lpTopaPhysAddr) ntStatus = FreePtResources();
		if (!NT_SUCCESS(ntStatus)) return ntStatus;
		// Table of Physical Address usage
		ntStatus = AllocAndSetCpuTopa(dwCurCpu, qwSize);
	}
	else 
	{
		if (perCpuData.u.Simple.lpTraceBuffVa) ntStatus = FreePtResources();
		if (!NT_SUCCESS(ntStatus)) return ntStatus;

		// Simple output range implementation
		LPVOID lpBuffVa = MmAllocateContiguousMemory(qwSize, MaxAddr);
		if (!lpBuffVa) return STATUS_INSUFFICIENT_RESOURCES;

		RtlZeroMemory(lpBuffVa, qwSize);

		perCpuData.u.Simple.lpTraceBuffVa = lpBuffVa;
		perCpuData.qwBuffSize = qwSize;

		// Grab the physical address:
		PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(lpBuffVa);
		perCpuData.u.Simple.lpTraceBuffPhysAddr = (ULONG_PTR)physAddr.QuadPart;

		// Allocate the relative MDL
		PMDL pPtMdl = IoAllocateMdl(lpBuffVa, (ULONG)perCpuData.qwBuffSize, FALSE, FALSE, NULL);
		if (pPtMdl) perCpuData.pTraceMdl = pPtMdl;
		
		ntStatus = STATUS_SUCCESS;
	}

	return ntStatus;
}

// Free the Trace buffer resources for current CPU
NTSTATUS FreePtResources() 
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;				// Returned NTSTATUS value
	ULONG dwCurCpu = 0;										// Current CPU number
	DWORD dwCurProcId = 0, dwTargetPid = 0;					// Current and target Process ID
	KIRQL kIrql = KeGetCurrentIrql();

	dwCurCpu = KeGetCurrentProcessorNumber();
	PER_PROCESSOR_PT_DATA & perCpuData = g_pDrvData->procData[dwCurCpu];

	if (!perCpuData.qwBuffSize) return STATUS_INVALID_BUFFER_SIZE;

	// First of all check if the trace buffer is mapped to any process
	if (perCpuData.lpUserVa) 
	{
		dwCurProcId = (DWORD)PsGetCurrentProcessId();
		if (perCpuData.lpMappedProc)
			dwTargetPid = (DWORD)PsGetProcessId(perCpuData.lpMappedProc);
		
		if ((!dwTargetPid || dwTargetPid == dwCurProcId) && kIrql <= APC_LEVEL) 
		{
			// We can safely unmap the PT buffer here
			ntStatus = UnmapTraceBuffToUserVa(dwCurCpu);
			if (!NT_SUCCESS(ntStatus)) 
			{
				DbgPrint("[TalosIntelPT] Error: Unable to unmap the trace buffer for process %i.\r\n", dwTargetPid);
				return ntStatus;
			}
		}
		else 
		{
			DbgPrint("[TalosIntelPT] Warning: Unable to free the the allocated physical memory for processor %i. The process with PID %i has still not unmapped the buffer. "
				"Base VA: 0x%llX, physical address: 0x%llX.\r\n", dwCurCpu, dwTargetPid, perCpuData.lpUserVa, perCpuData.u.Simple.lpTraceBuffPhysAddr);
			return STATUS_CONTEXT_MISMATCH;
		}
	}

	if (perCpuData.bUseTopa) 
	{
		// TODO: Change this afterwards
		if (perCpuData.u.ToPA.lpTopaVa) 
		{
			MmFreeContiguousMemory(perCpuData.u.ToPA.lpTopaVa);
			perCpuData.u.ToPA.lpTopaVa = NULL;
			perCpuData.u.ToPA.lpTopaPhysAddr = NULL;
		}

		if (perCpuData.pTraceMdl) 
		{
			// Free the used pages 
			MmFreePagesFromMdl(perCpuData.pTraceMdl);
			ExFreePool(perCpuData.pTraceMdl);
			perCpuData.pTraceMdl = NULL;
		}
	}
	else 
	{
		// Free the simple output region
		if (perCpuData.u.Simple.lpTraceBuffVa)
			MmFreeContiguousMemory(perCpuData.u.Simple.lpTraceBuffVa);

		if (perCpuData.pTraceMdl) 
		{
			IoFreeMdl(perCpuData.pTraceMdl);
			perCpuData.pTraceMdl = NULL;
		}

		perCpuData.u.Simple.lpTraceBuffVa = NULL;
		perCpuData.u.Simple.lpTraceBuffPhysAddr = NULL;
	}

	perCpuData.qwBuffSize = 0;
	return STATUS_SUCCESS;
}

// Allocate and set a ToPA for the current CPU
NTSTATUS AllocAndSetCpuTopa(DWORD dwCpuId, QWORD qwReqBuffSize) { return AllocAndSetCpuTopaSlow(dwCpuId, qwReqBuffSize); }

// Allocate and set a ToPA for the current CPU (with the Windows API)
NTSTATUS AllocAndSetCpuTopaSlow(DWORD dwCpuId, QWORD qwReqBuffSize) 
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	DWORD dwNumEntriesInMdl = 0;							// Number of entries in the MDL
	DWORD dwTopaSize = 0;									// Size of the ToPa
	TOPA_TABLE_ENTRY * pTopa = NULL;						// Pointer to the ToPa
	PHYSICAL_ADDRESS highPhysAddr = { (ULONG)-1, -1 };		// Highest physical memory address
	PHYSICAL_ADDRESS lowPhysAddr = { 0i64 };				// Lowest physical memory address
	PHYSICAL_ADDRESS topaPhysAddr = { 0i64 };				// The ToPA physical address
	PMDL pTraceBuffMdl = NULL;

	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	if (qwReqBuffSize % PAGE_SIZE) return STATUS_INVALID_PARAMETER_2;
	if (dwCpuId >= g_pDrvData->dwNumProcs) return STATUS_INVALID_PARAMETER;

	// Allocate the needed physical memory
	pTraceBuffMdl = MmAllocatePagesForMdlEx(lowPhysAddr, highPhysAddr, lowPhysAddr, (SIZE_T)qwReqBuffSize + PAGE_SIZE, MmCached, MM_ALLOCATE_FULLY_REQUIRED);
	if (!pTraceBuffMdl) return STATUS_INSUFFICIENT_RESOURCES;

	// Get the PFN array
	dwNumEntriesInMdl = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pTraceBuffMdl), MmGetMdlByteCount(pTraceBuffMdl));
	PPFN_NUMBER pfnArray = MmGetMdlPfnArray(pTraceBuffMdl);

	// Allocate the ToPA
	dwTopaSize = (dwNumEntriesInMdl + 1) * 8;
	dwTopaSize = ROUND_TO_PAGES(dwTopaSize);
	pTopa = (TOPA_TABLE_ENTRY *)MmAllocateContiguousMemory(dwTopaSize, highPhysAddr);
	topaPhysAddr = MmGetPhysicalAddress(pTopa);
	if (!pTopa) 
	{
		MmFreePagesFromMdl(pTraceBuffMdl);
		ExFreePool(pTraceBuffMdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pTopa, dwTopaSize);

	// Create the ToPA 
	for (DWORD i = 0; i < dwNumEntriesInMdl; i++) 
	{
		pTopa[i].Fields.BaseAddr = pfnArray[i];				// Pfn array contains the PFN offset, not the actual Physical address
		pTopa[i].Fields.Size = 0; // Encoding: 0 - 4K pages
	} 

	// LVT interrupt entry
	pTopa[dwNumEntriesInMdl - 1].Fields.Int = 1;
	pTopa[dwNumEntriesInMdl - 1].Fields.Stop = 1;

	// END entries 
	RtlZeroMemory(&pTopa[dwNumEntriesInMdl], sizeof(TOPA_TABLE_ENTRY));
	pTopa[dwNumEntriesInMdl].Fields.BaseAddr = (ULONG_PTR)(topaPhysAddr.QuadPart >> 0xC);
	pTopa[dwNumEntriesInMdl].Fields.End = 1;

	// Now set the ToPa
	g_pDrvData->procData[dwCpuId].bUseTopa = TRUE;
	g_pDrvData->procData[dwCpuId].u.ToPA.lpTopaPhysAddr = (ULONG_PTR)topaPhysAddr.QuadPart;
	g_pDrvData->procData[dwCpuId].u.ToPA.lpTopaVa = pTopa;
	g_pDrvData->procData[dwCpuId].qwBuffSize = qwReqBuffSize;
	g_pDrvData->procData[dwCpuId].pTraceMdl = pTraceBuffMdl;
	return ntStatus;
}
#pragma code_seg()

// Map a physical page buffer to a User-mode process
NTSTATUS MapTracePhysBuffToUserVa(DWORD dwCpuId) 
{
	PMDL pMdl = NULL;										// The new MDL describing the physical memory
	LPVOID lpUserBuff = NULL;								// The user-mode accessible buffer
	PEPROCESS pCurProc = NULL;								// The current EPROCESS target
	PER_PROCESSOR_PT_DATA * pPerCpuData = &g_pDrvData->procData[dwCpuId];

	// This should be executed at IRQL level <= APC for MmMapLockedPagesSpecifyCache
	ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	if (!pPerCpuData->u.Simple.lpTraceBuffVa || !pPerCpuData->qwBuffSize) return STATUS_INVALID_PARAMETER;

	if (pPerCpuData->bUseTopa) 
	{
		// Table of Physical Address Implementation
		pMdl = pPerCpuData->pTraceMdl;
		if (!pMdl) return STATUS_INTERNAL_ERROR;
	}
	else 
	{
		// Simple-output scheme implementation
		if (!pPerCpuData->u.Simple.lpTraceBuffPhysAddr) 
		{
			PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(pPerCpuData->u.Simple.lpTraceBuffVa);
			pPerCpuData->u.Simple.lpTraceBuffPhysAddr = (ULONG_PTR)physAddr.QuadPart;
		}

		if (pPerCpuData->pTraceMdl) 
			pMdl = pPerCpuData->pTraceMdl;
		else
			pMdl = IoAllocateMdl(pPerCpuData->u.Simple.lpTraceBuffVa, (ULONG)pPerCpuData->qwBuffSize, FALSE, FALSE, NULL);

		// Update this MDL to describe the underlying already-locked physical pages
		MmBuildMdlForNonPagedPool(pMdl);					// DO THIS only here and nowhere else

		pPerCpuData->pTraceMdl = pMdl;
		if (!pMdl) return STATUS_INSUFFICIENT_RESOURCES;
	}

	pCurProc = PsGetCurrentProcess();

	// Now map the MDL to the current user-mode process 
	// If AccessMode is UserMode, the caller must be running at IRQL <= APC_LEVEL
	lpUserBuff = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);				

	if (lpUserBuff) 
	{
		pPerCpuData->lpUserVa = lpUserBuff;
		pPerCpuData->lpMappedProc = pCurProc;
		ObReferenceObject(pCurProc);			// prevent process termination without freeing the resource
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;
}

// Unmap the memory-mapped physical memory from User mode
NTSTATUS UnmapTraceBuffToUserVa(DWORD dwCpuId) 
{
	PEPROCESS pCurProc = NULL;						// The current EPROCESS target
	PER_PROCESSOR_PT_DATA * pPerCpuData = &g_pDrvData->procData[dwCpuId];

	pCurProc = PsGetCurrentProcess();

	if (pPerCpuData->pTraceMdl) 
	{
		if (pPerCpuData->lpUserVa) 
		{
			BOOLEAN bExited = FALSE;
			PEPROCESS pMappedProc = pPerCpuData->lpMappedProc;

			// Get if the mapped process is already terminated
			if (pMappedProc) 
				bExited = PsGetProcessExitProcessCalled(pPerCpuData->lpMappedProc);

			if (pMappedProc && (bExited == FALSE) && (pCurProc != pMappedProc))
				return STATUS_CONTEXT_MISMATCH;

			if (!bExited)
				MmUnmapLockedPages(pPerCpuData->lpUserVa, pPerCpuData->pTraceMdl);
			
			pPerCpuData->lpUserVa = NULL;
			pPerCpuData->lpMappedProc = NULL;
			ObDereferenceObject(pMappedProc);
		}
	}
	return STATUS_SUCCESS;
}
#pragma endregion

#pragma region PMI Interrupt management code
#pragma code_seg(".nonpaged")
// Register the LVT (Local Vector Table) PMI interrupt
NTSTATUS RegisterPmiInterrupt() 
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	PMIHANDLER pNewPmiHandler = NULL;
	//PMIHANDLER pOldPmiHandler = NULL; 					// The old PMI handler (currently not implemented)

	BYTE lpBuff[0x20] = { 0 };
	//XXX ULONG dwBytesIo = 0;									// Number of I/O bytes

	// First of all we need to search for HalpLocalApic symbol
	MSR_IA32_APIC_BASE_DESC ApicBase = { 0 };				// In Multi-processors systems this address could change
	ApicBase.All = __readmsr(MSR_IA32_APIC_BASE);			// In Windows systems all the processors LVT are mapped at the same physical address

	if (!ApicBase.Fields.EXTD) 
	{
		LPDWORD lpdwApicBase = NULL;
		PHYSICAL_ADDRESS apicPhys = { 0 };

		apicPhys.QuadPart = ApicBase.All & (~0xFFFi64);
		lpdwApicBase = (LPDWORD)MmMapIoSpace(apicPhys, 0x1000, MmNonCached);

		if (lpdwApicBase) 
		{
			DrvDbgPrint("[TalosIntelPT] Successfully mapped the local APIC to 0x%llX.\r\n", lpdwApicBase);
			g_pDrvData->lpApicBase = lpdwApicBase;
		}
		else
			return STATUS_NOT_SUPPORTED;

		// Now read the entry 0x340 (not really needed)
		g_pDrvData->pmiVectDesc.All = lpdwApicBase[0x340 / 4];
	}
	else 
	{
		// Current system uses x2APIC mode, no need to map anything
		g_pDrvData->bCpuX2ApicMode = TRUE;
	}

	// The following functions must be stored in HalDispatchTable 
	// TODO: Find a way to proper get the old PMI interrupt handler routine. Search inside the HAL code?
	// ntStatus = HalQuerySystemInformation(HalProfileSourceInformation, COUNTOF(lpBuff), (LPVOID)lpBuff, &dwBytesIo);		

	// Now set the new PMI handler, WARNING: we do not save and restore old handler
	pNewPmiHandler = IntelPtPmiHandler;
	ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (LPVOID)&pNewPmiHandler);
	if (NT_SUCCESS(ntStatus)) 
	{
		DrvDbgPrint("[TalosIntelPT] Successfully registered system PMI handler to function 0x%llX.\r\n", (LPVOID)pNewPmiHandler);
		g_pDrvData->bPmiInstalled = TRUE;
	}

	return ntStatus;
}

// Unregister and remove the LVT PMI interrupt 
NTSTATUS UnregisterPmiInterrupt()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	PMIHANDLER pOldPmiHandler = g_pDrvData->pOldPmiHandler;	// The old PMI handler
		
	// This is currently not restoring old PMI handler since we don't know how to retrieve it, just nulling it out
	ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (LPVOID)&pOldPmiHandler);

	if (NT_SUCCESS(ntStatus)) 
	{
		g_pDrvData->bPmiInstalled = FALSE;
		if (g_pDrvData->lpApicBase)
			MmUnmapIoSpace(g_pDrvData->lpApicBase, 0x1000);
	}

	return ntStatus;
}

// The PMI LVT handler routine (Warning! This should run at very high IRQL)
VOID IntelPtPmiHandler(PKTRAP_FRAME pTrapFrame) 
{
	PKDPC pProcDpc = NULL;									// This processor DPC
	MSR_IA32_PERF_GLOBAL_STATUS_DESC pmiDesc = { 0 };		// The PMI Interrupt descriptor
	LVT_Entry perfMonDesc = { 0 };							// The LVT Performance Monitoring register
	LPDWORD lpdwApicBase = g_pDrvData->lpApicBase;			// The LVT Apic I/O space base address (if not in x2Apic mode)
	DWORD dwCurCpu = 0;
	UNREFERENCED_PARAMETER(pTrapFrame);

	ASSERT(KeGetCurrentIrql() > DISPATCH_LEVEL);

	dwCurCpu = KeGetCurrentProcessorNumber();

	// Check if the interrupt is mine
	pmiDesc.All = __readmsr(MSR_IA32_PERF_GLOBAL_STATUS);
	if (pmiDesc.Fields.TraceToPAPMI == 0)
		return;

	// Pause the Tracing. From Intel's Manual: "Software can minimize the likelihood of the second case by clearing
	//	TraceEn at the beginning of the PMI handler
	PauseResumeTrace(TRUE);
	g_pDrvData->procData[dwCurCpu].bBuffIsFull = TRUE;

	// Check the Intel PT status
	MSR_RTIT_STATUS_DESC traceStatusDesc = { 0 };
	traceStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	if (traceStatusDesc.Fields.Error)
		DrvDbgPrint("[TalosIntelPT] Warning: Intel PT Pmi has raised, but the PT Status register indicates an error!\r\n");

	// The IRQL is too high so we use DPC 
	pProcDpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), MEMTAG);
	KeInitializeDpc(pProcDpc, IntelPmiDpc, NULL);
	KeSetTargetProcessorDpc(pProcDpc, (CCHAR)dwCurCpu);
	KeInsertQueueDpc(pProcDpc, (LPVOID)dwCurCpu, NULL);

	MSR_IA32_PERF_GLOBAL_OVF_CTRL_DESC globalResetMsrDesc = { 0 };
	// Set the PMI Reset: Once the ToPA PMI handler has serviced the relevant buffer, writing 1 to bit 55 of the MSR at 390H
	// (IA32_GLOBAL_STATUS_RESET)clears IA32_PERF_GLOBAL_STATUS.TraceToPAPMI.
	globalResetMsrDesc.Fields.ClrTraceToPA_PMI = 1;
	__writemsr(MSR_IA32_PERF_GLOBAL_OVF_CTRL, globalResetMsrDesc.All);

	// Re-enable the PMI
	if (g_pDrvData->bCpuX2ApicMode) 
	{
		// Check Intel Manuals, Vol. 3A section 10-37
		ULONGLONG perfMonEntry = __readmsr(MSR_IA32_X2APIC_LVT_PMI);
		DbgBreak();			// XXX: Please help test this, I do not have a system with the x2Apic mode enabled
		perfMonDesc.All = (ULONG)perfMonEntry;
		perfMonDesc.Fields.Masked = 0;
		perfMonEntry = (ULONGLONG)perfMonDesc.All;
		__writemsr(MSR_IA32_X2APIC_LVT_PMI, perfMonEntry);
	}
	else 
	{
		if (!lpdwApicBase)
			// XXX: Not sure how to continue, No MmMapIoSpace at this IRQL (should not happen)
			KeBugCheckEx(INTERRUPT_EXCEPTION_NOT_HANDLED, NULL, NULL, NULL, NULL);
		perfMonDesc.All = lpdwApicBase[0x340 / 4];
		perfMonDesc.Fields.Masked = 0;
		lpdwApicBase[0x340 / 4] = perfMonDesc.All;
	}
};

// The PMI DPC routine
VOID IntelPmiDpc(struct _KDPC *pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) 
{
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	DWORD dwCpuNum = KeGetCurrentProcessorNumber();			// This CPU number
	ULONGLONG targetCr3 = 0ui64;							// The target CR3 register value
	
	// A quick integrity check
	ASSERT(dwCpuNum == (DWORD)SystemArgument1);

	PER_PROCESSOR_PT_DATA & curCpuData = g_pDrvData->procData[dwCpuNum];	// This processor DPC data
		
	if (curCpuData.lpTargetProc) 
	{
		// Verify that the Target CR3 still matches
		targetCr3 = ((ULONGLONG*)curCpuData.lpTargetProc)[5];
		ASSERT(targetCr3 == curCpuData.lpTargetProcCr3);

		// queue work item to suspend the target process 
		PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM) + sizeof(LPVOID), MEMTAG);
		if (pWorkItem) 
		{
			ExInitializeWorkItem(pWorkItem, IntelPmiWorkItem, (PVOID)pWorkItem);
			*((LPVOID*)(LPBYTE(pWorkItem) + sizeof(WORK_QUEUE_ITEM))) = (LPVOID)curCpuData.lpTargetProc;
			ExQueueWorkItem(pWorkItem, CriticalWorkQueue);
		}
	}

	// Set the Buffer full Event (if any)
	if (g_pDrvData->pPmiEvent) 
		KeSetEvent(g_pDrvData->pPmiEvent, IO_NO_INCREMENT, FALSE);

	ExFreePool(pDpc);
}

// The PMI Work Item
VOID IntelPmiWorkItem(PVOID Parameter) 
{
	PWORK_QUEUE_ITEM pWorkItem = NULL;					// This work item 
	PEPROCESS pTargetProc = NULL;						// The Target Process
	NTSTATUS ntStatus = STATUS_ABANDONED;				// The returned NTSTATUS 
	DWORD dwProcId = 0;									// The target process ID

	if (!Parameter) return;
	pWorkItem = (PWORK_QUEUE_ITEM)Parameter;
	pTargetProc = *(PEPROCESS*)((LPBYTE)Parameter + sizeof(WORK_QUEUE_ITEM));
	dwProcId = (DWORD)PsGetProcessId(pTargetProc);

	ntStatus = PsSuspendProcess(pTargetProc);
	if (NT_SUCCESS(ntStatus))
		DrvDbgPrint("[TalosIntelPT] Successfully suspended process ID: %i.\r\n", dwProcId);

	ExFreePool(pWorkItem);
}
#pragma code_seg()
#pragma endregion
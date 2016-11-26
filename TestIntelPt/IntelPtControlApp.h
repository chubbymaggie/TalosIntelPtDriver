/**********************************************************************
*   Intel Processor Trace Driver
*	Filename: IntelPtControlApp.h
*	A simple Intel PT driver control application header file
*	Last revision: 10/07/2016
*
*   Copyright© 2016 Andrea Allievi, Richard Johnson
* 	Microsoft Ltd & TALOS Research and Intelligence Group
*	All right reserved
**********************************************************************/

#pragma once
#include "IntelPt.h"

#define PAGE_SIZE 0x1000
#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

// The Application global data
struct GLOBAL_DATA {
	HANDLE hTraceFile;							// The trace file handle
	HANDLE hPtDev;								// The handle to the Intel PT device
	HANDLE hTargetProc;							// The traced process handle
	LPBYTE lpPtBuff;							// The Trace buffer
	DWORD dwTraceSize;							// The trace size in BYTES
	HANDLE hExitEvt;							// The handle to the exit event
	PT_USER_REQ currentTrace;
};

// Check the support of Intel Processor Tarce on this CPU
BOOL CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap);

// The PMI interrupt Thread 
DWORD WINAPI PmiThreadProc(LPVOID lpParameter);

// Spawn a suspended process and oblige the loader to load the remote image in memory
BOOL SpawnSuspendedProcess(LPTSTR lpAppName, LPTSTR lpCmdLine, PROCESS_INFORMATION * outProcInfo);
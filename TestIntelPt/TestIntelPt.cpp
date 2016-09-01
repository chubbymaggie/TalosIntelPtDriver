// TestIntelPt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "..\TalosIntelPtDriver\DriverIo.h"
#include "IntelPt.h"
const LPTSTR DosDevName = L"\\\\.\\TalosIntelPT";
#pragma comment (lib, "ntdll.lib")

// Global app data
GLOBAL_DATA g_appData = { 0 };
#define TRACE_BUFF_SIZE 64 * 1204  * 1024 

BOOL CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap)
{
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	int cpuid_ctx[4] = { 0 };			// EAX, EBX, ECX, EDX

	// Processor support for Intel Processor Trace is indicated by CPUID.(EAX=07H,ECX=0H):EBX[bit 25] = 1.
	__cpuidex(cpuid_ctx, 0x07, 0);
	if (!(cpuid_ctx[1] & (1 << 25))) return FALSE;

	// Now enumerate the Intel Processor Trace capabilities
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 0);
	// If the maximum valid sub-leaf index is 0 exit immediately
	if (cpuid_ctx[0] == 0) return FALSE;

	ptCap.bCr3Filtering = (cpuid_ctx[1] & (1 << 0)) != 0;					// EBX
	ptCap.bConfPsbAndCycSupported = (cpuid_ctx[1] & (1 << 1)) != 0;
	ptCap.bIpFiltering = (cpuid_ctx[1] & (1 << 2)) != 0;
	ptCap.bMtcSupport = (cpuid_ctx[1] & (1 << 3)) != 0;
	ptCap.bTopaOutput = (cpuid_ctx[2] & (1 << 0)) != 0;						// ECX
	ptCap.bTopaMultipleEntries = (cpuid_ctx[2] & (1 << 1)) != 0;
	ptCap.bSingleRangeSupport = (cpuid_ctx[2] & (1 << 2)) != 0;
	ptCap.bTransportOutputSupport = (cpuid_ctx[2] & (1 << 3)) != 0;
	ptCap.bIpPcksAreLip = (cpuid_ctx[2] & (1 << 31)) != 0;

	// Enmeration part 2:
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 1);
	ptCap.numOfAddrRanges = (BYTE)(cpuid_ctx[0] & 0x7);
	ptCap.mtcPeriodBmp = (SHORT)((cpuid_ctx[0] >> 16) & 0xFFFF);
	ptCap.cycThresholdBmp = (SHORT)(cpuid_ctx[1] & 0xFFFF);
	ptCap.psbFreqBmp = (SHORT)((cpuid_ctx[1] >> 16) & 0xFFFF);

	if (lpPtCap) *lpPtCap = ptCap;
	return TRUE;
}

#define PAGE_SIZE 0x1000
#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

int main()
{
	BOOL bRetVal = FALSE;
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	HANDLE hPtDev = NULL,							// Handle to the PT device
		hPmiThread = NULL;							// Handle to the PMI thread
	TCHAR procPath[MAX_PATH] = { 0 };				// The target process full path
	PT_TRACE_STRUCT ptStartStruct = { 0 };			// The Intel PT starting structure
	LPBYTE lpPtBuff = NULL;							// The Trace buffer
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	DWORD dwTargetCpu = 0;							// The target CPU
	TCHAR lpPtDumpFile[MAX_PATH] = { 0 };			// The target DUMP file
	DWORD dwPmiThrId = 0;							// The PMI Thread ID
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };


#pragma region DEBUG code section
	// Some DEBUG checks
	TOPA_TABLE_ENTRY tableEntry = { 0 };
	dwBytesIo = sizeof(tableEntry);
	tableEntry.Fields.Size = 15;
	tableEntry.Fields.BaseAddr = 0x123456789ABC;
	tableEntry.Fields.End = 1;

	// Debug check 2
	MSR_IA32_PERF_GLOBAL_STATUS_DESC globalStatus = { 0 };
	globalStatus.Fields.TraceToPAPMI = 1;
	globalStatus.Fields.PMC7_OVF = 1;
	globalStatus.Fields.FIXED_CTR1 = 1;
	globalStatus.Fields.Ovf_Buffer = 1;
	#pragma endregion

	GetModuleFileName(GetModuleHandle(NULL), lpPtDumpFile, MAX_PATH);
	LPTSTR slashPtr = wcsrchr(lpPtDumpFile, L'\\');
	if (slashPtr) slashPtr[1] = 0;
	wcscat_s(lpPtDumpFile, L"pt_dump.bin");

	wprintf(L"Talos Intel PT Test Application\r\n");
	wprintf(L"Version 0.1\r\n\r\n");

	// Create the Exit Event
	g_appData.hExitEvt = CreateEvent(NULL, FALSE, FALSE, NULL);

	bRetVal = CheckIntelPtSupport(&ptCap);
	wprintf(L"Intel Processor Tracing support for this CPU: %s\r\n", (bRetVal ? L"YES" : L"NO"));
	hPtDev = CreateFile(DosDevName, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dwLastErr = GetLastError();

	if (hPtDev == INVALID_HANDLE_VALUE) {
		wprintf(L"Unable to open the Intel PT device object!\r\n");
		return 0;
	} else
		g_appData.hPtDev = hPtDev;

	wprintf(L"Insert here the target Process to trace: ");
	wscanf_s(L"%s", procPath, MAX_PATH);

	// Create the Trace File
	wprintf(L"Creating trace file... ");
	HANDLE hDump = CreateFile(lpPtDumpFile, FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hDump == INVALID_HANDLE_VALUE) {
		cl_wprintf(RED, L"Error!\r\n");
		CloseHandle(hPtDev);
		wprintf(L"Press any key to exit...");
		getwchar();
		return -1;
	}
	cl_wprintf(GREEN, L"OK\r\n");
	g_appData.hTraceFile = hDump;

	si.cb = sizeof(STARTUPINFO);
	wprintf(L"Creating target process... ");
	bRetVal = CreateProcess(procPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	SetProcessAffinityMask(pi.hProcess, 0);
	if (bRetVal) cl_wprintf(GREEN, L"OK\r\n");
	else  {
		wprintf(L"Error!\r\n");
		CloseHandle(hPtDev);
		wprintf(L"Press any key to exit...");
		getwchar();
		return -1;
	}
	g_appData.hTargetProc = pi.hProcess;

	// Create the PMI thread
	hPmiThread = CreateThread(NULL, 0, PmiThreadProc, NULL, 0, &dwPmiThrId);

	// Start the device Tracing
	ptStartStruct.dwCpuId = dwTargetCpu;
	ptStartStruct.dwProcessId = pi.dwProcessId;
	ptStartStruct.dwTraceSize = TRACE_BUFF_SIZE;				// 64 Kbytes
	// For now do not set the frequencies....
	//ptStartStruct.dwOptsMask = PT_TRACE_TSC_PCKS_MASK | PT_TRACE_BRANCH_PCKS_MASK | PT_ENABLE_RET_COMPRESSION_MASK;
	wprintf(L"Starting the Tracing and resuming the process...");
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_START_TRACE, (LPVOID)&ptStartStruct, sizeof(PT_TRACE_STRUCT), &lpPtBuff, sizeof(LPVOID), &dwBytesIo, NULL);

	if (bRetVal) {
		cl_wprintf(GREEN, L"OK\r\n");
		g_appData.lpPtBuff = lpPtBuff;
		g_appData.dwTraceSize = TRACE_BUFF_SIZE;
		g_appData.currentTrace = ptStartStruct;

		// Resume the target process
		ResumeThread(pi.hThread);
		wprintf(L"Waiting for the traced process to exit...\r\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
	}
	else  {
		TerminateProcess(pi.hProcess, -1);
		wprintf(L"Error!\r\n");
	}

	SetEvent(g_appData.hExitEvt);
	WaitForSingleObject(hPmiThread, INFINITE);

	// Get the number of written packets
	PT_TRACE_DETAILS ptDetails = { 0 };
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDR_GET_TRACE_DETAILS, (LPVOID)&dwTargetCpu, 4, (LPVOID)&ptDetails, sizeof(ptDetails), &dwBytesIo, NULL);
	wprintf(L"Total number of Trace packets stored in the Dump: %I64i\r\n", ptDetails.qwTotalNumberOfPackets);

	// Free the resources
	CloseHandle(hPmiThread);
	CloseHandle(pi.hProcess); 
	CloseHandle(pi.hThread);

	// Don't forget to clear the trace buffer otherwise we will bugcheck
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_CLEAR_TRACE, (LPVOID)&dwTargetCpu, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
	CloseHandle(hPtDev);

	// ... then Exit ...
	rewind(stdin);
	wprintf(L"Press any key to exit...");
	getwchar();

    return 0;
}


// The PMI interrupt Thread 
DWORD WINAPI PmiThreadProc(LPVOID lpParameter) {
	LPTSTR lpEventName = L"Global\\TalosIntelPT";
	HANDLE hKernelEvt = NULL;
	BOOL bRetVal = FALSE;										// Returned Win32 value
	DWORD dwBytesIo = 0,										// Number of I/O bytes
		dwEvtNum = 0,											// The event number that has satisfied the wait
		dwLastErr = 0;											// Last Win32 error
	HANDLE hWaitEvts[2] = { 0 };

	hKernelEvt = OpenEvent(SYNCHRONIZE, FALSE, lpEventName);
	dwLastErr = GetLastError();

	if (!hKernelEvt) return -1;
	hWaitEvts[0] = hKernelEvt;
	hWaitEvts[1] = g_appData.hExitEvt;

	while (TRUE) {
		LPBYTE lpTraceBuff = NULL;						// The PT tracing buffer
		DWORD dwTraceBuffSize = 0;						// The trace buffer size
		HANDLE hTraceFile = NULL;
		dwEvtNum = WaitForMultipleObjects(2, hWaitEvts, FALSE, INFINITE);

		// Grab the parameters
		lpTraceBuff = g_appData.lpPtBuff;
		dwTraceBuffSize = g_appData.dwTraceSize;
		hTraceFile = g_appData.hTraceFile;
		
		if (dwEvtNum - WAIT_OBJECT_0 == 1) {
			// We are exiting, pause the Tracing
			bRetVal = DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_PAUSE_TRACE, (LPVOID)&g_appData.currentTrace.dwCpuId, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
		}

		if (hTraceFile) {
			WriteFile(hTraceFile, lpTraceBuff, dwTraceBuffSize, &dwBytesIo, NULL);
			RtlZeroMemory(lpTraceBuff, dwTraceBuffSize);
		}

		// If I am here the PMI interrupt has been fired
		if (dwEvtNum - WAIT_OBJECT_0 == 0) {
			// Resume the tracing and the execution of the target process
			bRetVal = DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_RESUME_TRACE, (LPVOID)&g_appData.currentTrace.dwCpuId, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
			ZwResumeProcess(g_appData.hTargetProc);
		} else
			// Exit from this thread
			break;
	}
	return 0;
}

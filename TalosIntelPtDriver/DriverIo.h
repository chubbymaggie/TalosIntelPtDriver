 /**********************************************************************
 *	Intel Processor Trace Driver
 *	Filename: DriverIo.h
 *	Define the I/O communication between the Driver and the User App
 *	Last revision: 10/07/2016
 *
 *  Copyright� 2016 Andrea Allievi, Richard Johnson
 *	TALOS Research and Intelligence Group and Microsoft Ltd
 *	All right reserved
 **********************************************************************/
#pragma once

#define PT_TRACE_CYC_PCKS_MASK				(1 << 0)				// Enable / disable CYC Packets
#define PT_TRACE_MTC_PCKS_MASK				(1 << 1)				// Enable / disable MTC Packets
#define PT_TRACE_TSC_PCKS_MASK				(1 << 2)				// Enable / disable TSC Packets
#define PT_TRACE_BRANCH_PCKS_MASK			(1 << 3)				// Enable / disable COFI-based packets: FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec, MODE.TSX.
#define PT_ENABLE_TOPA_MASK					(1 << 4)				// Enable / disable the usage of Table of Physical Addresses
#define PT_ENABLE_RET_COMPRESSION_MASK		(1 << 5)				// Enable / disable RET compression

struct PT_TRACE_IP_FILTERING {
	DWORD dwNumOfRanges;
	struct {
		LPVOID lpStartVa;
		LPVOID lpEndVa;
		BOOLEAN bStopTrace;
	} Ranges[4];
};

typedef struct _PT_USER_REQ {
	DWORD dwProcessId;						// The target process to trace (0 means ALL)
	DWORD dwCpuId;							// Target processor ID (-1 means ALL processors)
	DWORD dwTraceSize;						// TRACE buffer size 
	DWORD dwOptsMask;						// The trace options bitmask
	PT_TRACE_IP_FILTERING IpFiltering;		// The IP ranges that we would like to trace (if any)
} PT_USER_REQ, * PPT_USER_REQ;

enum PT_TRACE_STATE {
	PT_TRACE_STATE_ERROR = -1,
	PT_TRACE_STATE_STOPPED,
	PT_TRACE_STATE_PAUSED,
	PT_TRACE_STATE_RUNNING
};

// The structure used to retrieve the details of a TRACE
typedef struct _PT_TRACE_DETAILS {
	DWORD dwTargetProcId;					// The target process to trace
	DWORD dwCpuId;							// Target processor ID
	DWORD dwTraceBuffSize;					// The Trace buffer size
	QWORD qwTotalNumberOfPackets;			// The total number of packets acquired until now
	PT_TRACE_IP_FILTERING IpFiltering;		// The IP ranges that we would like to trace (if any)
	PT_TRACE_STATE dwCurrentTraceState;		// The current tracing state
} PT_TRACE_DETAILS, *PPT_TRACE_DETAILS;

#ifndef WIN32
// Driver generic pass-through routine
NTSTATUS DevicePassThrough(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Driver Device IO Control dispatch routine
NTSTATUS DeviceIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Driver create and close routine
NTSTATUS DeviceCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DeviceClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Driver unsupported routine
NTSTATUS DeviceUnsupported(PDEVICE_OBJECT pDevObj, PIRP pIrp);
#else
#include <WinIoCtl.h>
/*
*   IOCTL's are defined by the following bit layout.
* [Common |Device Type|Required Access|Custom|Function Code|Transfer Type]
*   31     30       16 15          14  13   12           2  1            0
*
*   Common          - 1 bit.  This is set for user-defined device types.
*   Device Type     - This is the type of device the IOCTL belongs to.
*					   This can be user defined (Common bit set).
*					   This must match the device type of the device object.
*   Required Access - FILE_READ_DATA, FILE_WRITE_DATA, etc.
*                     This is the required access for the  device.
*   Custom          - 1 bit.  This is set for user-defined IOCTL's.
*					   This is used in the same manner as "WM_USER".
*   Function Code   - This is the function code that the system or the
*					   user defined (custom bit set)
*   Transfer Type   - METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER,
*					   METHOD_BUFFERED, This the data transfer method to be used.
*/

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)
#endif

// Check the support for current processor and get the capabilities list
#define IOCTL_PTDRV_CHECKSUPPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_READ_DATA)
// Start a particular process trace
#define IOCTL_PTDRV_START_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_EXECUTE)
// Pause a process trace (needed to reliable read a TRACE)
#define IOCTL_PTDRV_PAUSE_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_EXECUTE)
// Resume a process trace (needed to reliable read a TRACE)
#define IOCTL_PTDRV_RESUME_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA07, METHOD_BUFFERED, FILE_EXECUTE)
// Stop, cleanup a process trace and free the resource
#define IOCTL_PTDRV_CLEAR_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA09, METHOD_BUFFERED, FILE_EXECUTE)
// Get the TRACE details (like total number of packets and so on)
#define IOCTL_PTDR_GET_TRACE_DETAILS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0B, METHOD_BUFFERED, FILE_READ_DATA | FILE_EXECUTE)
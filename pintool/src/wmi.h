#pragma once
#include "pin.H"
#include "functions.h"
#include "helper.h"

namespace W {
#include <Windows.h>
#include <wbemcli.h>
}

#define SUCCEEDEDNEW(hr) (((W::HRESULT)(hr)) >= 0)

// false string use to patch away VBOXVIDEO
#define FALSESTR	    "win32k"
#define BP_NUMCORES		4
#define BP_MAC_VENDOR	"\x07\x01\x33"
#define BP_NETVENDOR	"Intel"
#define BP_FAKEPROCESS	"cmd.exe"
#define BP_WFAKEPROCESS	L"abc.exe"
#define BP_TIMER		150
#define BP_ICMP_CREATE	300
#define BP_ICMP_ECHO	200
#define BP_HKL_LAYOUT	0x040c040c				/* France (we likely used it for Retefe) */
#define BP_MUTEX		"suppli"				/* used to create a valid handle */

// these are exposed for now through WMI queries only
#define BP_DISKSIZE		1000LL					/* HDD size in GB		*/
#define BP_ACPIDEV		L"ACPI\\ACPI0003\\0"	/* Name of false device */
#define BP_MACADDR		L"06:02:27:9C:BB:27"	/* consistency with BP_MAC_VENDOR? :) */
#define BP_MUI			"it-IT"					/* MUI language string	*/

VOID WMI_Patch(W::LPCWSTR query, W::VARIANT* enumerator, LoggingInfo* logInfo);
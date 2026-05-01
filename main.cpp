#include <windows.h>
#include <cstdint>
#include <string>
#include <iomanip>
#include <vector>
#include <cstdio>
#include <conio.h>
#include <winternl.h>

int main() {
	LUID luid{};

	{
		BOOL ok = LookupPrivilegeValueW(
			NULL,
			SE_SYSTEM_ENVIRONMENT_NAME,
			&luid
		);

		if (!ok) {
			printf("Lookup privilege failed\n");
			printf("%lu\n", GetLastError());
			return 1;
		}
	}

	TOKEN_PRIVILEGES tp{};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	HANDLE processAccessToken = NULL;
	{
		BOOL ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &processAccessToken);

		if (!ok) {
			printf("Open Process token failed\n");
			printf("%lu\n", GetLastError());
			return 1;
		}
	}

	{
		BOOL ok = AdjustTokenPrivileges(
			processAccessToken,
			FALSE,
			&tp,
			sizeof(tp),
			NULL,
			NULL
		);

		if (!ok) {
			printf("Adjust Token Privileges failed\n");
			printf("%lu\n", GetLastError());
			return 1;
		}
	}

	BYTE outBuf[1];

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) return 1;

	{
		using NtQuerySystemEnvironmentValueEx_t = NTSTATUS(NTAPI *) (
			IN PUNICODE_STRING VariableName,
			IN LPGUID VendorGuid,
			OUT PVOID Value,
			IN PULONG ValueSize,
			OUT PULONG ReturnLength
		);
		auto NtQuerySystemEnvironmentValueEx = (NtQuerySystemEnvironmentValueEx_t)GetProcAddress(ntdll, "NtQuerySystemEnvironmentValueEx");

		using RtlInitUnicodeString_t = decltype(&RtlInitUnicodeString);
		auto RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");

		using RtlGUIDFromString_t = NTSTATUS(NTAPI *)(PUNICODE_STRING GuidString, GUID *Guid);
		auto RtlGUIDFromString = (RtlGUIDFromString_t)GetProcAddress(ntdll, "RtlGUIDFromString");

		ULONG outBufSize = sizeof(outBuf);

		UNICODE_STRING variableName;
		RtlInitUnicodeString(&variableName, L"SecureBoot");

		UNICODE_STRING efiGlobalVariableGUIDString;
		RtlInitUnicodeString(&efiGlobalVariableGUIDString, L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}");

		GUID efiGlobalVariableGuid;
		RtlGUIDFromString(&efiGlobalVariableGUIDString, &efiGlobalVariableGuid);

		{
			NTSTATUS ok = NtQuerySystemEnvironmentValueEx(
				&variableName,
				&efiGlobalVariableGuid,
				outBuf,
				&outBufSize,
				NULL
			);

			if (!NT_SUCCESS(ok)) {
				printf("NtQuerySystemEnvironmentValueEx failed: %x\n", ok);
				return 1;
			}
		}

	}

	printf("%-45s %s\n", "NtQuerySystemEnvironmentValueEx Result:", ((int)outBuf == 1) ? "true" : "false");

	HKEY hSecureBoot = NULL;
	{
		LSTATUS ok = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
			NULL,
			KEY_QUERY_VALUE,
			&hSecureBoot
		);

		if (ok != ERROR_SUCCESS) {
			printf("failed to open SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecureBoot\\\\State: %lu\n", GetLastError());
			return 1;
		}
	}

	DWORD isSecureBootEnabled = FALSE;
	{
		DWORD bufSize = sizeof(isSecureBootEnabled);
		LSTATUS ok = RegQueryValueExW(
			hSecureBoot,
			L"UEFISecureBootEnabled",
			NULL,
			NULL,
			(BYTE *)&isSecureBootEnabled,
			&bufSize
		);

		RegCloseKey(hSecureBoot);

		if (ok != ERROR_SUCCESS) {
			printf("failed to query UEFISecureBootEnabled from hSecureBoot: %lu\n", GetLastError());
			return 1;
		}
	}

	printf("%-45s %s\n", "Secure Boot state from registry:", (isSecureBootEnabled == 1) ? "true" : "false");

	DWORD isCapableOfSecureBoot = FALSE;
	HKEY hSecureBootServicing = NULL;

	{
		LSTATUS ok = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing",
			NULL,
			KEY_QUERY_VALUE,
			&hSecureBootServicing
		);

		if (ok != ERROR_SUCCESS) {
			printf("failed to open SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecureBoot\\\\Servicing: %lu\n", GetLastError());
			return 1;
		}
	}

	{
		DWORD bufSize = sizeof(isCapableOfSecureBoot);
		LSTATUS ok = RegQueryValueExW(
			hSecureBootServicing,
			L"WindowsUEFICA2023Capable",
			NULL,
			NULL,
			(BYTE *)&isCapableOfSecureBoot,
			&bufSize
		);

		RegCloseKey(hSecureBootServicing);

		if (ok != ERROR_SUCCESS) {
			printf("failed to query WindowsUEFICA2023Capable from hSecureBootServicing: %lu", GetLastError());
			return 1;
		}
	}

	printf("%-45s %s\n", "is capable of secure boot from registry:", (isCapableOfSecureBoot != 0) ? "true" : "false");

	(void)_getch();
}
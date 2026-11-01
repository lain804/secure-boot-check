#define PHNT_VERSION PHNT_WINDOWS_10

#include <lainwinutils/phnt/phnt_windows.h>
#include <lainwinutils/phnt/phnt.h>

#include <cstdint>
#include <string>
#include <cstdio>
#include <conio.h>

HMODULE ntdll{};

using NtQuerySystemInformation_t = decltype(&NtQuerySystemInformation);
NtQuerySystemInformation_t pNtQuerySystemInformation{};

using NtQuerySystemEnvironmentValueEx_t = decltype(&NtQuerySystemEnvironmentValueEx);
NtQuerySystemEnvironmentValueEx_t pNtQuerySystemEnvironmentValueEx{};

using RtlInitUnicodeString_t = decltype(&RtlInitUnicodeString);
RtlInitUnicodeString_t pRtlInitUnicodeString{};

using RtlGUIDFromString_t = decltype(&RtlGUIDFromString);
RtlGUIDFromString_t pRtlGUIDFromString{};

void set_privilege_enabled(LPCWSTR privilege_name, bool enable) {
	LUID luid{};
	TOKEN_PRIVILEGES tp{};
	HANDLE process_access_token{};
	bool success{};

	{
		BOOL ok = LookupPrivilegeValueW(
			NULL,
			privilege_name,
			&luid
		);

		if (!ok) {
			fprintf(stderr, "Lookup privilege failed\n");
			fprintf(stderr, "%#lX\n", GetLastError());
			goto cleanup;
		}
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (enable) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		// there is no macro for disabling an existing specific privilege without removing it, its just 0
		tp.Privileges[0].Attributes = 0ul;
	}

	{
		BOOL ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &process_access_token);
		if (!ok) {
			fprintf(stderr, "Open Process token failed\n");
			fprintf(stderr, "%#lX\n", GetLastError());
			goto cleanup;
		}
	}

	{
		BOOL ok = AdjustTokenPrivileges(
			process_access_token,
			FALSE,
			&tp,
			sizeof(tp),
			NULL,
			NULL
		);
		if (!ok) {
			fprintf(stderr, "Adjust Token Privileges failed\n");
			fprintf(stderr, "%#lX\n", GetLastError());
			goto cleanup;
		}
	}
	
	success = true;

cleanup:
	_flushall();
	if (process_access_token) {
		CloseHandle(process_access_token);
	};
	if (!success) {
		exit(EXIT_FAILURE);
	}
}

bool is_secure_boot_enabled_NtQuerySystemEnvironmentValueEx_check() {
	bool out_buf{};
	{
		ULONG out_buf_size = sizeof(out_buf);

		UNICODE_STRING variable_name;
		pRtlInitUnicodeString(&variable_name, L"SecureBoot");

		UNICODE_STRING efi_global_variable_GUID_string;
		pRtlInitUnicodeString(&efi_global_variable_GUID_string, L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}");

		GUID efi_global_variable_GUID;
		pRtlGUIDFromString(&efi_global_variable_GUID_string, &efi_global_variable_GUID);

		{
			NTSTATUS ok = pNtQuerySystemEnvironmentValueEx(
				&variable_name,
				&efi_global_variable_GUID,
				&out_buf,
				&out_buf_size,
				NULL
			);
			if (!NT_SUCCESS(ok)) {
				fprintf(stderr, "NtQuerySystemEnvironmentValueEx failed: %#lX\n", ok);
				_flushall();
				exit(EXIT_FAILURE);
			}
		}
	}
	return out_buf;
}

bool is_secure_boot_enabled_registry_check() {
	DWORD is_secure_boot_enabled = 0;

	HKEY secure_boot_state_key_handle{};
	{
		LSTATUS ok = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
			NULL,
			KEY_QUERY_VALUE,
			&secure_boot_state_key_handle
		);
		if (ok != ERROR_SUCCESS) {
			fprintf(stderr, "Failed to open SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecureBoot\\\\State: %#lX\n", GetLastError());
			goto cleanup;
		}
	}

	{
		DWORD buf_size = sizeof(is_secure_boot_enabled);
		LSTATUS ok = RegQueryValueExW(
			secure_boot_state_key_handle,
			L"UEFISecureBootEnabled",
			NULL,
			NULL,
			(BYTE *)&is_secure_boot_enabled,
			&buf_size
		);
		if (ok != ERROR_SUCCESS) {
			fprintf(stderr, "Failed to query UEFISecureBootEnabled from secure_boot_state_key_handle: %#lX\n", GetLastError());
			goto cleanup;
		}
	}

cleanup:
	_flushall();
	if (secure_boot_state_key_handle) {
		RegCloseKey(secure_boot_state_key_handle);
	}
	return is_secure_boot_enabled == TRUE;
}

bool is_secure_boot_capable_registry_check() {
	DWORD secure_boot_capability = FALSE;
	
	HKEY secure_boot_servicing_key_handle = NULL;
	{
		LSTATUS ok = RegOpenKeyExW(
			HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing",
			NULL,
			KEY_QUERY_VALUE,
			&secure_boot_servicing_key_handle
		);

		if (ok != ERROR_SUCCESS) {
			fprintf(stderr, "failed to open SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecureBoot\\\\Servicing: %lu\n", GetLastError());
			goto cleanup;
		}
	}

	{
		DWORD bufSize = sizeof(secure_boot_capability);
		LSTATUS ok = RegQueryValueExW(
			secure_boot_servicing_key_handle,
			L"WindowsUEFICA2023Capable",
			NULL,
			NULL,
			(BYTE *)&secure_boot_capability,
			&bufSize
		);


		if (ok != ERROR_SUCCESS) {
			fprintf(stderr, "failed to query WindowsUEFICA2023Capable from secure_boot_servicing_key_handle: %lu", GetLastError());
			goto cleanup;
		}
	}

cleanup:
	if (secure_boot_servicing_key_handle) {
		RegCloseKey(secure_boot_servicing_key_handle);
	}

	enum WindowsUEFICA2023Capable : DWORD {
		NotInstalled = 0,
		Installed = 1,
		BootingWith2023CA = 2
	};

	return secure_boot_capability == WindowsUEFICA2023Capable::BootingWith2023CA;
}

bool is_secure_boot_enabled_NtQuerySystemInformation_check() {
	SYSTEM_SECUREBOOT_INFORMATION ssi{};

	{
		ULONG out_len;
		NTSTATUS ok = pNtQuerySystemInformation(
			SYSTEM_INFORMATION_CLASS::SystemSecureBootInformation, 
			&ssi, 
			sizeof(SYSTEM_SECUREBOOT_INFORMATION), 
			&out_len
		);
		if (!NT_SUCCESS(ok)) {
			fprintf(stderr, "Ntqsi SystemSecureBootInformation has failed: %#lX\n", ok);
			exit(EXIT_FAILURE);
		}
	}

	return ssi.SecureBootEnabled == TRUE;
}

bool is_secure_boot_enabled_KUSER_SHARED_DATA_check() {
	PKUSER_SHARED_DATA kuser_shared_data = USER_SHARED_DATA;
	return kuser_shared_data->DbgSecureBootEnabled == TRUE;
}

bool is_secure_boot_capable_NtQuerySystemInformation_check() {
	SYSTEM_SECUREBOOT_INFORMATION ssi{};
	{
		ULONG outLen;
		NTSTATUS ok = pNtQuerySystemInformation(
			SYSTEM_INFORMATION_CLASS::SystemSecureBootInformation,
			&ssi,
			sizeof(SYSTEM_SECUREBOOT_INFORMATION),
			&outLen
		);
		if (!NT_SUCCESS(ok)) {
			fprintf(stderr, "Ntqsi SystemSecureBootInformation has failed: %#lX\n", ok);
			_flushall();
			exit(EXIT_FAILURE);
		}
	}

	return ssi.SecureBootCapable == TRUE;
}

bool is_secure_boot_enabled_secure_boot_policy_check() {
	SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION sspfi{};
	ULONG outLen;
	NTSTATUS ok = pNtQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS::SystemSecureBootPolicyFullInformation,
		&sspfi,
		sizeof(sspfi),
		&outLen
	);
	return ok != STATUS_SECUREBOOT_NOT_ENABLED;
}

int main() {
	ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		fprintf(stderr, "Every process howls its name, I yield in silence\n");
		_flushall();
		exit(EXIT_FAILURE);
	}

	pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
	pNtQuerySystemEnvironmentValueEx = (NtQuerySystemEnvironmentValueEx_t)GetProcAddress(ntdll, "NtQuerySystemEnvironmentValueEx");
	pRtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");
	pRtlGUIDFromString = (RtlGUIDFromString_t)GetProcAddress(ntdll, "RtlGUIDFromString");

	set_privilege_enabled(SE_SYSTEM_ENVIRONMENT_NAME, true);

	printf("%-69s %d\n", "NtQuerySystemEnvironmentValueEx check:", (int)is_secure_boot_enabled_NtQuerySystemEnvironmentValueEx_check());
	printf("%-69s %d\n", "NtQuerySystemInformation SystemSecureBootInformation check:", (int)is_secure_boot_enabled_NtQuerySystemInformation_check());
	printf("%-69s %d\n", "NtQuerySystemInformation SystemSecureBootPolicyFullInformation check:", (int)is_secure_boot_enabled_secure_boot_policy_check());
	printf("%-69s %d\n", "KUSER_SHARED_DATA DbgSecureBootEnabled check:", (int)is_secure_boot_enabled_KUSER_SHARED_DATA_check());
	printf("%-69s %d\n", "Registry UEFISecureBootEnabled check:", (int)is_secure_boot_enabled_registry_check());

	printf("\n");

	printf("%-69s %d\n", "NtQuerySystemInformation SystemSecureBootInformation capable check:", (int)is_secure_boot_capable_NtQuerySystemInformation_check());
	printf("%-69s %d\n", "Registry WindowsUEFICA2023Capable capable check:", (int)is_secure_boot_capable_registry_check());

	(void)_flushall();

	(void)_getch();
}

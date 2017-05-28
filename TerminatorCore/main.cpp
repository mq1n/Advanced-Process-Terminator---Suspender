#include "main.h"
#include "TerminatorCore.h"
#pragma comment( lib, "psapi.lib" )

#pragma region Apis
static HMODULE						hNtdll						= nullptr;
static HMODULE						hUser32						= nullptr;
static HMODULE						hWinsta						= nullptr;
static lpNtGetNextProcess			NtGetNextProcess			= nullptr;
static lpNtGetNextThread			NtGetNextThread				= nullptr;
static lpNtTerminateProcess			NtTerminateProcess			= nullptr;
static lpNtTerminateThread			NtTerminateThread			= nullptr;
static lpNtCreateDebugObject		NtCreateDebugObject			= nullptr;
static lpNtDebugActiveProcess		NtDebugActiveProcess		= nullptr;
static lpEndTask					EndTask						= nullptr;
static lpWinStationTerminateProcess	WinStationTerminateProcess	= nullptr;
static lpNtSuspendProcess			NtSuspendProcess			= nullptr;
static lpNtQuerySystemInformation	NtQuerySystemInformation	= nullptr;
static lpNtDuplicateObject			NtDuplicateObject			= nullptr;
#pragma endregion Apis

TerminatorCore::CTerminatorCore::CTerminatorCore()
{
	hNtdll = LoadLibraryA("ntdll");
	assert(hNtdll);

	hUser32 = LoadLibraryA("user32");
	assert(hUser32);

	hWinsta = LoadLibraryA("winsta");
	assert(hWinsta);


	NtGetNextProcess = (lpNtGetNextProcess)GetProcAddress(hNtdll, "NtGetNextProcess");
	assert(NtGetNextProcess);

	NtGetNextThread = (lpNtGetNextThread)GetProcAddress(hNtdll, "NtGetNextThread");
	assert(NtGetNextThread);

	NtTerminateProcess = (lpNtTerminateProcess)GetProcAddress(hNtdll, "NtTerminateProcess");
	assert(NtTerminateProcess);

	NtTerminateThread = (lpNtTerminateThread)GetProcAddress(hNtdll, "NtTerminateThread");
	assert(NtTerminateThread);

	NtCreateDebugObject = (lpNtCreateDebugObject)GetProcAddress(hNtdll, "NtCreateDebugObject");
	assert(NtCreateDebugObject);

	NtDebugActiveProcess = (lpNtDebugActiveProcess)GetProcAddress(hNtdll, "NtDebugActiveProcess");
	assert(NtDebugActiveProcess);

	EndTask = (lpEndTask)GetProcAddress(hUser32, "EndTask");
	assert(EndTask);

	WinStationTerminateProcess = (lpWinStationTerminateProcess)GetProcAddress(hWinsta, "WinStationTerminateProcess");
	assert(WinStationTerminateProcess);

	NtSuspendProcess = (lpNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
	assert(NtSuspendProcess);

	NtQuerySystemInformation = (lpNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	assert(NtSuspendProcess);

	NtDuplicateObject = (lpNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
	assert(NtSuspendProcess);

}

std::vector<HANDLE> vHandleList;
static void CloseHandles()
{
	for (size_t i = 0; i < vHandleList.size(); i++)
	{
		__try { CloseHandle(vHandleList[i]); }
		__except (1) { }
	}
	vHandleList.clear();
}

void TerminatorCore::CTerminatorCore::ListProcesses()
{
	DWORD dwExitCode = 0;
	HANDLE hCurr = nullptr;

	while (NtGetNextProcess(hCurr, MAXIMUM_ALLOWED, 0, 0, &hCurr) == STATUS_SUCCESS)
	{
		if (!GetExitCodeProcess(hCurr, &dwExitCode) || dwExitCode != STILL_ACTIVE)
			continue;

		auto dwPid = GetProcessId(hCurr);
		auto szName = GetProcessName(hCurr);
		// printf("%p(%u) - %s\n", hCurr, dwPid, szName.c_str());
		printf("%u - %s\n", dwPid, szName.c_str());

		vHandleList.push_back(hCurr);
	}

	CloseHandles();
}


std::vector<HWND> vWindowList;
bool ListWindows(DWORD dwProcessId)
{
	HWND hWnd = nullptr;

	do
	{
		hWnd = FindWindowExA(NULL, hWnd, NULL, NULL);

		DWORD dwPID = 0;
		GetWindowThreadProcessId(hWnd, &dwPID);

		if (dwPID == dwProcessId)
			vWindowList.push_back(hWnd);
	} while (hWnd);

	return (vWindowList.size() > 0);
}


static std::map<EKillMethods, std::string> mKillMethodNames = {
	{ Exit_TerminateProcess,								"TerminateProcess" },
	{ Exit_TerminateThread,									"TerminateThread" },
	{ Exit_CreateRemoteThreadExitProcess,					"CreateRemoteThread + ExitProcess" },
	{ Exit_EipModificationExitProcess,						"Eip Modification + ExitProcess" },
	{ Exit_DebugActiveProcess,								"DebugActiveProcess" },
	{ Exit_EndTask,											"EndTask" },
	{ Exit_WM_CLOSE,										"WM_CLOSE" },
	{ Exit_SC_CLOSE,										"SC_CLOSE" },
	{ Exit_WinstationTerminate,								"WinStationTerminateProcess" },
	{ Exit_ShellCode,										"Inject shellcode" },
	{ Exit_AE_RESACCESS2,									"Send AE_RESACCESS2 message" },
	{ Exit_ALL_METHODS,										"Use all methods for terminate" },
	{ Crash_VirtualProtectEx,								"Crash with VirtualProtectEx" },
	{ Crash_WriteProcessMemory,								"Crash with WriteProcessMemory" },
	{ Crash_DuplicateHandle,								"Crash with DuplicateHandle" },
	{ Crash_JobObject,										"Crash with CreateJobObject, AssignProcessToJobObject, TerminateJobObject" },
	{ Suspend_AllThreads,									"Suspend All Threads" },
	{ Suspend_Process,										"Suspend Process" },
};
std::string TerminatorCore::CTerminatorCore::GetKillMethodName(EKillMethods kmMethod)
{
	auto it = mKillMethodNames.find(kmMethod);
	if (it == mKillMethodNames.end())
		return std::string("Undefined method: " + kmMethod);
	return it->second;
}


static HANDLE GetProcessHandle(DWORD dwProcessId)
{
	HANDLE hTarget = nullptr;
	HANDLE hCurr = nullptr;

	while (NtGetNextProcess(hCurr, MAXIMUM_ALLOWED, 0, 0, &hCurr) == STATUS_SUCCESS)
	{
		if (dwProcessId == GetProcessId(hCurr)) {
			hTarget = hCurr;
			break;
		}
		vHandleList.push_back(hCurr);
	}

	CloseHandles();
	return hTarget;
}

static void CreateThreadList(HANDLE hOwnerProcess)
{
	HANDLE hCurr = nullptr;

	while (NtGetNextThread(hOwnerProcess, hCurr, MAXIMUM_ALLOWED, 0, 0, &hCurr) == STATUS_SUCCESS)
		vHandleList.push_back(hCurr);
}


bool TerminatorCore::CTerminatorCore::KillProcessEx(EKillMethods kmMethod, HANDLE hProcess)
{
	DWORD dwExitCodeOfProcess = 0;
	NTSTATUS ntStat = STATUS_SUCCESS;

	switch (kmMethod)
	{
		case Exit_TerminateProcess:
		{
			ntStat = NtTerminateProcess(hProcess, EXIT_SUCCESS);
			return (ntStat == STATUS_SUCCESS);
		} break;

		case Exit_TerminateThread:
		{
			// Create thread list
			CreateThreadList(hProcess);

			// Close Threads of target process
			for (const auto & hThread : vHandleList)
			{
				ntStat = NtTerminateThread(hThread, STATUS_SUCCESS);
				if (ntStat != STATUS_SUCCESS) {
					CloseHandles();
					printf("Thread: %u can not terminated!\n", GetThreadId(hThread));
					return false;
				}
			}

			// Close created thread handles
			CloseHandles();
			
			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_CreateRemoteThreadExitProcess:
		{
			auto hExitThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)ExitProcess, nullptr, 0, nullptr);
			if (!hExitThread || hExitThread == INVALID_HANDLE_VALUE) {
				printf("Exit thread can not created! Error code: %u\n", GetLastError());
				return false;
			}

			auto dwWaitRet = WaitForSingleObject(hExitThread, 5000);
			if (dwWaitRet == WAIT_TIMEOUT) {
				printf("Exit thread timeout! Error code: %u\n", GetLastError());
				return false;
			}

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_EipModificationExitProcess:
		{
			// Create thread list
			CreateThreadList(hProcess);

			// Set new EIP to target process's threads
			for (const auto & hThread : vHandleList)
			{
				if (SuspendThread(hThread) == (DWORD)-1)
					continue;

				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_CONTROL;
				if (!GetThreadContext(hThread, &ctx)) {
					ResumeThread(hThread);
					continue;
				}

#ifdef _WIN64
				ctx.Rip = (DWORD64)ExitProcess;
#else
				ctx.Eip = (DWORD)ExitProcess;
#endif

				if (!SetThreadContext(hThread, &ctx)) {
					ResumeThread(hThread);
					continue;
				}

				if (ResumeThread(hThread) == (DWORD)-1)
					continue;
			}

			// Close created thread handles
			CloseHandles();

			WaitForSingleObject(hProcess, INFINITE);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_DebugActiveProcess:
		{
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, 0, 0, 0, 0);

			HANDLE hDebugObject;
			ntStat = NtCreateDebugObject(&hDebugObject, DEBUG_ALL_ACCESS, &oa, DEBUG_OBJECT_KILLONCLOSE);
			if (ntStat >= STATUS_SUCCESS)
				NtDebugActiveProcess(hProcess, hDebugObject);
			CloseHandle(hDebugObject);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_EndTask:
		{
			auto bListRet = ListWindows(GetProcessId(hProcess));
			if (!bListRet) return false;

			for (const auto & hWnd : vWindowList)
				EndTask(hWnd, FALSE, TRUE);

			vWindowList.clear();

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_WM_CLOSE:
		{
			auto bListRet = ListWindows(GetProcessId(hProcess));
			if (!bListRet) return false;

			for (const auto & hWnd : vWindowList)
			{
				SendMessageA(hWnd, WM_CLOSE, 0, 0);
				SendMessageA(hWnd, WM_QUIT, 0, 0);
				SendMessageA(hWnd, WM_DESTROY, 0, 0);
			}

			vWindowList.clear();

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_SC_CLOSE:
		{
			auto bListRet = ListWindows(GetProcessId(hProcess));
			if (!bListRet) return false;

			for (const auto & hWnd : vWindowList)
				SendMessageA(hWnd, SC_CLOSE, 0, 0);

			vWindowList.clear();

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_WinstationTerminate:
		{
			auto dwProcessId = GetProcessId(hProcess);

			WinStationTerminateProcess(NULL, dwProcessId, DBG_TERMINATE_PROCESS);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_ShellCode:
		{
			// Create thread list
			CreateThreadList(hProcess);

			// Set new EIP to target process's threads
			for (const auto & hThread : vHandleList)
			{
				if (SuspendThread(hThread) == (DWORD)-1)
					continue;

				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_CONTROL;
				if (!GetThreadContext(hThread, &ctx)) {
					ResumeThread(hThread);
					continue;
				}

#ifdef _WIN64
				auto dwEipAdr = (DWORD64)ctx.Rip;
#else
				auto dwEipAdr = (DWORD)ctx.Eip;
#endif

				CHAR pRet[] = { 0x31, 0xC0, 0xC3 };
				SIZE_T writtenByteSize = 0;
				auto bWriteRet = WriteProcessMemory(hProcess, (LPVOID)dwEipAdr, pRet, 0x3, &writtenByteSize);
				if (bWriteRet == FALSE) {
					ResumeThread(hThread);
					continue;
				}

				if (ResumeThread(hThread) == (DWORD)-1)
					continue;
			}

			// Close created thread handles
			CloseHandles();

			WaitForSingleObject(hProcess, INFINITE);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_AE_RESACCESS2:
		{
			auto bListRet = ListWindows(GetProcessId(hProcess));
			if (!bListRet) return false;

			for (const auto & hWnd : vWindowList)
				PostMessageA(hWnd, AE_RESACCESS2, 0, 0);

			vWindowList.clear();

			WaitForSingleObject(hProcess, 5000);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Crash_VirtualProtectEx:
		{
			auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
			if (!hSnap || hSnap == INVALID_HANDLE_VALUE) return false;

			MODULEENTRY32 modEntry;
			modEntry.dwSize = sizeof(MODULEENTRY32);
			if (!Module32First(hSnap, &modEntry)) return false;

			auto dwBaseAdr = modEntry.hModule;
			auto dwBaseSize = modEntry.modBaseSize;

			CloseHandle(hSnap);

			DWORD dwOldProtect = 0;
			auto bProtectRet = VirtualProtectEx(hProcess, dwBaseAdr, dwBaseSize, PAGE_NOACCESS, &dwOldProtect);
			if (!bProtectRet) return false;

			WaitForSingleObject(hProcess, INFINITE);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Crash_WriteProcessMemory:
		{
			SYSTEM_INFO sysINFO;
			GetSystemInfo(&sysINFO);

			PBYTE pCurAddr = (PBYTE)sysINFO.lpMinimumApplicationAddress;
			PBYTE pMaxAddr = (PBYTE)sysINFO.lpMaximumApplicationAddress;

			BYTE stub[] = { 0xC3 };
			MEMORY_BASIC_INFORMATION mbi;
			while (pCurAddr < pMaxAddr)
			{
				if (VirtualQueryEx(hProcess, pCurAddr, &mbi, sizeof(mbi)))
					WriteProcessMemory(hProcess, mbi.BaseAddress, &stub, mbi.RegionSize, 0);

				pCurAddr += mbi.RegionSize;
			}

			WaitForSingleObject(hProcess, INFINITE);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Crash_DuplicateHandle:
		{
			ULONG handleInfoSize = 0x10000;
			PSYSTEM_HANDLE_INFORMATION handleInfo = 0;
			HANDLE hDuplicateHandle = NULL;

			handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
			ZeroMemory(handleInfo, handleInfoSize);

			while ((ntStat = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
			{
				handleInfoSize *= 2;
				handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
			}

			if (!NT_SUCCESS(ntStat)) {
				free(handleInfo);
				return false;
			}

			for (ULONG i = 0; i < handleInfo->HandleCount; i++)
			{
				auto handle = handleInfo->Handles[i];

				if (handle.ProcessId != GetProcessId(hProcess))
					continue;

				if (DuplicateHandle(hProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &hDuplicateHandle, 0, FALSE, DUPLICATE_CLOSE_SOURCE) == FALSE)
				{
					printf("Can't get handle %08x from process %u\n", handle.Handle, handle.ProcessId);
					continue;
				}

				CloseHandle(hDuplicateHandle);
			}

			free(handleInfo);

			WaitForSingleObject(hProcess, INFINITE);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Crash_JobObject:
		{
			HANDLE Jobject = CreateJobObjectA(NULL, "Job");
			if (!Jobject || Jobject == INVALID_HANDLE_VALUE)
				return false;

			if (!AssignProcessToJobObject(Jobject, hProcess))
				return false;

			if (!TerminateJobObject(Jobject, EXIT_SUCCESS))
				return false;

			WaitForSingleObject(hProcess, INFINITE);

			// Check process status
			if (!GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess == STILL_ACTIVE)
				return false;
			return true;
		} break;

		case Exit_ALL_METHODS:
		{
			bool bExitRet = false;

			bExitRet = KillProcessEx(Exit_TerminateProcess, hProcess);
			printf("Method 1 completed. %s | Result: %s", GetKillMethodName(Exit_TerminateProcess).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_TerminateThread, hProcess);
			printf("Method 2 completed. %s | Result: %s", GetKillMethodName(Exit_TerminateThread).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_CreateRemoteThreadExitProcess, hProcess);
			printf("Method 3 completed. %s | Result: %s", GetKillMethodName(Exit_CreateRemoteThreadExitProcess).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_EipModificationExitProcess, hProcess);
			printf("Method 4 completed. %s | Result: %s", GetKillMethodName(Exit_EipModificationExitProcess).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_DebugActiveProcess, hProcess);
			printf("Method 5 completed. %s | Result: %s", GetKillMethodName(Exit_DebugActiveProcess).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_EndTask, hProcess);
			printf("Method 6 completed. %s | Result: %s", GetKillMethodName(Exit_EndTask).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_WM_CLOSE, hProcess);
			printf("Method 7 completed. %s | Result: %s", GetKillMethodName(Exit_WM_CLOSE).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_SC_CLOSE, hProcess);
			printf("Method 8 completed. %s | Result: %s", GetKillMethodName(Exit_SC_CLOSE).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_WinstationTerminate, hProcess);
			printf("Method 9 completed. %s | Result: %s", GetKillMethodName(Exit_WinstationTerminate).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_ShellCode, hProcess);
			printf("Method 10 completed. %s | Result: %s", GetKillMethodName(Exit_ShellCode).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Exit_AE_RESACCESS2, hProcess);
			printf("Method 11 completed. %s | Result: %s", GetKillMethodName(Exit_AE_RESACCESS2).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Crash_VirtualProtectEx, hProcess);
			printf("Method 12 completed. %s | Result: %s", GetKillMethodName(Crash_VirtualProtectEx).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Crash_WriteProcessMemory, hProcess);
			printf("Method 13 completed. %s | Result: %s", GetKillMethodName(Crash_WriteProcessMemory).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Crash_DuplicateHandle, hProcess);
			printf("Method 14 completed. %s | Result: %s", GetKillMethodName(Crash_DuplicateHandle).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;

			KillProcessEx(Crash_JobObject, hProcess);
			printf("Method 15 completed. %s | Result: %s", GetKillMethodName(Crash_JobObject).c_str(), bExitRet ? "OK" : "Fail");
			if (bExitRet) return true;


			return bExitRet;
		} break;

		case Suspend_AllThreads:
		{
			// Create thread list
			CreateThreadList(hProcess);

			for (const auto & hThread : vHandleList)
			{
				if (SuspendThread(hThread) == (DWORD)-1)
					return false;
			}

			// Close created thread handles
			CloseHandles();
			return true;
		} break;

		case Suspend_Process:
		{
			ntStat = NtSuspendProcess(hProcess);
			return (ntStat == STATUS_SUCCESS);
		} break;

		default:
			printf("Unknown or undefined kill method: %d\n", kmMethod);
			return false;
	}

	CloseHandle(hProcess);
	return true;
}

bool TerminatorCore::CTerminatorCore::KillProcess(EKillMethods kmMethod, DWORD dwProcessId)
{
	DWORD dwExitCodeOfProcess = 0;
	auto hProcess = GetProcessHandle(dwProcessId);
	if (!hProcess || !GetExitCodeProcess(hProcess, &dwExitCodeOfProcess) || dwExitCodeOfProcess != STILL_ACTIVE) {
		printf("GetProcessHandle fail! Error code: %u\n", GetLastError());
		return false;
	}
	printf("Process handle created: %p\n", hProcess);


	printf("Method: %d -> %s triggered!\n", kmMethod, GetKillMethodName(kmMethod).c_str());

	bool bKillRet = KillProcessEx(kmMethod, hProcess);
	printf("Process terminate completed. Result: %s\n", bKillRet ? "OK" : "Fail");
	return bKillRet;
}


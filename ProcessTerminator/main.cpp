#include <Windows.h>
#include <iostream>
#include <assert.h>
#include <string>

#include "../TerminatorCore/TerminatorCore.h"
#ifdef _DEBUG
#pragma comment( lib, "../Debug/TerminatorCore.lib" )
#else
#pragma comment( lib, "../Release/TerminatorCore.lib" )
#endif
using namespace TerminatorCore;
static CTerminatorCore terminatorCore;


typedef NTSTATUS(NTAPI* lpRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
lpRtlAdjustPrivilege RtlAdjustPrivilege = nullptr;

int main()
{
	HMODULE hNtdll = LoadLibraryA("ntdll");
	assert(hNtdll);

	RtlAdjustPrivilege = (lpRtlAdjustPrivilege)GetProcAddress(LoadLibraryA("ntdll"), "RtlAdjustPrivilege");
	assert(RtlAdjustPrivilege);

	BOOLEAN boAdjustPrivRet;
	RtlAdjustPrivilege(20, TRUE, FALSE, &boAdjustPrivRet);


	printf("Advanced process terminator started!\n");
	Sleep(2000);


	printf("Kill methods: \n");
	for (int iCurrentMethod = KILL_METHOD_MIN + 1; iCurrentMethod != KILL_METHOD_MAX; iCurrentMethod++)
	{
		EKillMethods kmCurrentMethod = static_cast<EKillMethods>(iCurrentMethod);
		printf("%d) %s\n", iCurrentMethod, terminatorCore.GetKillMethodName(kmCurrentMethod).c_str());
	}

	printf("\nKill method: ");
	int iKillMethod = 0;
	std::cin >> iKillMethod;
	if (iKillMethod <= KILL_METHOD_MIN || iKillMethod >= KILL_METHOD_MAX) {
		printf("Unknown kill method: %d\n", iKillMethod);
		return 0;
	}


	terminatorCore.ListProcesses();


	printf("\nTarget Process: ");
	DWORD dwTargetPID = 0;
	std::cin >> dwTargetPID;

	auto bKillRet = terminatorCore.KillProcess(static_cast<EKillMethods>(iKillMethod), dwTargetPID);
	std::string szMsgOK = "Process: " + std::to_string(dwTargetPID) + " succesfully terminated!\n";
	std::string szMsgFail = "Process: " + std::to_string(dwTargetPID) + " can NOT terminated!\n";
	printf("%s", bKillRet ? szMsgOK.c_str() : szMsgFail.c_str());


	printf("Completed!\n");
	Sleep(INFINITE);
	return 0;
}


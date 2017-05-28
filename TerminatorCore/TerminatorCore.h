#pragma once

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <string>

enum EKillMethods {
	KILL_METHOD_MIN,
	Exit_TerminateProcess,
	Exit_TerminateThread,
	Exit_CreateRemoteThreadExitProcess,
	Exit_EipModificationExitProcess,
	Exit_DebugActiveProcess,
	Exit_EndTask,
	Exit_WM_CLOSE,
	Exit_SC_CLOSE,
	Exit_WinstationTerminate,
	Exit_ShellCode,
	Exit_AE_RESACCESS2,
	Exit_ALL_METHODS,
	Crash_VirtualProtectEx,
	Crash_WriteProcessMemory,
	Crash_DuplicateHandle,
	Crash_JobObject,
	Suspend_AllThreads,
	Suspend_Process,
	KILL_METHOD_MAX
};

namespace TerminatorCore
{
	class CTerminatorCore
	{
		public:
			CTerminatorCore();

			void ListProcesses();

			std::string GetKillMethodName(EKillMethods kmMethod);
			bool KillProcess(EKillMethods kmMethod, DWORD dwProcessId);

		protected:
			bool KillProcessEx(EKillMethods kmMethod, HANDLE hProcess);
	};
}


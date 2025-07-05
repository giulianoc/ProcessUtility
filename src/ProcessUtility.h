/*
 Copyright (C) Giuliano Catrambone (giuliano.catrambone@catrasoftware.it)

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either
 version 2 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 Commercial use other than under the terms of the GNU General Public
 License is allowed only after express negotiation of conditions
 with the authors.
*/

#pragma once

#include "spdlog/spdlog.h"
#include <format>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace std;

class ProcessUtility
{

  public:
	struct ProcessId
	{
#ifdef _WIN32
		HANDLE processHandle = NULL;
		void reset() { processHandle = NULL; }
		bool isInitialized() { return processHandle != NULL; }
#else
		pid_t pid = -1;
		void reset() { pid = -1; }
		bool isInitialized() { return pid != -1; }
#endif
	};

  public:
	static void forkAndExec(
		string programPath,
		// first string is the program name, than we have the params
		vector<string> &argList, string redirectionPathName, bool redirectionStdOutput, bool redirectionStdError, ProcessId &processId,
		int *piReturnedStatus
	);

	template <typename Func> static int forkAndExec(Func func, int timeoutSeconds = 10, string referenceToLog = "");

	static int execute(string command);

	static void killProcess(ProcessId processId);
	static void termProcess(ProcessId processId);
	static void quitProcess(ProcessId processId);

	static void launchUnixDaemon(string pidFilePathName);
	static long getCurrentProcessIdentifier();
};

// #endif

template <typename Func> int ProcessUtility::forkAndExec(Func func, int timeoutSeconds, string referenceToLog)
{
	// Duplicate this process.
	pid_t childPid = fork();
	if (childPid == -1)
	{
		string errorMessage = std::format(
			"forkAndExec. Fork failed"
			"{}"
			", timeoutSeconds: {}"
			", errno: {}",
			referenceToLog, timeoutSeconds, errno
		);
		SPDLOG_ERROR(errorMessage);

		throw runtime_error(errorMessage);
	}

	if (childPid != 0)
	{
		// parent process
		// Status information about the child reported by wait is more than just the exit status of the child, it also includes
		// - normal/abnormal termination
		//		WIFEXITED(status): child exited normally
		//		WEXITSTATUS(status): return code when child exits
		// - termination cause
		//		WIFSIGNALED(status): child exited because a signal was not caught
		//		WTERMSIG(status): gives the number of the terminating signal
		// - exit status
		//		WIFSTOPPED(status): child is stopped
		//		WSTOPSIG(status): gives the number of the stop signal
		// if we want to prints information about a signal
		//	void psignal(unsigned sig, const char *s);

		// Processo padre: aspetta con timeout
		int waited = 0;
		int exitStatus = 0;
		while (waited < timeoutSeconds)
		{
			pid_t result = waitpid(childPid, &exitStatus, WNOHANG);
			if (result == 0)
			{
				if (waited % 60 == 0)
					SPDLOG_DEBUG(
						"forkAndExec. Still waiting the child process"
						"{}"
						", timeoutSeconds: {}",
						referenceToLog, timeoutSeconds
					);
				this_thread::sleep_for(chrono::seconds(1));
				waited++;
			}
			else
				break;
		}

		if (waited >= timeoutSeconds)
		{
			kill(childPid, SIGKILL);
			waitpid(childPid, &exitStatus, 0); // cleanup zombie

			exitStatus = -3; // timeout

			SPDLOG_ERROR(
				"forkAndExec. Child process timeout, killed"
				"{}"
				", timeoutSeconds: {}"
				", childPid: {}"
				", exitStatus: {}",
				referenceToLog, timeoutSeconds, childPid, exitStatus
			);

			return exitStatus;
		}

		exitStatus = WIFEXITED(exitStatus) ? WEXITSTATUS(exitStatus) : -4;

		SPDLOG_DEBUG(
			"forkAndExec. Child process terminated"
			"{}"
			", timeoutSeconds: {}"
			", exitStatus: {}",
			referenceToLog, timeoutSeconds, exitStatus
		);

		return exitStatus;
	}
	else
	{
		// Processo figlio: esegue il comando bloccante
		try
		{
			return func();
		}
		catch (const std::exception &e)
		{
			// std::cerr << "Error: " << e.what() << std::endl;
			return -1;
		}
	}
}

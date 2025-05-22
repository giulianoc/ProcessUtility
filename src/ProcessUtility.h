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
// #ifndef ProcessUtility_h
// #define ProcessUtility_h

#include "spdlog/spdlog.h"
#include <format>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace std;

class ProcessUtility
{

  public:
	static void forkAndExec(
		string programPath,
		// first string is the program name, than we have the params
		vector<string> &argList, string redirectionPathName, bool redirectionStdOutput, bool redirectionStdError, pid_t *pPid, int *piReturnedStatus
	);

	template <typename Func> static int forkAndExec(Func func, int timeoutSeconds = 10, string referenceToLog = "");

	static int execute(string command);

	static void killProcess(pid_t pid);
	static void termProcess(pid_t pid);
	static void quitProcess(pid_t pid);

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
		string errorMessage = std::format("Fork failed. errno: {}", errno);

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
					SPDLOG_INFO(
						"Still waiting the child process"
						"{}",
						referenceToLog
					);
				sleep(1);
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
				"Child process timeout, killed"
				"{}"
				", childPid: {}"
				", exitStatus: {}",
				referenceToLog, childPid, exitStatus
			);

			return exitStatus;
		}

		exitStatus = WIFEXITED(exitStatus) ? WEXITSTATUS(exitStatus) : -4;

		SPDLOG_INFO(
			"Child process terminated"
			"{}"
			", exitStatus: {}",
			referenceToLog, exitStatus
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

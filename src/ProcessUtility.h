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
#include "spdlog/spdlog.h"

class ProcessUtility
{

  public:
	struct ProcessId
	{
#ifdef _WIN32
		HANDLE processHandle = NULL;
		void reset() { processHandle = NULL; }
		bool isInitialized() { return processHandle != NULL; }
		std::string toString() { return std::format("{}", reinterpret_cast<uintptr_t>(processHandle)); }
#else
		pid_t pid = -1;
		void reset() { pid = -1; }
		[[nodiscard]] bool isInitialized() const { return pid != -1; }
		std::string toString() { return std::format("{}", pid); }
#endif
		auto operator<=>(const ProcessId &) const = default;
	};

	static void forkAndExec(
		const std::string &programPath,
		// first string is the program name, than we have the params
		std::vector<std::string> &argList, const std::string &redirectionPathName, bool redirectionStdOutput, bool redirectionStdError, ProcessId &processId,
		int &returnedStatus
	);

    using LineCallback = std::function<void(const std::string_view&)>;

	static void forkAndExecByCallback(
		const std::string &programPath,
		// first string is the program name, than we have the params
		const std::vector<std::string> &argList, const LineCallback& lineCallback, bool redirectionStdOutput, bool redirectionStdError, ProcessId &processId,
		int &returnedStatus
	);

#ifdef _WIN32
#else
	template <typename Func> static int forkAndExec(Func func, int timeoutSeconds = 10, std::string referenceToLog = "");
#endif

	static int execute(const std::string &command);

	static void killProcess(ProcessId processId);
#ifdef _WIN32
#else
	static void termProcess(ProcessId processId);
	static void quitProcess(ProcessId processId);
#endif

#ifdef _WIN32
#else
	static void launchUnixDaemon(std::string pidFilePathName);
#endif
	static long getCurrentProcessIdentifier();
};

// #endif

#ifdef _WIN32
#else
template <typename Func> int ProcessUtility::forkAndExec(Func func, int timeoutSeconds, std::string referenceToLog)
{
	// Duplicate this process.
	pid_t childPid = fork();
	if (childPid == -1)
	{
		std::string errorMessage = std::format(
			"forkAndExec. Fork failed"
			"{}"
			", timeoutSeconds: {}"
			", errno: {}",
			referenceToLog, timeoutSeconds, errno
		);
		SPDLOG_ERROR(errorMessage);

		throw std::runtime_error(errorMessage);
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
				std::this_thread::sleep_for(std::chrono::seconds(1));
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
#endif

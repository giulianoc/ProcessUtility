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

#include "ProcessUtility.h"
#include <assert.h>
#include <cstdlib>
#include <errno.h>
#include <fcntl.h>
#include <format>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void ProcessUtility::forkAndExec(
	string programPath,
	// first string is the program name, than we have the params
	vector<string> &argList, string redirectionPathName, bool redirectionStdOutput, bool redirectionStdError, ProcessId &processId,
	int &returnedStatus
)
{
#ifdef _WIN32
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hThread = NULL;

	try
	{
		bool redirectOnFile = redirectionPathName != "" && (redirectionStdOutput || redirectionStdError);
		if (redirectOnFile)
		{
			// 1. Crea file log
			SECURITY_ATTRIBUTES sa{sizeof(sa), NULL, TRUE}; // Handle ereditabile
			hFile = CreateFileA(redirectionPathName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			if (hFile == INVALID_HANDLE_VALUE)
				throw runtime_error("Unable to open log file: " + logFilePath);
		}

		STARTUPINFOA si = {sizeof(si)};
		if (redirectOnFile)
		{
			si.cb = sizeof(si);
			si.dwFlags = STARTF_USESTDHANDLES;
			si.hStdOutput = hFile;
			si.hStdError = hFile;
			si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		}
		PROCESS_INFORMATION pi;

		string command;
		{
			command = programPath + " ";

			for (int paramIndex = 0; paramIndex < argList.size(); paramIndex++)
				command = argList[paramIndex] + " ";
		}

		if (!CreateProcessA(NULL, cmdCopy.data(), NULL, NULL, redirectOnFile ? TRUE /* ereditare gli handle */ : FALSE, 0, NULL, NULL, &si, &pi))
			throw runtime_error("Failed to launch process: " + command);

		// salva gli handle per chiuderli in seguito
		processId.processHandle = pi.hProcess;
		hThread = pi.hThread;

		returnedStatus = -1;

		// 4. Attendi la fine del processo
		WaitForSingleObject(processId.processHandle, INFINITE);
		DWORD exitCode = 0;
		GetExitCodeProcess(processId.processHandle, &exitCode);

		// 5. Cleanup
		CloseHandle(hThread);
		CloseHandle(processId.processHandle);
		CloseHandle(hFile);

		returnedStatus = static_cast<int>(exitCode);
	}
	catch (const exception &ex)
	{
		// Cleanup anche in caso di errore
		if (hThread != NULL)
			CloseHandle(hThread);
		if (processId.processHandle != NULL)
			CloseHandle(processId.processHandle);
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);

		throw runtime_error(std::format("Exception: {}", ew.what()));
	}
#else
	// Duplicate this process.
	pid_t childPid = fork();
	if (childPid == -1)
	{
		// fork failed
		string errorMessage = string("Fork failed. errno: ") + to_string(errno);

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

		processId.pid = childPid;

		bool childTerminated = false;
		while (!childTerminated)
		{
			int wstatus;
			// pid_t childPid = wait(piReturnedStatus);
			// wait(&wstatus);
			pid_t waitPid = waitpid(childPid, &wstatus, 0);
			if (waitPid == -1)
			{
				string errorMessage = string("waitpid failed");
				returnedStatus = -1;

				throw runtime_error(errorMessage);
			}
			else if (waitPid == 0)
			{
				// child still running
			}
			else // if (waitPid == childPid)
			{
				// child ended

				childTerminated = true;

				if (WIFEXITED(wstatus))
				{
					// Child ended normally
					returnedStatus = WEXITSTATUS(wstatus);
				}
				else if (WIFSIGNALED(wstatus))
				{
					string errorMessage =
						string("Child has exit abnormally because of an uncaught signal. Terminating signal: ") + to_string(WTERMSIG(wstatus));
					returnedStatus = WTERMSIG(wstatus);

					throw runtime_error(errorMessage);
				}
				else if (WIFSTOPPED(wstatus))
				{
					string errorMessage = string("Child has stopped. Stop signal: ") + to_string(WSTOPSIG(wstatus));
					returnedStatus = WSTOPSIG(wstatus);

					throw runtime_error(errorMessage);
				}
			}
		}
	}
	else
	{
		vector<char *> commandVector;
		for (int paramIndex = 0; paramIndex < argList.size(); paramIndex++)
			commandVector.push_back(const_cast<char *>(argList[paramIndex].c_str()));
		commandVector.push_back(NULL);

		if (redirectionPathName != "" && (redirectionStdOutput || redirectionStdError))
		{
			int fd = open(redirectionPathName.c_str(), O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (fd == -1)
			{
				string errorMessage = string("Redirection file Open failed: ") + redirectionPathName;

				throw runtime_error(errorMessage);
			}

			// redirect out, copy the file descriptor fd into standard output/error
			if (redirectionStdOutput)
			{
				close(STDOUT_FILENO);
				dup2(fd, STDOUT_FILENO);
			}
			if (redirectionStdError)
			{
				close(STDERR_FILENO);
				dup2(fd, STDERR_FILENO);
			}

			// close (fd); // close the file descriptor as we don't need it more
		}

		// child process: execute the command
		execv(programPath.c_str(), &commandVector[0]);
		// execv(programPath.c_str(),  argListParam);

		// The execv  function returns only if an error occurs.
		string errorMessage = string("An error occurred in execv. errno: ") + to_string(errno);

		throw runtime_error(errorMessage);
	}
#endif
}

int ProcessUtility::execute(string command)
{
	int returnedStatus;
	int iLocalStatus;

	if ((iLocalStatus = system(command.c_str())) == -1)
		throw runtime_error("system failed");

#ifdef WIN32
	*returnedStatus = iLocalStatus;
#else
	if (!WIFEXITED(iLocalStatus))
		throw runtime_error(std::format(
			"system failed"
			"iLocalStatus: {}",
			iLocalStatus
		));

	returnedStatus = WEXITSTATUS(iLocalStatus);
#endif

	return returnedStatus;
}

void ProcessUtility::killProcess(ProcessId processId)
{
	if (!processId.isInitialized())
	{
		string errorMessage = std::format("processId is wrong. processId: {}", processId.toString());

		throw runtime_error(errorMessage);
	}
#ifdef _WIN32
	TerminateProcess(processId.processHandle, 1);
#else
	if (kill(processId.pid, SIGKILL) == -1)
	{
		string errorMessage = std::format("kill failed. errno: {}", errno);

		throw runtime_error(errorMessage);
	}
#endif
}

#ifdef _WIN32
#else
void ProcessUtility::termProcess(ProcessId processId)
{
	if (processId.pid <= 0)
	{
		string errorMessage = std::format("pid is wrong. pid: {}", processId.pid);

		throw runtime_error(errorMessage);
	}

	if (kill(processId.pid, SIGTERM) == -1)
	{
		string errorMessage = std::format("kill failed. errno: {}", errno);

		throw runtime_error(errorMessage);
	}
}
#endif

#ifdef _WIN32
#else
void ProcessUtility::quitProcess(ProcessId processId)
{
	if (processId.pid <= 0)
	{
		string errorMessage = std::format("pid is wrong. pid: {}", processId.pid);

		throw runtime_error(errorMessage);
	}

	if (kill(processId.pid, SIGQUIT) == -1)
	{
		string errorMessage = std::format("quit failed. errno: {}", errno);

		throw runtime_error(errorMessage);
	}
}
#endif

#ifdef _WIN32
#else
void ProcessUtility::launchUnixDaemon(string pidFilePathName)
{
	/* Our process ID and Session ID */
	pid_t pid, sid;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* If we got a good PID, then
		we can exit the parent process. */
	if (pid > 0)
	{
		exit(EXIT_SUCCESS);
	}

	/*
		In order to write to any files (including logs) created
		by the daemon, the file mode mask (umask) must be changed
		to ensure that they can be written to or read from properly.
		umask default value: 0x022
	*/
	umask(0x002);

	/*
		From here, the child process must get a unique SID from the kernel
		in order to operate. Otherwise, the child process becomes
		an orphan in the system.
	*/
	sid = setsid();
	if (sid < 0)
	{
		/* Log the failure */

		exit(EXIT_FAILURE);
	}

	/*
		The current working directory should be changed to some place
		that is guaranteed to always be there.
	*/
	if ((chdir("/")) < 0)
	{
		/* Log the failure */

		exit(EXIT_FAILURE);
	}

	/* Close out the standard file descriptors */
	/*
		Since a daemon cannot use the terminal, it is better to close
		the standard file descriptors (STDIN, STDOUT, STDERR) that
		are redundant and potential security hazard.
	*/
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	// close (STDERR_FILENO);

	{
		long processIdentifier = ProcessUtility::getCurrentProcessIdentifier();

		ofstream of(pidFilePathName.c_str(), ofstream::trunc);
		of << processIdentifier;
	}
}
#endif

long ProcessUtility::getCurrentProcessIdentifier()
{
#ifdef WIN32
	return _getpid();
#else
	return getpid();
#endif
}

/*
Error ProcessUtility::getCurrentProcessIdentifier(long *plProcessIdentifier)

{

	if (plProcessIdentifier == (long *)NULL)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_ACTIVATION_WRONG);

		return err;
	}

#ifdef WIN32
	*plProcessIdentifier = _getpid();
#else
	*plProcessIdentifier = getpid();
#endif

	return errNoError;
}

#ifdef WIN32
#else
Error ProcessUtility::setUserAndGroupID(const char *pUserName)

{

	char *pUserNameToSearch;
	Buffer_t bPasswdFile;
	StringTokenizer_t stPasswdTokenizer;
	StringTokenizer_t stUserNameTokenizer;
	Error errRead;
	Error errNextToken;
	const char *pToken;
	unsigned long ulUserNameLength;
	uid_t uUserID;
	gid_t gGroupID;
	Boolean_t bUserNameFound;

	if (pUserName == (const char *)NULL)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_ACTIVATION_WRONG);

		return err;
	}

	if (bPasswdFile.init() != errNoError)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_INIT_FAILED);

		return err;
	}

	if ((errRead = bPasswdFile.readBufferFromFile("/etc/passwd")) != errNoError)
	{
		// Error err = ToolsErrors (__FILE__, __LINE__,
		// 	TOOLS_BUFFER_READBUFFERFROMFILE_FAILED);

		if (bPasswdFile.finish() != errNoError)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
		}

		return errRead;
	}

	if (stPasswdTokenizer.init((const char *)bPasswdFile, -1, "\n") != errNoError)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_INIT_FAILED);

		if (bPasswdFile.finish() != errNoError)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
		}

		return err;
	}

	ulUserNameLength = strlen(pUserName);

	if ((pUserNameToSearch = new char[ulUserNameLength + 1 + 1]) == (char *)NULL)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_NEW_FAILED);

		if (stPasswdTokenizer.finish() != errNoError)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
		}

		if (bPasswdFile.finish() != errNoError)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
		}

		return err;
	}

	strcpy(pUserNameToSearch, pUserName);
	strcat(pUserNameToSearch, ":");

	uUserID = 0;
	gGroupID = 0;
	bUserNameFound = false;

	do
	{
		if ((errNextToken = stPasswdTokenizer.nextToken(&pToken)) != errNoError)
		{
			if ((long)errNextToken == TOOLS_STRINGTOKENIZER_NOMORETOKEN)
				continue;
			else
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_NEXTTOKEN_FAILED);

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}
		}

		if (strlen(pToken) < ulUserNameLength + 1)
			continue;

		if (!strncmp(pToken, pUserNameToSearch, ulUserNameLength + 1))
		{
			if (stUserNameTokenizer.init(pToken, -1, ":") != errNoError)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_INIT_FAILED);

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}

			// user name
			if (stUserNameTokenizer.nextToken(&pToken) != errNoError)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_NEXTTOKEN_FAILED);

				if (stUserNameTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}

			// ???
			if (stUserNameTokenizer.nextToken(&pToken) != errNoError)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_NEXTTOKEN_FAILED);

				if (stUserNameTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}

			// user ID
			if (stUserNameTokenizer.nextToken(&pToken) != errNoError)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_NEXTTOKEN_FAILED);

				if (stUserNameTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}

			uUserID = atol(pToken);

			// group ID
			if (stUserNameTokenizer.nextToken(&pToken) != errNoError)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_NEXTTOKEN_FAILED);

				if (stUserNameTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}

			gGroupID = atol(pToken);

			if (stUserNameTokenizer.finish() != errNoError)
			{
				Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);

				delete[] pUserNameToSearch;

				if (stPasswdTokenizer.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);
				}

				if (bPasswdFile.finish() != errNoError)
				{
					Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
				}

				return err;
			}

			bUserNameFound = true;

			break;
		}
	} while (errNextToken == errNoError);

	delete[] pUserNameToSearch;

	if (stPasswdTokenizer.finish() != errNoError)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_STRINGTOKENIZER_FINISH_FAILED);

		if (bPasswdFile.finish() != errNoError)
		{
			Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);
		}

		return err;
	}

	if (bPasswdFile.finish() != errNoError)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_BUFFER_FINISH_FAILED);

		return err;
	}

	if (!bUserNameFound)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_PROCESSUTILITY_USERNAMENOTFOUND, 1, pUserName);

		return err;
	}

	// it is important the order, first setgid and after setuid
	if (setgid(gGroupID) == -1)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_SETGID_FAILED, 2, errno, (long)gGroupID);

		return err;
	}

	if (setuid(uUserID) == -1)
	{
		Error err = ToolsErrors(__FILE__, __LINE__, TOOLS_SETUID_FAILED, 2, errno, (long)uUserID);

		return err;
	}

	return errNoError;
}
#endif
*/

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
#ifdef _WIN32
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

void ProcessUtility::forkAndExec(
	const std::string& programPath,
	// first string is the program name, than we have the params
	std::vector<std::string> &argList, const std::string& redirectionPathName, bool redirectionStdOutput, bool redirectionStdError, ProcessId &processId,
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
				throw std::runtime_error("Unable to open log file: " + redirectionPathName);
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

		std::string command;
		{
			command = programPath + " ";

			for (int paramIndex = 1; paramIndex < argList.size(); paramIndex++)
				command += (argList[paramIndex] + " ");
		}

		// LOG_INFO("windows command: {}", command);
		DWORD creationFlags = CREATE_NO_WINDOW;
		if (!CreateProcessA(
				NULL, command.data(), NULL, NULL, redirectOnFile ? TRUE /* ereditare gli handle */ : FALSE, creationFlags, NULL, NULL, &si, &pi
			))
			throw std::runtime_error("Failed to launch process: " + command);

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
	catch (const std::exception &ex)
	{
		// Cleanup anche in caso di errore
		if (hThread != NULL)
			CloseHandle(hThread);
		if (processId.processHandle != NULL)
			CloseHandle(processId.processHandle);
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);

		throw std::runtime_error(std::format("Exception: {}", ex.what()));
	}
#else
	// Duplicate this process.
	const pid_t childPid = fork();
	if (childPid == -1)
	{
		// fork failed
		const std::string errorMessage = std::format("Fork failed. errno: {}", errno);
		LOG_ERROR(errorMessage);

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
				std::string errorMessage = "waitpid failed";
				returnedStatus = -1;

				throw std::runtime_error(errorMessage);
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
					std::string errorMessage =
						std::format("Child has exit abnormally because of an uncaught signal. Terminating signal: {}", WTERMSIG(wstatus));
					returnedStatus = WTERMSIG(wstatus);

					throw std::runtime_error(errorMessage);
				}
				else if (WIFSTOPPED(wstatus))
				{
					std::string errorMessage = std::format("Child has stopped. Stop signal: {}", WSTOPSIG(wstatus));
					returnedStatus = WSTOPSIG(wstatus);

					throw std::runtime_error(errorMessage);
				}
			}
		}
	}
	else
	{
		std::vector<char *> commandVector;
		commandVector.reserve(argList.size() + 1);
		for (int paramIndex = 0; paramIndex < argList.size(); paramIndex++)
			commandVector.push_back(const_cast<char *>(argList[paramIndex].c_str()));
		commandVector.push_back(NULL);

		if (!redirectionPathName.empty() && (redirectionStdOutput || redirectionStdError))
		{
			int fd = open(redirectionPathName.c_str(), O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if (fd == -1)
			{
				std::string errorMessage = std::format("Redirection file Open failed: {}", redirectionPathName);

				throw std::runtime_error(errorMessage);
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
		std::string errorMessage = std::format("An error occurred in execv. errno: {}", errno);

		throw std::runtime_error(errorMessage);
	}
#endif
}

#ifdef _WIN32

// Quota un token secondo regole di Windows per CreateProcess,
// compatibile con la CRT (escape di backslash prima di un doppio apice).
static std::string quoteArgWindows(const std::string& arg) {
	bool needQuotes = arg.empty() || arg.find_first_of(" \t\"") != std::string::npos;
	if (!needQuotes) return arg;

	std::string out;
	out.push_back('"');
	size_t bsCount = 0;
	for (char c : arg) {
		if (c == '\\') {
			++bsCount;
		} else if (c == '"') {
			// Escape: raddoppia i backslash e poi escape quote
			out.append(bsCount * 2, '\\');
			bsCount = 0;
			out.append("\\\"");
		} else {
			if (bsCount) {
				out.append(bsCount, '\\');
				bsCount = 0;
			}
			out.push_back(c);
		}
	}
	// Backslash finali prima della chiusura di quote vanno raddoppiati
	if (bsCount) out.append(bsCount * 2, '\\');
	out.push_back('"');
	return out;
}

// Costruisce la command line: primo token = programma (quotato),
// poi tutti gli argomenti quotati (saltando argList[0] se è il nome programma).
static std::string buildWindowsCommandLine(const std::string& programPath,
										   const std::vector<std::string>& argList) {
	std::string cmd = quoteArgWindows(programPath);
	// Se argList[0] è il "nome programma", saltiamolo per non duplicarlo
	for (size_t i = 1; i < argList.size(); ++i) {
		cmd.push_back(' ');
		cmd += quoteArgWindows(argList[i]);
	}
	return cmd;
}
#endif

void ProcessUtility::forkAndExecByCallback(
	const std::string& programPath,
	// first string is the program name, than we have the params
	const std::vector<std::string> &argList, const LineCallback& lineCallback, bool redirectionStdOutput, bool redirectionStdError, ProcessId &processId,
	int &returnedStatus
)
{
#ifdef _WIN32

    HANDLE stdoutRead = NULL, stdoutWrite = NULL;
    HANDLE stderrRead = NULL, stderrWrite = NULL;
    HANDLE childProcess = NULL;
    HANDLE childThread = NULL;

    try {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE; // pipe con handle ereditabili (poi rimuoviamo l'ereditarietà dove serve)

        if (redirectionStdOutput) {
            if (!CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0))
                throw std::runtime_error("CreatePipe stdout failed");
            // Il figlio NON deve ereditare l'estremo di lettura
            SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
        }
        if (redirectionStdError) {
            if (!CreatePipe(&stderrRead, &stderrWrite, &sa, 0))
                throw std::runtime_error("CreatePipe stderr failed");
            SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);
        }

        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;

        si.hStdOutput = redirectionStdOutput ? stdoutWrite : GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = redirectionStdError ? stderrWrite : GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};

        // Command line correttamente quotata e NUL-terminata
        std::string cmd = buildWindowsCommandLine(programPath, argList);
        std::vector<char> cmdBuf(cmd.begin(), cmd.end());
        cmdBuf.push_back('\0'); // LPSTR deve essere mutabile e NUL-terminato

        if (!CreateProcessA(
                /*lpApplicationName*/ nullptr,
                /*lpCommandLine*/    cmdBuf.data(), // primo token = exe quotato
                /*lpProcessAttributes*/ nullptr,
                /*lpThreadAttributes*/  nullptr,
                /*bInheritHandles*/     TRUE,
                /*dwCreationFlags*/     CREATE_NO_WINDOW,
                /*lpEnvironment*/       nullptr,
                /*lpCurrentDirectory*/  nullptr,
                /*lpStartupInfo*/       &si,
                /*lpProcessInformation*/&pi))
        {
            throw std::runtime_error("CreateProcessA failed: " + cmd);
        }

        childProcess = pi.hProcess;
        childThread  = pi.hThread;
    	processId.processHandle = childProcess;

        // Nel padre: chiudi gli estremi di scrittura (il figlio li usa)
        if (stdoutWrite) { CloseHandle(stdoutWrite); stdoutWrite = NULL; }
        if (stderrWrite) { CloseHandle(stderrWrite); stderrWrite = NULL; }

        // Thread di lettura stdout
        std::thread stdoutThread([&] {
            if (!redirectionStdOutput) return;

            std::string buffer;
            buffer.reserve(4096);
            char chunk[2048];
            DWORD nRead = 0;

            while (ReadFile(stdoutRead, chunk, sizeof(chunk), &nRead, nullptr) && nRead > 0) {
                buffer.append(chunk, chunk + nRead);
                // Emissione per righe: gestisci CRLF
                size_t start = 0;
                while (true) {
                    size_t pos = buffer.find('\n', start);
                    if (pos == std::string::npos) break;
                    size_t end = (pos > 0 && buffer[pos - 1] == '\r') ? (pos - 1) : pos;
                    std::string_view line(buffer.data() + start, end - start);
			    	if (lineCallback)
				        lineCallback(line);
                    start = pos + 1;
                }
                if (start > 0) buffer.erase(0, start);
            }

            // Flush dell’ultima porzione (senza newline)
            if (!buffer.empty() && lineCallback) {
                lineCallback(std::string_view(buffer));
                buffer.clear();
            }
        });

        // Thread di lettura stderr
        std::thread stderrThread([&] {
            if (!redirectionStdError) return;

            std::string buffer;
            buffer.reserve(4096);
            char chunk[2048];
            DWORD nRead = 0;

            while (ReadFile(stderrRead, chunk, sizeof(chunk), &nRead, nullptr) && nRead > 0) {
                buffer.append(chunk, chunk + nRead);
                size_t start = 0;
                while (true) {
                    size_t pos = buffer.find('\n', start);
                    if (pos == std::string::npos) break;
                    size_t end = (pos > 0 && buffer[pos - 1] == '\r') ? (pos - 1) : pos;
                    std::string_view line(buffer.data() + start, end - start);
                    // Prefissa per distinguere stderr con un unico callback
                    // std::string prefixed;
                    // prefixed.reserve(line.size() + 9);
                    // prefixed += "[stderr] ";
                    // prefixed.append(line.data(), line.size());
			    	if (lineCallback)
	                    lineCallback(line); // std::string_view(prefixed));
                    start = pos + 1;
                }
                if (start > 0) buffer.erase(0, start);
            }

            if (!buffer.empty() && lineCallback) {
                // std::string prefixed;
                // prefixed.reserve(buffer.size() + 9);
                // prefixed += "[stderr] ";
                // prefixed += buffer;
                lineCallback(std::string_view(buffer)); // std::string_view(prefixed));
                buffer.clear();
            }
        });

        // Attendi i reader
        stdoutThread.join();
        stderrThread.join();

        // Attendi il processo figlio e ottieni l'exit code
        WaitForSingleObject(childProcess, INFINITE);
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(childProcess, &exitCode)) {
            exitCode = static_cast<DWORD>(-1);
        }
        returnedStatus = static_cast<int>(exitCode);

    	// send empty line to signal end of output
    	if (lineCallback)
    		lineCallback("");

    	// Chiudi gli estremi di lettura
        if (stdoutRead) { CloseHandle(stdoutRead); stdoutRead = NULL; }
        if (stderrRead) { CloseHandle(stderrRead); stderrRead = NULL; }
        if (childThread) { CloseHandle(childThread); childThread = NULL; }
        if (childProcess) { CloseHandle(childProcess); childProcess = NULL; }
    }
    catch (const std::exception& ex) {
        if (stdoutRead) CloseHandle(stdoutRead);
        if (stderrRead) CloseHandle(stderrRead);
        if (stdoutWrite) CloseHandle(stdoutWrite);
        if (stderrWrite) CloseHandle(stderrWrite);
        if (childThread) CloseHandle(childThread);
        if (childProcess) CloseHandle(childProcess);
        throw std::runtime_error(std::string("Exception: ") + ex.what());
    }
#else
	// a pipe is a connection between two processes, such that the standard output from one process
	// becomes the standard input of the other process
	int pipefd[2];
	// il flag FD_CLOEXEC indica che eventuali subprocess NON ereditano la pipe
	// It sets the close-on-exec flag for the file descriptor, which causes the file descriptor to be automatically (and atomically)
	// closed when any of the exec-family functions succeed
#ifdef __linux__
	if (pipe2(pipefd, O_CLOEXEC) == -1)
#else
	if (pipe(pipefd) == -1)
#endif
	{
		const std::string errorMessage = std::format("pipe failed. errno: {}", errno);
		LOG_ERROR(errorMessage);
		throw std::runtime_error(errorMessage);
	}

#ifdef __linux__
#else
	fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
	fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
#endif

	// Duplicate this process.
	const pid_t childPid = fork();
	if (childPid == -1)
	{
		close(pipefd[0]);
		close(pipefd[1]);

		const std::string errorMessage = std::format("Fork failed. errno: {}", errno);
		LOG_ERROR(errorMessage);
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

		// close write end of the pipe
		close(pipefd[1]);

		processId.pid = childPid;

		// reader loop
		{
	        char buf[4096];
			std::string buffer;
	        while (true)
	        {
	        	// read() termina solo quando:
	        	//	- riceve EOF → tutte le write-end della pipe sono chiuse
	        	//	- oppure riceve dati
				// Se per QUALSIASI motivo:
				//  - il processo figlio termina
				//  - ma qualche file descriptor verso pipefd[1] rimane aperto
	        	// allora:
	        	// - read() non riceve mai EOF
	        	// - rimane bloccato
	        	// - non si esce mai dal loop
	        	// Questo puo accadere se ad es:
	        	// - il processo figlio crea processi figli che ereditano la pipe e non la chiudono
	        	// - il processo figlio crea thread che ereditano la pipe e non la chiudono
	        	// - il processo figlio non chiude la pipe dopo execv
	        	// Per questo motivo sopra ho settato il flag FD_CLOEXEC sulla pipe, in modo che eventuali subprocess non ereditino la pipe
	        	// e non possano rimanere con file descriptor aperti verso pipefd[1]

	            ssize_t bytesRead = ::read(pipefd[0], buf, sizeof(buf));
				if (bytesRead > 0)
	            {
	            	buffer.append(buf, bytesRead);

	            	// extract all complete lines
	            	size_t pos;
	            	while ((pos = buffer.find('\n')) != std::string::npos)
	            	{
	            		std::string line = buffer.substr(0, pos);
	            		buffer.erase(0, pos + 1);

	            		if (lineCallback)
	            			lineCallback(line);
	            	}
	            }
				else if (bytesRead == 0) // reading end-of-file
	                break;
				else // -1 is returned and the global variable errno is set to indicate the error
	            {
	                if (errno == EINTR) // A read from a slow device was interrupted before any data arrived by the delivery of a signal
	                	continue;
	                break;
	            }
	        }
			// leftover partial line
			if (!buffer.empty() && lineCallback)
				lineCallback(buffer);
		}
		// send empty line to signal end of output
		if (lineCallback)
			lineCallback("");

		close(pipefd[0]);

		// se siamo qui abbiamo ricevuto EOF nella pipe, questo significa che il processo figlio ha chiuso la write-end della pipe,
		// quindi è terminato (cmq aspettiamo la terminazione con waitpid per sicurezza e per ottenere il codice di uscita)
		int wstatus;
		if (waitpid(childPid, &wstatus, 0) == -1)
		{
			returnedStatus = -1;

			const std::string errorMessage = std::format("waitpid failed. errno: {}", errno);
			LOG_ERROR(errorMessage);
			throw std::runtime_error(errorMessage);
		}
		if (WIFEXITED(wstatus))
		{
			// Child ended normally
			returnedStatus = WEXITSTATUS(wstatus);
		}
		else if (WIFSIGNALED(wstatus))
		{
			returnedStatus = WTERMSIG(wstatus);

			const std::string errorMessage = std::format("Child has exit abnormally because of an uncaught signal. Terminating signal: {}", WTERMSIG(wstatus));
			LOG_ERROR(errorMessage);
			throw std::runtime_error(errorMessage);
		}
		else if (WIFSTOPPED(wstatus))
		{
			returnedStatus = WSTOPSIG(wstatus);

			const std::string errorMessage = std::format("Child has stopped. Stop signal: {}", WSTOPSIG(wstatus));
			LOG_ERROR(errorMessage);
			throw std::runtime_error(errorMessage);
		}
	}
	else
	{
		// processo figlio

		std::vector<char *> commandVector;
		commandVector.reserve(argList.size() + 1);
		for (const auto & arg : argList)
			commandVector.push_back(const_cast<char *>(arg.c_str()));
		commandVector.push_back(nullptr);

		if (redirectionStdOutput || redirectionStdError)
		{
			// redirect stdout and stderr to pipefd[1]
			// dopo la chiamata dup2, STDOUT_FILENO/STDERR_FILENO punta a pipefd[1]
			// Tutto ciò che il processo figlio scriverà su stdout/stderr finirà nella pipe creata prima della fork
			if (redirectionStdOutput)
				dup2(pipefd[1], STDOUT_FILENO);
			if (redirectionStdError)
				dup2(pipefd[1], STDERR_FILENO);
			// al processo figlio non serve la pipe
			close(pipefd[0]);
			close(pipefd[1]);
		}

		// child process: execute the command
		execv(programPath.c_str(), &commandVector[0]);
		// execv(programPath.c_str(),  argListParam);

		// The execv function returns only if an error occurs.
		// Dopo fork in un processo multi-thread, NON è safe usare logger, Nel child dovresti fare SOLO funzioni async-signal-safe
		// const std::string errorMessage = std::format("execv failed. errno: {}", errno);
		// LOG_ERROR(errorMessage);
		// perror scrive su stderr, poichè abbiamo rediretto, perror() finisce nella pipe, viene letto nel parent, passa nel lineCallback
		perror("execv failed");
		// ritroveremmo 255 ritornato da WEXITSTATUS in caso di execv fallito, così da distinguere un execv fallito da un processo
		// che ritorna 255 come exit code
		exit(255);
	}
#endif
}

int ProcessUtility::execute(const std::string& command)
{
	int returnedStatus;
	int iLocalStatus;

	if ((iLocalStatus = system(command.c_str())) == -1)
		throw std::runtime_error("system failed");

#ifdef WIN32
	returnedStatus = iLocalStatus;
#else
	if (!WIFEXITED(iLocalStatus))
		throw std::runtime_error(std::format(
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
		throw std::runtime_error(std::format("processId is wrong. processId: {}", processId.toString()));
#ifdef _WIN32
	TerminateProcess(processId.processHandle, 1);
#else
	if (kill(processId.pid, SIGKILL) == -1)
		throw std::runtime_error(std::format("kill failed. errno: {}", errno));
#endif
}

#ifdef _WIN32
#else
void ProcessUtility::termProcess(ProcessId processId)
{
	if (processId.pid <= 0)
		throw std::runtime_error(std::format("pid is wrong. pid: {}", processId.pid));

	if (kill(processId.pid, SIGTERM) == -1)
		throw std::runtime_error(std::format("kill failed. errno: {}", errno));
}
#endif

#ifdef _WIN32
#else
void ProcessUtility::quitProcess(ProcessId processId)
{
	if (processId.pid <= 0)
		throw std::runtime_error(std::format("pid is wrong. pid: {}", processId.pid));

	if (kill(processId.pid, SIGQUIT) == -1)
		throw std::runtime_error(std::format("quit failed. errno: {}", errno));
}
#endif

#ifdef _WIN32
#else
void ProcessUtility::launchUnixDaemon(std::string pidFilePathName)
{
	/* Our process ID and Session ID */
	pid_t pid, sid;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);

	/* If we got a good PID, then
		we can exit the parent process. */
	if (pid > 0)
		exit(EXIT_SUCCESS);

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
		exit(EXIT_FAILURE);

	/*
		The current working directory should be changed to some place
		that is guaranteed to always be there.
	*/
	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);

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
		const long processIdentifier = ProcessUtility::getCurrentProcessIdentifier();

		std::ofstream of(pidFilePathName.c_str(), std::ofstream::trunc);
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

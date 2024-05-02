#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD getPID(WCHAR *nameProcess)
{
	/*
	* https://learn.microsoft.com/ru-ru/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
	* https://learn.microsoft.com/ru-ru/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	*/

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, nameProcess) == 0)
            {
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return NULL;
}

DWORD getAddress(WCHAR* moduleName, DWORD PID)
{
    MODULEENTRY32 moduleEntry = { 0 };
    moduleEntry.dwSize = sizeof(moduleEntry);

    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);

    if (!hSnapShot)
    {
        return NULL;
    }
       
    BOOL bModule = Module32First(hSnapShot, &moduleEntry);
    while (bModule)
    {
        if (!wcscmp(moduleEntry.szModule, moduleName))
        {
            CloseHandle(hSnapShot);
            return (DWORD)moduleEntry.modBaseAddr;
        }
        bModule = Module32Next(hSnapShot, &moduleEntry);
    }
    CloseHandle(hSnapShot);
    return NULL;
}

int main()
{
    /*
    * 
    */
    DWORD PID = NULL;
    DWORD baseAddress = NULL;
    WCHAR* nameProcess = L"codeInjection1.exe";
    HANDLE handler;

    PID = getPID(nameProcess);
    if (PID == NULL)
    {
        printf("Process does not exist\n");
        system("pause");
        return -1;
    }
    printf("PID: %d\n", PID);
    system("pause");

    if (!(handler = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID)))
    {
        printf("OpenProcess error\n");
        return -1;
    }

    if (!(baseAddress = getAddress(nameProcess, PID)))
    {
        printf("Error\n");
        return -1;
    }
    printf("BaseAddress: %x\n\n", baseAddress);

    DWORD realBuffer = baseAddress + 0x17B34; //x86
    DWORD realFuncPrintMessage = baseAddress +0x118F0; //x86

    char localBuffer[16];
    ReadProcessMemory(handler, (void*)realBuffer, &localBuffer, 16, 0);
    printf("Buffer: %s\n\n", localBuffer);

    HANDLE hProcThread;
    DWORD pInjectedFunction = (DWORD)VirtualAllocEx(handler, NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    if (pInjectedFunction == 0)
    {
        printf("Error\n");
        return -1;
    }

    DWORD local_a = pInjectedFunction + 17;
    DWORD local_b = realFuncPrintMessage;
    char shellcode[128];

    while (1)
    {
        printf("ss\n");
        strcpy_s(shellcode, 128, "\xBF");
        strcat_s(shellcode, 128,  "XXXX");
        strcat_s(shellcode, 128, "\xBB");
        strcat_s(shellcode, 128, "YYYY");
        strcat_s(shellcode, 128, "\x57\xFF\xD3\x83\xC4\x04\xC3");
      
        printf("Your text: ");
        fgets(localBuffer, sizeof(localBuffer), stdin);
        strcat_s(shellcode, 128, localBuffer);
        memcpy(shellcode + 1, &local_a, 4);
        memcpy(shellcode + 6, &local_b, 4);
        WriteProcessMemory(handler, (LPVOID)pInjectedFunction, shellcode, 128, 0);
        hProcThread = CreateRemoteThread(handler, NULL, NULL, (LPTHREAD_START_ROUTINE)pInjectedFunction, NULL, NULL, NULL);
    }

    return 0;
}
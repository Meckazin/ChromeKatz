# ChromeKatz

ChromeKatz is a solution for dumping sensitive information from memory of Chromium based browsers.
As for now, ChromeKatz consists of two projects:
 1. CookieKatz - The cookie dumper
 2. CredentialKatz - The password dumper

Both tools have an exe, Beacon Object File, and minidump parser available.

CookieKatz has been completely revamped to use much more robust method for finding the cookies! New method supports older browser version as well.

Google doesn't want to pay bounties and my cats are hungry. But you can support us via Ko-Fi!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/E1E716M78J)

## CredentialKatz - Dump credential manager contents from memory

CredentialKatz is a project that allows operators to dump all credentials from Credential Manager of Chrome and Edge.
Most of the time Chromium based browsers keep your passwords in the credential manager encrypted until they are needed, either viewed in the credential manager, or auto filled to a login form. But for whatever reason, `passwords_with_matching_reused_credentials_` of `PasswordReuseDetectorImpl` class is populated with all credentials from the credential manager, in **plain text**. This will include all credentials that you have added to the password manager locally. If you have logged in the browser with your account, this will also include all the passwords you have ever synced with that account. 

There are few perks in accessing credentials in this way.:
 1. Dump credentials of other user's browsers when running elevated
 2. DPAPI keys not needed to decrypt the credentials
 3. No need to touch on-disk database file
 4. Parse credential manager offline from a minidump file

This solution consists of three projects, **CredentialKatz** that is a PE executable, **CredentialKatz-BOF** the Beacon Object File version and **CredentialKatzMinidump** which is the minidump parser.

## Usage

NOTE! When choosing using PID to target, use commands /list or cookie-katz-find respectively to choose the right subprocess!

### CredentialKatz

```text
Examples:
.\CredentialKatz.exe
    By default targets first available Chrome process
.\CredentialKatz.exe /edge
    Targets first available Edge process
.\CredentialKatz.exe /pid:<pid>
    Attempts to target given pid, expecting it to be Chrome
.\CredentialKatz.exe /edge /pid:<pid>
    Target the specified Edge process

Flags:
    /edge       Target current user Edge process
    /pid        Attempt to dump given pid, for example, someone else's if running elevated
    /list       List targettable processes, use with /edge to list Edge processes
    /help       This what you just did! -h works as well
```

### CredentialKatz-BOF

```text
beacon> help credential-katz
Dump credential manager from Chrome or Edge
Use: credential-katz [chrome|edge] [pid]

beacon> help cookie-katz-find
Find processes for credential-katz
Use: credential-katz-find [chrome|edge]
```

### CredentialKatzMinidump

```text
Usage:
    CredentialKatzMinidump.exe <Path_to_minidump_file>

Example:
    .\CredentialKatzMinidump.exe .\msedge.DMP

You need to dump the Chrome/Edge main process. Hint: It is the one with the smallest PID
```

## CookieKatz - Dump cookies directly from memory

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
- [B3arr0](https://github.com/B3arr0) for testing the BOF version and helping to squash the bugs
- [TheWover](https://github.com/TheWover) for excellent PEB definitions!
- [0vercl0k](https://github.com/0vercl0k) for creating udmp-parser which is the core library for minidump parsing

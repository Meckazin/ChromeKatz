# Cookie dumper for Chrome and Edge

CookieKatz is a project that allows operators to dump cookies from Chrome or Edge directly from the process memory.
Chromium based browsers load all their cookies from the on-disk cookie database on startup. This allows the dumping of the cookies from the browser memory without need to touch the on-disk database.

The benefits of this solution over other tools are:
 - No need to touch on-disk database file
 - DPAPI keys not needed to access the cookies
 - Dump cookies from other user's browsers when running elevated
 - Support dumping from Chrome's Incogntio and Edge's In-Private processes

On the negative side, even as the method of finding the correct offsets in memory currently is stable and works on multiple different Chrome versions, it will definitely break at some point in the future.
32bit browsers are not supported and 32bit builds are not supported either.

This solution consists of two projects, CookieKatz that is a PE executable, and CookieKatz-BOF that is a Beacon Object File version.

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
    Attempts to target given pid (remember to use flag: edge if the target is Edge)

Flags:
    /edge    Target current user Edge process
    /pid     Attempt to dump given pid, for example, someone else's if running elevated
    /list    List targettable processes, use with /edge to target Edge
    /help    This what you just did! -h works as well
```

### CookieKatz-BOF

```text
beacon> help cookie-katz
Dump cookies from Chrome or Edge
Use: cookie-katz [chrome|edge] [pid]

beacon> help cookie-katz-find
Find processes for Cookie-Katz
Use: cookie-katz-find [chrome|edge]
```

## Credits
- [Henkru](https://github.com/Henkru) for fixing the BOF version crashes and creating the CNA script
- [B3arr0](https://github.com/B3arr0) for testing the BOF version and helping to squash the bugs
- [TheWover](https://github.com/TheWover) for excellent PEB definitions!

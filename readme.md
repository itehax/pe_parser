# Pe parser  using rust 

This is a simple [portable executable](https://en.wikipedia.org/wiki/Portable_Executable) parser that I wrote in Rust 🦀 to explain the PE format.

Here is my [post](https://itehax.com/blog/portable-executable-explained-throught-rust-code) on the details of the PE format.

## References
- <https://paper.bobylive.com/Security/Bin_Portable_Executable_File_Format_%E2%80%93_A_Reverse_Engineer_View_2012-1-31_16.43_CBM_1_2_2006_Goppit_PE_Format_Reverse_Engineer_View.pdf>

- <https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++>

- <https://0xrick.github.io/win-internals/pe8/>

- <https://k0deless.github.io/posts/pe-file-format/>

- <https://en.wikipedia.org/wiki/Portable_Executable>

- <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>

- <https://ferreirasc.github.io/PE-Export-Address-Table/>


Main:

```rust
let mut pe = PE::new(file_path);
    if !pe.is_valid() {
        panic!("Invalid pe type")
    }
    pe.dump_dos_header();
   
    pe.seek_magic();
    pe.get_pe_type();

    pe.seek_image_nt_header();
    pe.dump_nt_header();

    pe.dump_sections();

    pe.dump_import();
    pe.dump_export();
```

Output example:

```
Dos Header:
    magic -> 0x5a4d
    address of the pe file header -> 0xf0
Pe 64
Image Nt Headers 64:
    Pe Signature -> 0x4550

File Header:
    Machine -> 0x8664
    section count -> 0x6
    time date stamp -> 0x558104cf
    pointer to simble table -> 0x0
    num of simbles -> 0x0
    size of optional headers -> 0xf0
    characteristics -> 0x2022

Optional Header:
    Magic -> 0x20b
    Major Linker Version -> 0xc
    Minor Linker Version -> 0xa
    Size Of Code -> 0x19a00
    Size Of Initialized Data -> 0x7c00
    Size Of Uninitialized Data -> 0x0
    Address Of Entry Point -> 0x19a80
    Base Of Code -> 0x1000
    Image Base -> 0x180000000
    Section Alignment -> 0x1000
    File Alignment -> 0x200
    Major Operating System Version -> 0xa
    Minor Operating System Version -> 0x0
    Major Image Version -> 0xa
    Minor Image Version -> 0x0
    Major Subsystem Version -> 0x6
    Minor Subsystem Version -> 0x1
    Win32 Version Value -> 0x0
    Size Of Image -> 0x25000
    Size Of Headers -> 0x400
    CheckSum -> 0x2a506
    Subsystem -> 0x3
    Dll Characteristics -> 0x4160
    Number Of RVA And Sizes -> 0x10

Data directory:
    import directory:
        Virtual address -> 0x200e4
        Size -> 0x12c
    export directory:
        Virtual address -> 0x20070
        Size -> 0x71
    resource directory:
        Virtual address -> 0x23000
        Size -> 0x408
    iat:
        Virtual address -> 0x1b000
        Size -> 0x2a8

Sections header:
    .text
        virtual address -> 0x1000
        virtual size -> 0x19980
        pointer to raw data -> 0x400
        size of raw data -> 0x19a00
        characteristics -> 0x60000020

    .rdata
        virtual address -> 0x1b000
        virtual size -> 0x5b1a
        pointer to raw data -> 0x19e00
        size of raw data -> 0x5c00
        characteristics -> 0x40000040

    .data
        virtual address -> 0x21000
        virtual size -> 0x620
        pointer to raw data -> 0x1fa00
        size of raw data -> 0x200
        characteristics -> 0xc0000040

    .pdata
        virtual address -> 0x22000
        virtual size -> 0xd44
        pointer to raw data -> 0x1fc00
        size of raw data -> 0xe00
        characteristics -> 0x40000040

    .rsrc
        virtual address -> 0x23000
        virtual size -> 0x408
        pointer to raw data -> 0x20a00
        size of raw data -> 0x600
        characteristics -> 0x40000040

    .reloc
        virtual address -> 0x24000
        virtual size -> 0x3c0
        pointer to raw data -> 0x21000
        size of raw data -> 0x400
        characteristics -> 0x42000040

Import:
import -> msvcrt.dll
name -> __C_specific_handler
    iat function address -> 0x20580
    function address -> 0x20580
name -> _initterm
    iat function address -> 0x20574
    function address -> 0x20574
name -> _amsg_exit
    iat function address -> 0x20566
    function address -> 0x20566
name -> _XcptFilter
    iat function address -> 0x20558
    function address -> 0x20558
name -> time
    iat function address -> 0x20550
    function address -> 0x20550
name -> _wsplitpath_s
    iat function address -> 0x20540
    function address -> 0x20540
name -> _wcsicmp
    iat function address -> 0x20534
    function address -> 0x20534
name -> wcsstr
    iat function address -> 0x2052a
    function address -> 0x2052a
name -> towlower
    iat function address -> 0x2051e
    function address -> 0x2051e
name -> strstr
    iat function address -> 0x20514
    function address -> 0x20514
name -> _strlwr
    iat function address -> 0x2050a
    function address -> 0x2050a
name -> wcsncpy_s
    iat function address -> 0x204fe
    function address -> 0x204fe
name -> ??3@YAXPEAX@Z
    iat function address -> 0x204ee
    function address -> 0x204ee
name -> free
    iat function address -> 0x204e6
    function address -> 0x204e6
name -> malloc
    iat function address -> 0x204dc
    function address -> 0x204dc
name -> memmove
    iat function address -> 0x204d2
    function address -> 0x204d2
name -> _purecall
    iat function address -> 0x204c6
    function address -> 0x204c6
name -> swprintf_s
    iat function address -> 0x204b8
    function address -> 0x204b8
name -> memcpy
    iat function address -> 0x20b06
    function address -> 0x20b06
name -> memset
    iat function address -> 0x20b10
    function address -> 0x20b10
import -> api-ms-win-core-misc-l1-1-0.dll
name -> Sleep
    iat function address -> 0x205a4
    function address -> 0x205a4
name -> lstrcmpiW
    iat function address -> 0x2060e
    function address -> 0x2060e
import -> api-ms-win-core-sysinfo-l1-1-0.dll
name -> GetSystemTimeAsFileTime
    iat function address -> 0x206e2
    function address -> 0x206e2
name -> GetVersionExW
    iat function address -> 0x20720
    function address -> 0x20720
name -> GetVersionExA
    iat function address -> 0x205ac
    function address -> 0x205ac
name -> GetTickCount
    iat function address -> 0x2091a
    function address -> 0x2091a
name -> GetSystemInfo
    iat function address -> 0x206fc
    function address -> 0x206fc
import -> api-ms-win-core-errorhandling-l1-1-0.dll
name -> GetLastError
    iat function address -> 0x205bc
    function address -> 0x205bc
name -> SetUnhandledExceptionFilter
    iat function address -> 0x208b8
    function address -> 0x208b8
name -> SetLastError
    iat function address -> 0x205ec
    function address -> 0x205ec
name -> UnhandledExceptionFilter
    iat function address -> 0x2089c
    function address -> 0x2089c
import -> api-ms-win-core-libraryloader-l1-1-0.dll
name -> FreeLibrary
    iat function address -> 0x205de
    function address -> 0x205de
name -> GetProcAddress
    iat function address -> 0x205cc
    function address -> 0x205cc
name -> LoadLibraryExA
    iat function address -> 0x2061a
    function address -> 0x2061a
name -> LoadLibraryExW
    iat function address -> 0x205fc
    function address -> 0x205fc
import -> api-ms-win-core-localregistry-l1-1-0.dll
name -> RegQueryValueExA
    iat function address -> 0x2070c
    function address -> 0x2070c
name -> RegQueryValueExW
    iat function address -> 0x2063c
    function address -> 0x2063c
name -> RegOpenKeyExA
    iat function address -> 0x2062c
    function address -> 0x2062c
name -> RegCloseKey
    iat function address -> 0x20650
    function address -> 0x20650
import -> api-ms-win-core-handle-l1-1-0.dll
name -> CloseHandle
    iat function address -> 0x2065e
    function address -> 0x2065e
name -> DuplicateHandle
    iat function address -> 0x206aa
    function address -> 0x206aa
import -> api-ms-win-core-memory-l1-1-0.dll
name -> MapViewOfFile
    iat function address -> 0x206d2
    function address -> 0x206d2
name -> VirtualQueryEx
    iat function address -> 0x207f4
    function address -> 0x207f4
name -> UnmapViewOfFile
    iat function address -> 0x20770
    function address -> 0x20770
name -> VirtualFree
    iat function address -> 0x20688
    function address -> 0x20688
name -> ReadProcessMemory
    iat function address -> 0x207e0
    function address -> 0x207e0
name -> VirtualAlloc
    iat function address -> 0x2066c
    function address -> 0x2066c
import -> api-ms-win-core-file-l1-1-0.dll
name -> GetFileSize
    iat function address -> 0x20762
    function address -> 0x20762
name -> WriteFile
    iat function address -> 0x2067c
    function address -> 0x2067c
name -> CreateFileA
    iat function address -> 0x20754
    function address -> 0x20754
name -> SetFilePointer
    iat function address -> 0x20806
    function address -> 0x20806
name -> CreateFileW
    iat function address -> 0x20730
    function address -> 0x20730
import -> api-ms-win-core-processthreads-l1-1-0.dll
name -> GetCurrentProcess
    iat function address -> 0x20696
    function address -> 0x20696
name -> TerminateProcess
    iat function address -> 0x208d6
    function address -> 0x208d6
name -> ResumeThread
    iat function address -> 0x207a8
    function address -> 0x207a8
name -> GetCurrentProcessId
    iat function address -> 0x20904
    function address -> 0x20904
name -> GetPriorityClass
    iat function address -> 0x207b8
    function address -> 0x207b8
name -> GetThreadPriority
    iat function address -> 0x207cc
    function address -> 0x207cc
name -> SuspendThread
    iat function address -> 0x20798
    function address -> 0x20798
name -> GetCurrentThreadId
    iat function address -> 0x20782
    function address -> 0x20782
import -> api-ms-win-core-string-l1-1-0.dll
name -> MultiByteToWideChar
    iat function address -> 0x206bc
    function address -> 0x206bc
name -> WideCharToMultiByte
    iat function address -> 0x2073e
    function address -> 0x2073e
import -> api-ms-win-core-heap-l1-1-0.dll
name -> HeapAlloc
    iat function address -> 0x20818
    function address -> 0x20818
name -> HeapFree
    iat function address -> 0x20840
    function address -> 0x20840
name -> HeapDestroy
    iat function address -> 0x20824
    function address -> 0x20824
name -> HeapCreate
    iat function address -> 0x2084c
    function address -> 0x2084c
name -> HeapReAlloc
    iat function address -> 0x20832
    function address -> 0x20832
import -> api-ms-win-core-rtlsupport-l1-1-0.dll
name -> RtlLookupFunctionEntry
    iat function address -> 0x2086e
    function address -> 0x2086e
name -> RtlCaptureContext
    iat function address -> 0x2085a
    function address -> 0x2085a
name -> RtlVirtualUnwind
    iat function address -> 0x20888
    function address -> 0x20888
import -> api-ms-win-core-profile-l1-1-0.dll
name -> QueryPerformanceCounter
    iat function address -> 0x208ea
    function address -> 0x208ea
Export:
    name -> MiniDumpReadDumpStream
    address -> 6b60
    name -> MiniDumpWriteDump
    address -> 6870
```


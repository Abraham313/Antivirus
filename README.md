# Antivirus
Some shit i made when i was in my junior year of high school.... I havent touched it since so I thought Id release it since it has no use for me anymore...

The UI is sorta unfinished.  The pipe communication between the service and EXE is not complete. The left tab on the UI needs to be adjusted. The scan and certain features need to be styled. 

The UI is made in QT. (i am not the best or the worst in C++, just saying ;\. I'm more used to C). At first I did a basic sha256 check (so the code is still there) just to test my table output...

The input/output from the serivce needs to be completed. This project will only scan files and detect malicious ones depending on sig avaliable. It will not remove anything.... this also needs to be finished.


The main driver which protects the process does the following callbacks, all of which are monitored to see if they are unregistered or anything along this line:.

ObRegisterCalbacks() will strip access handle rights. Prevent aid in the prevntion of termination of our process and other access rights such as duplicating handle. Duplicating handle can lead to serious issues ;). It strips the basics.

PsSetCreateProcessNotifyRoutine(), PsSetCreateThreadNotifyRoutine() self explantory. information is sent to usermode.
PsSetLoadImageNotifyRoutine(), almost the same procedure as the procesnotifyroutine. have code for x64 and x86 platofmrs to use APC's to inject my usermode DLL in, it interacts with the service via pipe.

IRP_MJ_DEVICE_CONTROL IOCTL's:
1. ANTIVIRUS_TERMINATE_PROCESS 
will terminate process.
2. ANTIVIRUS_UNLOAD_DRIVER
will unload a driver. (will not unload one of its own drivers).
3. ANTIVIRUS_CONFIG
will send config data to the driver.


The registry driver which protects the registry keys and informs usermode of any changes does the following:

IRP_MJ_READ:
Upon calling ReadFile() on the driver device the user will recieve the following data:
1. registry path
2. the subkey if present
3. action to preform (like open, enum etc etc)
4. ObjectID
5. BOOLEAN to decide whether to Block the action?


IRP_MJ_WRITE:
1. Will recieve the ObjectID of the registry function
2. Will recieve the action to preform on the registry key.

IRP_MJ_DEVICE_CONTROL IOCTL's:
ANTIVIRUS_CONFIG:
1. Recieves config data on registry keys to protect from the service.  


The NDIS Driver which intercepts network data and extracts any infos needed does the following:

depending on the ethertype, https://en.wikipedia.org/wiki/EtherType, it extracts data from teh PNET_BUFFER_LIST and sends the necessary infos to the service.
In my NDIS_FILTER_PARTIAL_CHARACTERISTICS I define the corresponding functions and in these functiosn i decide whether or not i should block. i block via NdisFSendNetBufferListsComplete()

The File System Driver which intercepts file disk activity does the following: (yes i know there are ways the attacker can bypass my filter...)
1. prevent access to my files.
2. Information about DISK i/o 


The ELAM driver:
calls driver load routine and upon boot it will read a values from the registry 
it then decides whether it should block/allow.



The Service:


I have my own signature format which I made using lexer + bison.
here is an example of the format.

```

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $a = { F4 23 62 B4 };
		$b = { F4 12 62 B4 };
    check:
        $a not $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $a = { F4 23 ( 62 B4 | 56 ) 45 };
        $b = "1231312";
    check:
        $a and $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $a = "AA?B";
        $b = {12 66 34 12};
    check:
        $a or $b;
}



Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $b = "wow\n";
    check:
        $b;
}


Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $b = "wow\tyea";
    check:
        $b;
}


Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $b = "wow\\";
    check:
        $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        insensitive $b = "wow";
    check:
        $b;
}


Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:

     $b = pe.exports("That", "Boy", "His", "Here");
     $c = pe.imports("This", "That", "Where", "Here");
    check:
      $c or $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:

     $b = pe.exports("That", "Boy", "His", "Here");
     $c = pe.imports("This", "That", "Where", "Here");
    check:
      $c and $b;
}
Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:

     $b = pe.exports("That", "Boy", "His", "Here");
     $c = pe.imports("This", "That", "Where", "Here");
    check:
      $c not $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        wide $b = "wow";
    check:
        $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        ascii $b = "wow";
    check:
        $b;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        nonalpha $b = "mywebsite";
    check:
        $b;
}/*
hjdvkjsdv sdvnsd vsdkvjhbsd vsdkvjhbsdsdvb
sdikhsdn sdksdhn dsklvhsdn
sdkdsn dsdhfnsdfdkshfndskf */
Signature Banker : 12312312312 //This is a comment
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $b = "something";
    check:
        $b at 4;
}
// This is a comment

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $b = "something";
    check:
        $b at 0x2;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    /*
      This is a comment
    */
    // this is another comment
    types:
        $b = "something";
    check:
        ($b * 5); // five times
}






Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $a = filename = = "something.exe";
    check:
        $a;
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $a = filesize >  = 100;
    check:
        $a;
}

Signature Banker : 1235
{
   info:
    	description= "this is blah blah...";
    	level=5;
    types:

    check:
      pe.call("OutputDebugString('O')");
      pe.call("OutputDebugString('O')", "MessageBox(0, 'A', 'M', NULL)");
}

Signature Banker : 12312312312
{
    info:
    	description= "this is blah blah...";
    	level=5;
    types:
        $b = /md5: [0-9a-zA-Z]{32}/;
    check:
        $b;
}

Signature Banker : 1235
{
   info:
    	description= "this is blah blah...";
    	level=5;
    types:
      $a = pe.call("OutputDebugString('O')");
      $b = pe.call("OutputDebugString('O')", "MessageBox(0, 'A', 'M', NULL)");
    check:
      $a;
      $b;
}

```

you can add comments in between and you can setup calls with specific values to monitor.

The service also emulates PE files using the unicorn engine. It will monitor API calls with the values passed. This is used to see if there are any networking calls :).
 
For unpacking compressed files I used libarchive. I tried my best to limit the number of 3rd party libraries I was using. But I am not going to implement everything from scratch since... That would be much, much more work than I anticipated.

The service also interacts with a DLL which is inject into process's via a named pipe. For applications where injection is not possible, I attempt to use a pre-exisiting handle because of the possiblity that my handle access rights are being stripped possibly from a kernel mode callback or something. Also it is to note that many applications (ff, last time i saw) now prevent "basic injection" that calls LoadLibrary().

The service also has its own PE functions to read certain segments of the PE file and I was going to add support for packers but that never happened. 

The service also has the regular memory scanning via ReadProcessMemory()...

The service also uses WinVerifyTrust() to verify signature in a "score" to determine whether a file is malicious.

The service also grabs the SHA256 of the file using bcrypt functions. This is needed for a regular hash comparison of the file.

The service also handles PDF files by parsing them and analyzing these parts, I was going to add support to the sig format for these parts. 

The service also has support for handling OLE files and MS docs. It can extract and decode macros.

The service also has support for handling SWF files since :) who doesnt love flash 0days.

The service also scans the MBR (lol??), for each partition it reads 512 bytes of the MBR))). It also handle VBR. it will check what kind it is etc like if it is "NT 6.0 Virtual BootRecord" etc and record this information and store it into a structure which will be sent back to see if a signature exists with the infos provided. (i never added this to sig format). 
I also use a diassembler for this part as well to see if there is any call or return instruction.


here are the types
 ```
typedef enum _Types{
    NOTHING = 0x00,
    FAT12 = 0x01,
    XENIX_ROOT = 0x02,
    XENIX_USR = 0x03,
    FAT16_old = 0x04,
    Extended_DOS = 0x05,
    FAT16 = 0x06,
    FAT32 = 0x0b,
    FAT32_LBA = 0x0c,
    NTFS = 0x07,
    LINUX_SWAP = 0x82,
    LINUX_NATIVE = 0x83,
    PROTECTIVE_MBR = 0xee
} Types;
```
I was going to eventually add support for javascript and other languages but the list will never stop... So here it stops


eventually todo:

add hypervisor to aid in hooking)))

make some cool tensorflow crap, oh boy this will fail badly...

a shit ton of crap like, add support for detecting remote code injection, detect hooking of functions (bankers, certain functions hooked like PR_Write, SSL_Write etc etc), New desktop creation (possible HVNC),

update sig format...

the list will never stop. there is too much work for a single person to do... The only thing that really matters is a nice looking UI since you can sell bullshit to people and they wont give a f**k. 
As long as it looks good, it "works". 


picture of the UI:

![ui](https://i.imgur.com/cTJaRaE.jpg)

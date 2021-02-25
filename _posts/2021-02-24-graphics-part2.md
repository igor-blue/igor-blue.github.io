---
layout: single
title:  "Security of the Intel Graphics Stack - Part 2 - FW <-> GuC"
---

Today we\'ll continue our voyage into the graphics subsystem components.

The question we\'ll try to answer is what kind of communications occur between the GuC and the rest of the system. In this post we\'ll look at firmware components and next post at Windows components.

For a reminder what the GuC is, look at [part1 post]({% post_url 2021-02-10-graphics-part1 %}) .

* Do not remove this line (it will not be displayed)
{:toc}

# Part 1: The IntelGOP DXE driver
The Intel Graphics Output Protocol (GOP) EFI DXE driver can be extracted in various versions from many UEFI capsules available through many vendors.
For this post I redid my original analysis on a recent version from a CanonLake system.

The purpose of this exercise is to try and see whether the GOP driver communicates with the GuC over the PCIe bus (TL;dr: it doesn\'t)

The binary isn\'t to large - 84KB, so we can try to completely reverse engineer it. I used both IDA+HexRays and a dynamic analysis UEFI emulator I developed for just these cases. The emulator lets you run EFI DXE drivers in Windows simulating many UEFI services and allowing me to modify/inspect EFI interfaces, hook UEFI protocol structs, and even has some fuzzing capabilities.

Looking at the driver\'s entrypoint we see it stores the different service tables in globals and then jumps to the main() functions I called GopEntryPoint(). 

```nasm
.text:0000000000001580 ; EFI_STATUS __fastcall ModuleEntryPoint(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
.text:0000000000001580                 public _ModuleEntryPoint
.text:0000000000001580 _ModuleEntryPoint proc near             ; DATA XREF: HEADER:00000000000000E8↑o
.text:0000000000001580                 sub     rsp, 28h
.text:0000000000001584                 mov     r8, [rdx+60h]
.text:0000000000001588                 mov     rax, [rdx+58h]
.text:000000000000158C                 mov     cs:gIMAGE_HANDLE, rcx
.text:0000000000001593                 mov     cs:gBOOT_SERVICES, r8
.text:000000000000159A                 mov     cs:gRUNTIME_SERVICES, rax
.text:00000000000015A1                 mov     cs:gBOOT_SERVICES2, r8
.text:00000000000015A8                 mov     cs:gSYSTEM_TABLE2, rdx
.text:00000000000015AF                 call    GopEntryPoint
.text:00000000000015B4                 add     rsp, 28h
.text:00000000000015B8                 retn
.text:00000000000015B8 _ModuleEntryPoint endp
```

GopEntryPoint() first part is really boring, just setting up version information in global strings.

```c
_int64 __fastcall GopEntryPoint(EFI_HANDLE img_handle_arg)
{
  EFI_HANDLE image_handle; // rbx
  CHAR16 *driver_desc_ptr; // rax
  __int64 img_handle; // r11
  __int64 result; // rax
  EFI_HANDLE Handle; // [rsp+50h] [rbp+18h]
  EFI_LOADED_IMAGE_PROTOCOL *Interface; // [rsp+58h] [rbp+20h]

  image_handle = img_handle_arg;
  v2 = atoi(L"0") == 1;
  driver_desc_ptr = gDriverDescription;
  v4 = 'I';
  byte_142A0 = v2;
  do
  {
    *driver_desc_ptr = v4;
    ++driver_desc_ptr;
    v4 = *(CHAR16 *)((char *)driver_desc_ptr + (char *)L"Intel(R) GOP Driver" - (char *)gDriverDescription);
  }
  while ( v4 );
  *driver_desc_ptr = 0;
  strcat(gDriverDescription, L" [");
  strcat(gDriverDescription, L"11");
  strcat(gDriverDescription, L".");
  strcat(gDriverDescription, L"0");
  strcat(gDriverDescription, L".");
  strcat(gDriverDescription, L"1014");
  strcat(gDriverDescription, L"]");
  gDriverState.ImgHandle = img_handle;
  v12 = &gDriverVersion;
  v13 = '1';
  do
  {
    *v12 = v13;
    ++v12;
    v13 = *(CHAR16 *)((char *)v12 + (char *)L"11" - (char *)&gDriverVersion);
  }
  while ( v13 );
  *v12 = 0;
  strcat(&gDriverVersion, L".");
  strcat(&gDriverVersion, L"0");
  strcat(&gDriverVersion, L".");
  strcat(&gDriverVersion, L"1014");
  gDriverState.ControllerName = (__int64)L"Intel(R) Graphics Controller";
  gDriverState.DriverVersion = v17;
  atoi(L"11");
  atoi(L"0");
  v18 = atoi(L"1014");
```

The second part does the actual work. First it looks for the EFI_LOADED_IMAGE_PROTOCOL to setup a the unload routine:

```c
  gDRIVER_BINDING_PROTOCOL.Version = v18 + v19;
  result = gBOOT_SERVICES->OpenProtocol(
             image_handle,
             &EFI_LOADED_IMAGE_PROTOCOL_GUID,
             (void **)&Interface,
             image_handle,
             image_handle,
             2u);
  if ( result >= 0 )
  {
    Interface->Unload = (EFI_IMAGE_UNLOAD)UnloadImage;
```

And then install four protocol handlers, three of which I identified: one for driver binding and two for component name handling. The InstallMultipleProtocolInterfaces(..) can accept multiple protocols, each protocol has a GUID and the "virtual table" like structure used by UEFI. The final entry is NULL. Most UEFI protocol GUIDs are public (and appear in the EDK) so we can identify them easily and this identify the virtual table structures associated with them, for example for the UEFI binding protocol we have in DriverBinding.h:

```c
#define EFI_DRIVER_BINDING_PROTOCOL_GUID \
	{0x18A031AB,0xB443,0x4D1A,0xA5,0xC0,0x0C,0x09,0x26,0x1E,0x9F,0x71}

GUID_VARIABLE_DECLARATION(gEfiDriverBindingProtocolGuid, EFI_DRIVER_BINDING_PROTOCOL_GUID);

typedef struct _EFI_DRIVER_BINDING_PROTOCOL EFI_DRIVER_BINDING_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_DRIVER_BINDING_PROTOCOL_SUPPORTED) (
	IN EFI_DRIVER_BINDING_PROTOCOL *This, 
	IN EFI_HANDLE ControllerHandle,
	IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath OPTIONAL
);

typedef EFI_STATUS (EFIAPI *EFI_DRIVER_BINDING_PROTOCOL_START) (
	IN EFI_DRIVER_BINDING_PROTOCOL *This,
	IN EFI_HANDLE ControllerHandle,
	IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath OPTIONAL
);

typedef EFI_STATUS (EFIAPI *EFI_DRIVER_BINDING_PROTOCOL_STOP) (
	IN EFI_DRIVER_BINDING_PROTOCOL *This,
	IN EFI_HANDLE ControllerHandle,
	IN UINTN NumberOfChildren,
	IN EFI_HANDLE *ChildHandleBuffer OPTIONAL
);

struct _EFI_DRIVER_BINDING_PROTOCOL {
	EFI_DRIVER_BINDING_PROTOCOL_SUPPORTED Supported;
	EFI_DRIVER_BINDING_PROTOCOL_START Start;
	EFI_DRIVER_BINDING_PROTOCOL_STOP Stop;
	UINT32 Version;
	EFI_HANDLE ImageHandle;
	EFI_HANDLE DriverBindingHandle;
};
```

This enables us to reverse the rest of GopEntryPoint:
```c    
    Handle = image_handle;
    gBOOT_SERVICES->InstallMultipleProtocolInterfaces(
      &Handle,
      &EFI_DRIVER_BINDING_PROTOCOL_GUID,
      &gDRIVER_BINDING_PROTOCOL,
      &EFI_COMPONENT_NAME2_PROTOCOL_GUID,
      &gCOMPONENT_NAME2_PROTOCOL,
      0i64);
    gDRIVER_BINDING_PROTOCOL.DriverBindingHandle = Handle;
    gDRIVER_BINDING_PROTOCOL.ImageHandle = image_handle;
    gBOOT_SERVICES->InstallMultipleProtocolInterfaces(
      &gDRIVER_BINDING_PROTOCOL.DriverBindingHandle,
      &UNKNOWN_PROTOCOL_GUID,
      &gDriverState.unknwon_proto,
      0i64);
    result = gBOOT_SERVICES->InstallMultipleProtocolInterfaces(
               &gDRIVER_BINDING_PROTOCOL.DriverBindingHandle,
               &GOP_COMPONENT_NAME2_PROTOCOL_GUID,
               &gGOP_COMPONENT_NAME2_PROTOCOL,
               0i64);
    if ( result >= 0 )
      qword_142B0 = (__int64)image_handle;
  }
  return result;
}
```

All the GUID values appear close to each other at the beginning of the binary, so we can take a shortcut and find all the GUIDs the driver uses:

```nasm
.text:0000000000000240 EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID dd 9042A9DEh            ; Data1
.text:0000000000000240                                         ; DATA XREF: HEADER:00000000000000EC↑o
.text:0000000000000240                                         ; HEADER:00000000000001D4↑o ...
.text:0000000000000240                 dw 23DCh                ; Data2
.text:0000000000000240                 dw 4A38h                ; Data3
.text:0000000000000240                 db 96h, 0FBh, 7Ah, 0DEh, 0D0h, 80h, 51h, 6Ah; Data4
.text:0000000000000250 EFI_EDID_ACTIVE_PROTOCOL_GUID dd 0BD8C1056h           ; Data1
.text:0000000000000250                                         ; DATA XREF: InstallGraphicsProto+124↓o
.text:0000000000000250                                         ; uninstall2?+9B↓o ...
.text:0000000000000250                 dw 9F36h                ; Data2
.text:0000000000000250                 dw 44ECh                ; Data3
.text:0000000000000250                 db 92h, 0A8h, 0A6h, 33h, 7Fh, 81h, 79h, 86h; Data4
.text:0000000000000260 EFI_EDID_DISCOVERED_PROTOCOL_GUID dd 1C0C34F6h            ; Data1
.text:0000000000000260                                         ; DATA XREF: sub_1CA4+2A5↓o
.text:0000000000000260                                         ; InstallGraphicsProto+DF↓o ...
.text:0000000000000260                 dw 0D380h               ; Data2
.text:0000000000000260                 dw 41FAh                ; Data3
.text:0000000000000260                 db 0A0h, 49h, 8Ah, 0D0h, 6Ch, 1Ah, 66h, 0AAh; Data4
.text:0000000000000270 GOP_DISPLAY_BRIGHTNESS_PROTOCOL_GUID dd 6FF23F1Dh            ; Data1
.text:0000000000000270                                         ; DATA XREF: sub_1F78+B1↓o
.text:0000000000000270                                         ; uninstall2?+14B↓o ...
.text:0000000000000270                 dw 877Ch                ; Data2
.text:0000000000000270                 dw 4B1Bh                ; Data3
.text:0000000000000270                 db 93h, 0FCh, 0F1h, 42h, 0B2h, 0EEh, 0A6h, 0A7h; Data4
.text:0000000000000280 GOP_DISPLAY_BIST_PROTOCOL_GUID dd 0F51DD33Ah           ; Data1
.text:0000000000000280                                         ; DATA XREF: sub_1F78+75↓o
.text:0000000000000280                                         ; uninstall2?+F5↓o ...
.text:0000000000000280                 dw 0E57Fh               ; Data2
.text:0000000000000280                 dw 4020h                ; Data3
.text:0000000000000280                 db 0B4h, 66h, 0F4h, 0C1h, 71h, 0C6h, 0E4h, 0F7h; Data4
.text:0000000000000290 EFI_PCI_IO_PROTOCOL_GUID dd 4CF5B200h            ; Data1
.text:0000000000000290                                         ; DATA XREF: DriverBindingProtoSupported+CB↓o
.text:0000000000000290                                         ; DriverBindingProtoSupported+173↓o ...
.text:0000000000000290                 dw 68B8h                ; Data2
.text:0000000000000290                 dw 4CA5h                ; Data3
.text:0000000000000290                 db 9Eh, 0ECh, 0B2h, 3Eh, 3Fh, 50h, 2, 9Ah; Data4
.text:00000000000002A0 GOP_COMPONENT_NAME2_PROTOCOL_GUID dd 651B7EBDh            ; Data1
.text:00000000000002A0                                         ; DATA XREF: GopEntryPoint+22F↓o
.text:00000000000002A0                 dw 0CE13h               ; Data2
.text:00000000000002A0                 dw 41D0h                ; Data3
.text:00000000000002A0                 db 82h, 0E5h, 0A0h, 63h, 0ABh, 0BEh, 9Bh, 0B6h; Data4
.text:00000000000002B0 UNKNOWN_PROTOCOL_GUID dd 0DBCB2FCDh           ; Data1
.text:00000000000002B0                                         ; DATA XREF: UnloadImage+9A↓o
.text:00000000000002B0                                         ; GopEntryPoint+203↓o
.text:00000000000002B0                 dw 0E29Ah               ; Data2
.text:00000000000002B0                 dw 410Eh                ; Data3
.text:00000000000002B0                 db 9Dh, 0D9h, 0FAh, 9Dh, 5Fh, 0F4h, 0CDh, 0A7h; Data4
.text:00000000000002C0 MAYBE_AUX_PROTOCOL_GUID? dd 0C7D4703Bh           ; Data1
.text:00000000000002C0                                         ; DATA XREF: DriverBindingProtoStartImp+2A8↓o
.text:00000000000002C0                                         ; DriverBindingProtoStop+70↓o
.text:00000000000002C0                 dw 0F36h                ; Data2
.text:00000000000002C0                 dw 4E51h                ; Data3
.text:00000000000002C0                 db 0A9h, 83h, 5Eh, 61h, 0ACh, 0B8h, 68h, 3Ch; Data4
.text:00000000000002D0 EFI_DEVICE_PATH_PROTOCOL_GUID dd 9576E91h             ; Data1
.text:00000000000002D0                                         ; DATA XREF: DriverBindingProtoSupported+5F↓o
.text:00000000000002D0                                         ; DriverBindingProtoSupported+A2↓o ...
.text:00000000000002D0                 dw 6D3Fh                ; Data2
.text:00000000000002D0                 dw 11D2h                ; Data3
.text:00000000000002D0                 db 8Eh, 39h, 0, 0A0h, 0C9h, 69h, 72h, 3Bh; Data4
.text:00000000000002E0 ; EFI_GUID EFI_LOADED_IMAGE_PROTOCOL_GUID
.text:00000000000002E0 EFI_LOADED_IMAGE_PROTOCOL_GUID dd 5B1B31A1h            ; Data1
.text:00000000000002E0                                         ; DATA XREF: GopEntryPoint+169↓o
.text:00000000000002E0                 dw 9562h                ; Data2
.text:00000000000002E0                 dw 11D2h                ; Data3
.text:00000000000002E0                 db 8Eh, 3Fh, 0, 0A0h, 0C9h, 69h, 72h, 3Bh; Data4
.text:00000000000002F0 EFI_DRIVER_BINDING_PROTOCOL_GUID dd 18A031ABh            ; Data1
.text:00000000000002F0                                         ; DATA XREF: UnloadImage+BB↓o
.text:00000000000002F0                                         ; GopEntryPoint+1D2↓o
.text:00000000000002F0                 dw 0B443h               ; Data2
.text:00000000000002F0                 dw 4D1Ah                ; Data3
.text:00000000000002F0                 db 0A5h, 0C0h, 0Ch, 9, 26h, 1Eh, 9Fh, 71h; Data4
.text:0000000000000300 EFI_COMPONENT_NAME2_PROTOCOL_GUID dd 6A7A5CFFh            ; Data1
.text:0000000000000300                                         ; DATA XREF: UnloadImage+A1↓o
.text:0000000000000300                                         ; GopEntryPoint+1B8↓o
.text:0000000000000300                 dw 0E8D9h               ; Data2
.text:0000000000000300                 dw 4F70h                ; Data3
.text:0000000000000300                 db 0BAh, 0DAh, 75h, 0ABh, 30h, 25h, 0CEh, 14h; Data4
```

A few couldn\'t be identified. Another \"fast forward\" trick I can use is to find all locations protocols are installed or requested.
If we look at how protocols are installed using gBOOT_SERVICES::InstallMultipleProtocolInterfaces:

```nasm
.text:0000000000002938 FF 90 48 01 00 00                 call    qword ptr dword_148[rax]
```

We see the offset is pretty large, 0x148. We can just search for the wildcard `"call qword ptr dword_148[reg]"` and see if reg contains the global gBOOT_SERVICES. This way we can jump directly to the functions
and identify what they do and name them:

```
Address	Function	Instruction
.text:000000000000188B	GopEntryPoint	                    FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:00000000000018C3	GopEntryPoint	                    FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:00000000000018E8	GopEntryPoint	                    FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:0000000000001ECC	EnumConnectionsAndInstallEdidProto	FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:0000000000001F50	EnumConnectionsAndInstallEdidProto	FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:0000000000001FFA	InstallBrightnessProto	            FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:0000000000002036	InstallBrightnessProto              FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:000000000000221F	InstallGraphicsProto	            FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:00000000000022A0	InstallGraphicsProto             	FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
.text:0000000000002938	DriverBindingProtoStartImp        	FF 90 48 01 00 00                 call    [rax+EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces]
```

This also gets as all the function tables for these protocols, and helps us understand the global state struct for the driver. Unlike C++, the UEFI function receive a ```This``` pointer that contains both data members and function pointers, for example for the GOP protocol:

```c
...
typedef EFI_STATUS (EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT) (
    IN EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
    IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer OPTIONAL,
    IN EFI_GRAPHICS_OUTPUT_BLT_OPERATION BltOperation,
    IN UINTN SourceX, IN UINTN SourceY,
    IN UINTN DestinationX, IN UINTN DestinationY,
    IN UINTN Width, IN UINTN Height,
    IN UINTN Delta OPTIONAL
);

typedef struct {
    UINT32 MaxMode;
    UINT32 Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
    UINTN SizeOfInfo;
    EFI_PHYSICAL_ADDRESS FrameBufferBase;
    UINTN FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

struct _EFI_GRAPHICS_OUTPUT_PROTOCOL {
    EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE QueryMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE SetMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT Blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
};
```

So the protocol structure has to be stored in some state structure. If the state structure is a singleton it can be stored as a global, but if we want multiple copies the driver allocates a state structure, places the protocol structure in a known offset within, and then can calculate the start of the structure from the `This` pointer provided to the protocol functions. We can use this information to try to piece together this global structre:

```nasm
00000000 DriverState     struc ; (sizeof=0xE8, mappedto_92)
00000000                                         ; XREF: .text:gDriverState/r
00000000 language        dq ?                    ; offset
00000008 ImgHandle       dq ?                    ; XREF: GopEntryPoint+A9/w
00000010 field_10        dd ?
00000014 field_14        dd ?
00000018 graphics_proto  dq ?
00000020 field_20        dq ?                    ; XREF: GetDriverVersion+16/o
00000028 DriverVersion   dq ?                    ; XREF: GopEntryPoint+125/w
00000030 field_30        dq ?
00000038 active_proto_copy dq ?
00000040 field_40        dq ?                    ; XREF: GetControllerName+99/o
00000048 ControllerName  dq ?                    ; XREF: GopEntryPoint+11E/w
00000050 field_50        dq ?
00000058 field_58        dq ?
00000060 brightness_proto dq ?                   ; XREF: UnloadImage+8E/o
00000060                                         ; GopEntryPoint+1EE/o
00000068 name_proto      dq ?
00000070 bist_proto_orig GOP_DISPLAY_BIST_PROTOCOL_FUNC_TABLE ?
00000070                                         ; XREF: InstallBrightnessProto+50/o
00000080 bist_proto      GOP_DISPLAY_BIST_PROTOCOL ?
00000080                                         ; XREF: sub_44D8+21/o
00000080                                         ; sub_44D8+28/w ...
00000094 field_94        dd ?
00000098 field_98        dq ?                    ; XREF: sub_4900+24/o
00000098                                         ; sub_4900+2F/w ...
000000A0 field_A0        dq ?                    ; XREF: sub_4900+36/w
000000A0                                         ; sub_4900+319/r ...
000000A8 field_A8        dq ?                    ; XREF: sub_245C+14/r
000000A8                                         ; sub_245C+1B/o ...
000000B0 field_B0        dq ?                    ; XREF: sub_245C+86/r
000000B0                                         ; sub_259C+6C/r ...
000000B8 field_B8        dq ?                    ; XREF: sub_35A4+37A/o
000000B8                                         ; sub_35A4+384/w ...
000000C0 field_C0        dq ?                    ; XREF: sub_35A4+38B/w
000000C0                                         ; sub_35A4+3EF/r ...
000000C8 field_C8        dq ?
000000D0 field_D0        dq ?                    ; XREF: sub_35A4+420/o
000000D8 field_D8        dq ?
000000E0 field_E0        dq ?
000000E8 DriverState     ends
```

and so on.

It won\'t be too interesting to just dump more and more dissassembled functions here, as our goal is to find possible access to GuC. None of the functions I identified had any connection to the GuC, so next I looked at all accesses to PCI devices, as GuC accesses should be made using PCI. The devices are identified using ```EFI_DEVICE_PATH_PROTOCOL``` and accessed through ```EFI_PCI_IO_PROTOCOL_GUID```.

|-------------|--------|
| DriverBindingProtoSupported+CB | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| DriverBindingProtoSupported+173 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| EnumConnectionsAndInstallEdidProto+259 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| sub_245C+9C | `lea     r8, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| sub_259C+33 | `lea     r8, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| sub_259C+81 | `lea     r8, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| DriverBindingProtoStartImp+44 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| DriverBindingProtoStartImp+20C | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| uninstall?+76 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| uninstall?+220 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| DriverBindingProtoStop+DD | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| DriverBindingProtoStop+120 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| sub_2EC0+158 | `lea     r8, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| GetControllerName+3A | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| GetControllerName+59 | `lea     rdx, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|
| GetControllerName:loc_55C6 | `lea     r8, EFI_PCI_IO_PROTOCOL_GUID` |
|-------------|--------|

Some places are spurios, like:
```nasm
.text:00000000000024F8                 lea     r8, EFI_PCI_IO_PROTOCOL_GUID
.text:00000000000024FF                 mov     rcx, rsi
.text:0000000000002502                 call    sub_5F04
```

Since `sub_5F04` overrides r8 immediatly:
```nasm
.text:0000000000005F04 sub_5F04        proc near               ; CODE XREF: sub_245C+A6↑p
.text:0000000000005F04                                         ; sub_259C+41↑p ...
.text:0000000000005F04
.text:0000000000005F04 count           = qword ptr -18h
.text:0000000000005F04 arg_0           = qword ptr  8
.text:0000000000005F04 proto_info      = qword ptr  20h
.text:0000000000005F04
.text:0000000000005F04                 mov     [rsp+arg_0], rbx
.text:0000000000005F09                 push    rdi
.text:0000000000005F0A                 sub     rsp, 30h
.text:0000000000005F0E                 mov     rax, cs:gBOOT_SERVICES
.text:0000000000005F15                 mov     rdi, rdx
.text:0000000000005F18                 lea     r9, [rsp+38h+count]
.text:0000000000005F1D                 lea     r8, [rsp+38h+proto_info]      ;; HERE!!
```

Long story short: no code in the GOP DXE driver communicates with the GuC.

Before moving on to CSME vs GuC, I was curious who exactly uses all these protocols, in the rest of the UEFI BIOS and Windows. I extracted the UEFI capsule and 
also mounted the Windows ISO and WIM files (`dism /mount-image /imagefile:e:\sources\install.wim /index:1 /mountdir:c:\mnt\install /readonly`), and then 
ran the following python script:


```python
from struct import unpack
from os import walk
from mmap import mmap, ACCESS_READ
import os.path as path

GUIDS = (
((0xDE, 0xA9, 0x42, 0x90, 0xDC, 0x23, 0x38, 0x4A, 0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A), 'EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID'),
((0x56, 0x10, 0x8C, 0xBD, 0x36, 0x9F, 0xEC, 0x44, 0x92, 0xA8, 0xA6, 0x33, 0x7F, 0x81, 0x79, 0x86), 'EFI_EDID_ACTIVE_PROTOCOL_GUID'),
((0xF6, 0x34, 0x0C, 0x1C, 0x80, 0xD3, 0xFA, 0x41, 0xA0, 0x49, 0x8A, 0xD0, 0x6C, 0x1A, 0x66, 0xAA), 'EFI_EDID_DISCOVERED_PROTOCOL_GUID'),
((0x1D, 0x3F, 0xF2, 0x6F, 0x7C, 0x87, 0x1B, 0x4B, 0x93, 0xFC, 0xF1, 0x42, 0xB2, 0xEE, 0xA6, 0xA7), 'GOP_DISPLAY_BRIGHTNESS_PROTOCOL_GUID'),
((0x3A, 0xD3, 0x1D, 0xF5, 0x7F, 0xE5, 0x20, 0x40, 0xB4, 0x66, 0xF4, 0xC1, 0x71, 0xC6, 0xE4, 0xF7), 'GOP_DISPLAY_BIST_PROTOCOL_GUID'),
#((0x00, 0xB2, 0xF5, 0x4C, 0xB8, 0x68, 0xA5, 0x4C, 0x9E, 0xEC, 0xB2, 0x3E, 0x3F, 0x50, 0x02, 0x9A), 'EFI_PCI_IO_PROTOCOL_GUID'),
#((0xBD, 0x7E, 0x1B, 0x65, 0x13, 0xCE, 0xD0, 0x41, 0x82, 0xE5, 0xA0, 0x63, 0xAB, 0xBE, 0x9B, 0xB6), 'GOP_COMPONENT_NAME2_PROTOCOL_GUID'),
((0xCD, 0x2F, 0xCB, 0xDB, 0x9A, 0xE2, 0x0E, 0x41, 0x9D, 0xD9, 0xFA, 0x9D, 0x5F, 0xF4, 0xCD, 0xA7), 'UNKNOWN_PROTOCOL_GUID'),
((0x3B, 0x70, 0xD4, 0xC7, 0x36, 0x0F, 0x51, 0x4E, 0xA9, 0x83, 0x5E, 0x61, 0xAC, 0xB8, 0x68, 0x3C), 'MAYBE_AUX_PROTOCOL_GUID?'),
#((0x91, 0x6E, 0x57, 0x09, 0x3F, 0x6D, 0xD2, 0x11, 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B), 'EFI_DEVICE_PATH_PROTOCOL_GUID'),
#((0xA1, 0x31, 0x1B, 0x5B, 0x62, 0x95, 0xD2, 0x11, 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B), 'EFI_LOADED_IMAGE_PROTOCOL_GUID'),
#((0xAB, 0x31, 0xA0, 0x18, 0x43, 0xB4, 0x1A, 0x4D, 0xA5, 0xC0, 0x0C, 0x09, 0x26, 0x1E, 0x9F, 0x71), 'EFI_DRIVER_BINDING_PROTOCOL_GUID'),
#((0xFF, 0x5C, 0x7A, 0x6A, 0xD9, 0xE8, 0x70, 0x4F, 0xBA, 0xDA, 0x75, 0xAB, 0x30, 0x25, 0xCE, 0x14), 'EFI_COMPONENT_NAME2_PROTOCOL_GUID')
)

guids = { bytes(k) : v for k, v in GUIDS }
first_dwords = set([unpack("<I", guid[0:4]) for guid in guids.keys()])

for root in ('c:\\mnt\\iso', 'c:\\mnt\\boot', 'c:\\mnt\\install', 'c:\\mnt\\uefi'):
    for dir, _, files in walk(root):
        for file in files:
            filename = dir + '\\' + file
            try:
                filelen = path.getsize(filename) & ~15
                if filelen == 0:
                    continue
                with open(filename, 'rb') as file:
                    with mmap(file.fileno(), filelen, access=ACCESS_READ) as mem:
                        for ofs in range(0, filelen, 16):
                            if unpack("<I", mem[ofs:ofs+4]) in first_dwords:
                                guid = mem[ofs:ofs+16]
                                try:
                                    name = guids[guid]
                                    print(f'{filename}\t{ofs:x}\t{name}')
                                except KeyError:
                                    pass
            except PermissionError:
                pass
```

The UEFI setup and legacy components use the GOP and the EDID components:
```
c:\mnt\uefi\\AMITSE.efi	400	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\uefi\\Bds.efi	3d0	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\uefi\\ConSplitter.efi	310	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\uefi\\CsmVideo.efi	2c0	EFI_EDID_DISCOVERED_PROTOCOL_GUID
c:\mnt\uefi\\CsmVideo.efi	2d0	EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\uefi\\CsmVideo.efi	320	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\uefi\\GraphicsConsole.efi	2b0	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\uefi\\Setup.efi	2e0	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\uefi\\UefiPxeBcDxe.efi	490	EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
```

In Windows we have only:

```
c:\mnt\boot\Windows\Boot\EFI\bootmgfw.efi       a1a0    EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\boot\Windows\Boot\EFI\bootmgfw.efi       a220    EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\winload.efi        17e210  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\winload.efi        17e2a0  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\winresume.efi      122c00  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\winresume.efi      122c80  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\Boot\winload.efi   17e210  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\Boot\winload.efi   17e2a0  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\Boot\winresume.efi 122bf0  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\boot\Windows\System32\Boot\winresume.efi 122c70  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\install\Windows\Boot\EFI\bootmgfw.efi    a1a0    EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\install\Windows\Boot\EFI\bootmgfw.efi    a220    EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\install\Windows\System32\SecConfig.efi   110b80  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\install\Windows\System32\SecConfig.efi   110c00  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\install\Windows\System32\winload.efi     17e210  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\install\Windows\System32\winload.efi     17e2a0  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\install\Windows\System32\winresume.efi   122c00  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\install\Windows\System32\winresume.efi   122c80  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\install\Windows\System32\Boot\winload.efi        17e210  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\install\Windows\System32\Boot\winload.efi        17e2a0  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\install\Windows\System32\Boot\winresume.efi      122bf0  EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\install\Windows\System32\Boot\winresume.efi      122c70  EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
c:\mnt\iso\bootx64.efi a1a0    EFI_EDID_ACTIVE_PROTOCOL_GUID
c:\mnt\iso\bootx64.efi a220    EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
```

So basically most of the GOP DXE driver functions go unused and can be considered bloat ...

Are EFI_GRAPHICS_OUTPUT_PROTOCOL and EFI_EDID_ACTIVE_PROTOCOL_GUID possible vectors for exploitation from UEFI -> Windows? Assume for example a DXE driver has a bug that can be exploited using specialized hardware, and you gain execution in the UEFI firmware during boot. Can these protocols be used as an attack surface to attack SecureBoot Windows?

As seen before, EFI_GRAPHICS_OUTPUT_PROTOCOL has a driver controlled `Mode` member
```c
struct _EFI_GRAPHICS_OUTPUT_PROTOCOL {
    EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE QueryMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE SetMode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT Blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
};
```

In turn EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE is defined as:
```c
typedef struct {
    UINT32 MaxMode;
    UINT32 Mode;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
    UINTN SizeOfInfo;
    EFI_PHYSICAL_ADDRESS FrameBufferBase;
    UINTN FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;
```

These structure are used in several functions inside the console library shared by all the relevant Windows components. The two main functions are `ConsoleEfiGopOpen` and `ConsoleEfiGopEnable`:

```c
__int64 __fastcall ConsoleEfiGopOpen(CONSOLE_DATA *this)
{
  ...
  if ( EfiOpenProtocol(this->efi_handle, (__int64)&EfiGraphicsOutputProtocol, &gop_protocol) >= 0 )
  {
    status = EfiGopGetCurrentMode(gop_protocol, &mode, &mode_info);
    if ( status >= 0 )
    {
      orig_mode = mode;
      new_mode = mode;
      
      ... check if mode is allowed, if not get allowed mode ...
      
      // fill state with mode data
      is_rgb = mode_info.PixelFormat == PixelBlueGreenRedReserved8BitPerColor;
      this_1->gop_protocol = gop_protocol;
      this_1->new_mode = new_mode;
      this_1->orig_mode = orig_mode;
      if ( is_rgb )
        bits_per_pixel = 32;
      else if ( mode_info.PixelFormat == PixelBitMask )
        bits_per_pixel = 24;      
      else {
        status = STATUS_UNSUCCESSFUL;
        goto exit_handler;
      }
      this_1->orig_horiz_res = mode_info.HorizontalResolution;
      this_1->orig_vert_res = mode_info.VerticalResolution;
      pixels_per_scan_line = mode_info.PixelsPerScanLine;
      this_1->orig_bits_per_pixel = bits_per_pixel;
      result = 0i64;
      this_1->orig_pixels_per_scan_line = pixels_per_scan_line;
      return result;
      
    }
exit_handler:
    EfiCloseProtocol(this_1->efi_handle, &EfiGraphicsOutputProtocol);
    return (unsigned int)status;
  }
  return 0xC00000BB;
}
```

EfiGopGetCurrentMode() in turn uses MmArchTranslateVirtualAddress to get physical addresses for the output:

```c
int __fastcall EfiGopGetCurrentMode(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop, unsigned int *mode, EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info)
{
  ...
  info_phys_addr = info;
  mode_phys_addr = mode;
  gop_phys_addr = gop;
  context_mode = *gCurrentExecutionContext;
  if ( *gCurrentExecutionContext != ExecutionContextFirmware )
  {
    if ( gop )
      status = MmArchTranslateVirtualAddress(gop, (unsigned __int64 *)&phys_addr, 0i64, 0i64);
    else
      status = 0;
    if ( !status )
      return STATUS_UNSUCCESSFUL;
    gop_phys_addr = phys_addr;
    is_mapped = mode_phys_addr ? MmArchTranslateVirtualAddress(
                                   mode_phys_addr,
                                   (unsigned __int64 *)&phys_addr,
                                   0i64,
                                   0i64) : 0;
    if ( !is_mapped )
      return STATUS_UNSUCCESSFUL;
    mode_phys_addr = (unsigned int *)phys_addr;
    is_mapped_2 = info_phys_addr ? MmArchTranslateVirtualAddress(
                                     info_phys_addr,
                                     (unsigned __int64 *)&phys_addr,
                                     0i64,
                                     0i64) : 0;
    if ( !is_mapped_2 )
      return STATUS_UNSUCCESSFUL;
    info_phys_addr = (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *)phys_addr;
    BlpArchSwitchContext(ExecutionContextFirmware);
  }
  *mode_phys_addr = gop_phys_addr->Mode->Mode;
  mode_info = gop_phys_addr->Mode->Info;
  *(_OWORD *)&info_phys_addr->Version = *(_OWORD *)&mode_info->Version;
  info_phys_addr->PixelInformation = mode_info->PixelInformation;
  info_phys_addr->PixelsPerScanLine = mode_info->PixelsPerScanLine;
  if ( context_mode != ExecutionContextFirmware )
    BlpArchSwitchContext(context_mode);
  return v3;
}
```

The most we can get from this is an arbitary read from physical memory by Windows.

Lets look at `ConsoleEfiGopEnable`:

```
unsigned int __fastcall ConsoleEfiGopEnable(CONSOLE_DATA *this)
{
  ...
  status = EfiGopGetCurrentMode(this->gop_protocol, &old_mode, &mode_info);
  if ( status < 0 )
    return status;
  new_mode_1 = old_mode;
  if ( old_mode != new_mode )
  {  
    status = EfiGopSetMode(this_1->gop_protocol, new_mode);
    if ( status >= 0 )
    {
      BlDisplayInvalidateOemBitmap();
      EfiGopGetCurrentMode(this_1->gop_protocol, &mode, &mode_info);
      new_mode_1 = old_mode;
    }
  }
  
    if ( mode_info.PixelFormat == PixelBlueGreenRedReserved8BitPerColor )
        bits_per_pixel = 32;
    else if ( mode_info.PixelFormat == PixelBitMask )
        bits_per_pixel = 24;
    else { ...; return STATUS_UNSUCCESSFUL; }
    
    EfiGopGetFrameBuffer(this_1->gop_protocol, &frame_buffer_base, &frame_buffer_size);
    if ( BlMmMapPhysicalAddressEx(&frame_buffer, frame_buffer_base, frame_buffer_size, 8u, 0) >= 0
      || (status = BlMmMapPhysicalAddressEx(&frame_buffer, frame_buffer_base, frame_buffer_size, 1u, 0), status >= 0) )
    {
      this_1->frame_buffer = (void *)frame_buffer_1;
      this_1->frame_buffer_size = frame_buffer_size;
      this_1->bits_per_pixel = bits_per_pixel;
      this_1->horiz_res = mode_info.HorizontalResolution;
      ... contonue filling this_1 with mode_info ...
      return result;
    }
  }
  return STATUS_UNSUCCESSFUL;
```

Here Windows map the physical address supplied by GOP->FrameBuffer (retrieved in EfiGopGetFrameBuffer) into Windows.
We can control FrameBuffer so we might be able to arbitarily map any physical memory as the frame buffer.

How does that help us? If for example the OEM logo (specified in the \'BGRT\' ACPI table) is copied to the FrameBuffer, we can write data under our control to a physical address under our control - after the bootmgr has already been verified as part of the Secure Boot process.

But this is tangental to this post so we'll examine this vector in a future post.

# Part 2: From CSME
Now lets turn to the question wether CSME accesses the GuC and vice-versa.

The CSME is really big, so an exhastive disassembly like we did for the GOP is less relevant. So where might the CSME engine need to communicate with the GuC?

One place that comes into mind is the PAVP - Protected Audio Video Path. This is the component that protects protected HD content from being copied. The protection is implemented by creating a secure pipeline from the media components in the Windows kernel, through the GFX driver, and all the way to the display. The CSME is used to protect the pipeline including certs, keys and much more.

We can start with the CSME HECI (Host Embedded Controller Interface) driver on Windows and find the relevant HECI messages.
One group of interesting messages I found was for the `LSPCON` component. LSPCON stands for *Level Shifter and Protocol Converter*, which is used for HDR signalling over HDMI.

No hard work means no fish, so we go on a fishing expedition and finally manage to extract the **PAVP** component from an old CSME15 build. Its about 300KB in size, so still quite big.

Reversing this I went down a deep rabbit hole. I finally discovered a function I named `PAVP_init_heci`, that is called from `main` and  initializes the HECI communication module in PAVP and registers an interface with three functions:
- handle async messages  - `PAVP_handle_async_message`
- HECI connection request - `PAVP_connect`
- HECI disconnect request - `PAVP_disconnect`
(all the names are mine)

`PAVP_heci_handle_async_message()` handles different types of messages like *widevine*, *asmf*, *PlayReady* and so on. We are interested in CPHS - Intel Content Protection HECI Service, a function I named `PAVP_process_cphs_message()`. Digging deeper we eventually reach the LSPCON command handler:

```nasm
.text:0010775B ; int __cdecl LSPCON_command_handler(PavpCtx *ctx, void *heci_msg, int heci_msg_len, int max_out_len, int *out_len)
.text:0010775B LSPCON_command_handler proc near        ; CODE XREF: PAVP_heci_command_handler+8D↑p
.text:0010775B
.text:0010775B var_14          = dword ptr -14h
.text:0010775B msg_len         = dword ptr -10h
.text:0010775B ctx             = dword ptr  8
.text:0010775B heci_msg        = dword ptr  0Ch
.text:0010775B heci_msg_len    = dword ptr  10h
.text:0010775B max_out_len     = dword ptr  14h
.text:0010775B out_len         = dword ptr  18h
.text:0010775B
.text:0010775B cmd = ebx
.text:0010775B                 push    ebp
.text:0010775C                 mov     ebp, esp
.text:0010775E                 push    edi
.text:0010775F                 push    esi
.text:00107760                 push    cmd
.text:00107761                 sub     esp, 8
.text:00107764                 mov     eax, [ebp+heci_msg_len]
.text:00107767                 mov     ecx, [ebp+ctx]
.text:0010776A                 mov     [ebp+msg_len], eax
.text:0010776D                 mov     eax, [ebp+max_out_len]
.text:00107770                 mov     cmd, [ebp+heci_msg]
.text:00107773                 mov     [ebp+var_14], eax
.text:00107776                 mov     esi, [ebp+out_len]
.text:00107779                 test    ecx, ecx
.text:0010777B                 jz      short err_cmd_not_in_range
.text:0010777D                 cmp     [ecx+PavpCtx.Lspcon], 0
.text:00107781                 jz      short err_cmd_not_in_range
.text:00107783                 test    cmd, cmd
.text:00107785                 setz    dl
.text:00107788                 test    esi, esi
.text:0010778A                 setz    al
.text:0010778D                 or      dl, al
.text:0010778F                 jnz     short err_cmd_not_in_range
.text:00107791                 cmp     [ebp+msg_len], 0Fh ; cmd_len <= sizeof(LSPCON_heci_command_header_t)
.text:00107795                 ja      short is_cmd_id_in_heci_range
```

It begins by verifying the command buffer is big enough to fit the LSPCON HECI command header:
```nasm
00000000 LSPCON_heci_command_header_t struc ; (sizeof=0x10, mappedto_125)
00000000                                         ; XREF: LSPCON_HECICMD_PLAYBACK_DONE_IN/r
00000000                                         ; LSPCON_HECICMD_PLAYBACK_DONE_OUT/r ...
00000000 version         dd ?
00000004 cmdid           dd ?                    ; XREF: LSPCON_command_handler:is_cmd_id_in_heci_range/r
00000008 status          dd ?
0000000C size            dd ?                    ; XREF: LSPCON_command_handler+6B/w
0000000C                                         ; LSPCON_command_handler+91/w ...
00000010 LSPCON_heci_command_header_t ends
```

Next it checks the command is one of the 7 LSPCON HECI commands and retreives appropriate handler from a global handler list:

```nasm
.text:001077B8 is_cmd_id_in_heci_range:                ; CODE XREF: LSPCON_command_handler+3A↑j
.text:001077B8                 mov     edi, [cmd+LSPCON_heci_command_header_t.cmdid]
.text:001077BB                 lea     eax, [edi-0E000h] ; is 0xE000 < id < 0xE008
.text:001077C1                 cmp     eax, 7
.text:001077C4                 jbe     short get_handler
                               ...
.text:001077D4 get_handler:                            ; CODE XREF: LSPCON_command_handler+69↑j
.text:001077D4                 mov     edx, dword ptr ds:gLSPCONCmdHandlerTable[eax*8] ; gLSPCONCmdHandlerTable.HandleFunc
.text:001077DB                 test    edx, edx        ; EDX contains handler
.text:001077DD                 jnz     short check_cmd_data
```

The global list looks something like:

```c
gLSPCONCmdHandlerTable[] = {
      { 0 },
      { LSPCON_get_status,             sizeof(LSPCON_HECICMD_GET_LSPCON_STATUS_IN),    sizeof(LSPCON_HECICMD_GET_LSPCON_STATUS_OUT)},
      { LSPCON_set_dev_cert,           sizeof(LSPCON_HECICMD_SET_LSPCON_CERT_IN),      sizeof(LSPCON_HECICMD_SET_LSPCON_CERT_OUT)},
      { LSPCON_init_session,           sizeof(LSPCON_HECICMD_INIT_SESSION_IN),         sizeof(LSPCON_HECICMD_INIT_SESSION_OUT)},
      { LSPCON_init_limits,            sizeof(LSPCON_HECICMD_INIT_LIMITS_IN),          sizeof(LSPCON_HECICMD_INIT_LIMITS_OUT)},
      { LSPCON_playback_done,          sizeof(LSPCON_HECICMD_PLAYBACK_DONE_IN),        sizeof(LSPCON_HECICMD_PLAYBACK_DONE_OUT)},
      { LSPCON_ack,                    sizeof(LSPCON_HECICMD_MSG_ACK_IN),              sizeof(LSPCON_HECICMD_MSG_ACK_OUT)},
      { LSPCON_get_topology,           sizeof(LSPCON_HECICMD_GET_TOPOLOGY_IN),         sizeof(LSPCON_HECICMD_GET_TOPOLOGY_OUT)},
  };
  ```
  
After verifying the size of the input and output structs the actual command handle is called.

```nasm
.text:001077FD
.text:001077FD check_cmd_data:                         ; CODE XREF: LSPCON_command_handler+82↑j
.text:001077FD                 movzx   edi, word ptr ds:unk_82364[eax*8] ; gLSPCONCmdHandlerTable.InputSize
.text:00107805                 cmp     edi, [ebp+msg_len]
.text:00107808                 ja      short sizes_error
.text:0010780A                 movzx   eax, word ptr ds:unk_82366[eax*8] ; gLSPCONCmdHandlerTable.OutputSize
.text:00107812                 cmp     eax, [ebp+var_14]
.text:00107815                 ja      short sizes_error
                               ...
.text:00107830
.text:00107830 loc_107830:                             ; CODE XREF: LSPCON_command_handler+C5↑j
.text:00107830                 push    cmd
.text:00107831                 push    ecx
                               ...
.text:00107846                 call    edx             ; Call Command Handler!
```

Reveresing all the command handlers we find something interesting in the most unexpected one (thus the last I REd): `LSPCON_playback_done()`. It took me a while to even understand its releated to the GuC, and I'll explain later how it does so.

What does `LSPCON_playback_done` do? It checks whether HDCP restrictions should remain in place after a playback is complete.

The function begins by verifying the input parameter (LSPCON_HECICMD_PLAYBACK_DONE_IN) is valid:

```nasm
.text:00107C6B ; int __cdecl LSPCON_playback_done(PavpCtx *ctx, void *msg)
.text:00107C6B LSPCON_playback_done proc near
.text:00107C6B
.text:00107C6B cur_hdcp_requirements= dword ptr -18h
.text:00107C6B count_active_sessions= dword ptr -14h
.text:00107C6B var_10          = dword ptr -10h
.text:00107C6B ctx             = dword ptr  8
.text:00107C6B msg             = dword ptr  0Ch
.text:00107C6B
.text:00107C6B ctx_ptr = edi
.text:00107C6B                 push    ebp
.text:00107C6C                 mov     ebp, esp
.text:00107C6E                 push    ctx_ptr
.text:00107C6F                 push    esi
.text:00107C70                 push    ebx
.text:00107C71                 sub     esp, 0Ch
.text:00107C74                 mov     [ebp+count_active_sessions], 0
.text:00107C7B                 mov     esi, [ebp+msg]
.text:00107C7E                 mov     eax, ds:stack_cookie_ptr
.text:00107C83                 mov     [ebp+var_10], eax
.text:00107C86                 xor     eax, eax
.text:00107C88                 mov     ctx_ptr, [ebp+ctx]
.text:00107C8B                 test    esi, esi
.text:00107C8D                 jnz     short check_valid_header
                               ...
.text:00107C99 check_valid_header:                     ; CODE XREF: LSPCON_playback_done+22↑j
.text:00107C99                 mov     [esi+LSPCON_HECICMD_PLAYBACK_DONE_IN.header.size], 0
.text:00107CA0                 test    ctx_ptr, ctx_ptr
.text:00107CA2                 jz      short invalid_parameter
.text:00107CA4                 cmp     [ctx_ptr+PavpCtx.Lspcon], 0
.text:00107CA8                 jz      short invalid_parameter
```

And now comes the interesting part:

```nasm
.text:00107CAA                 lea     eax, [ebp+count_active_sessions]
.text:00107CAD                 push    eax             ; num_active_sessions
.text:00107CAE                 push    0               ; type
.text:00107CB0                 push    ctx_ptr         ; ctx
.text:00107CB1                 call    GUC_get_active_sessions ; 
.text:00107CB6                 add     esp, 0Ch
.text:00107CB9                 mov     ebx, eax
.text:00107CBB                 test    eax, eax
.text:00107CBD                 jz      short got_active_sessions
```

If there are any remaining active sessions the code continues to check what level of HDCP protection they require and set protection to that level if it is lower then the current level, I won't go into that disassembly as its not really interesting.

Why do I think `GUC_get_active_sessions` is actually related to GuC and why did I name it that? Lets continue by examining this function. Its just a wrapper around a function I called `GUC_send_message` that sends message no. 6, 

```nasm
.text:0010452C ; int __cdecl GUC_get_active_sessions(PavpCtx *ctx, int type, unsigned int *num_active_sessions)
.text:0010452C GUC_get_active_sessions proc near       ; CODE XREF: LSPCON_playback_done+46↓p
.text:0010452C
.text:0010452C guc2csme        = GUC2CSME_MSG ptr -18h
.text:0010452C csme2guc        = CSME2GUC_MSG ptr -10h
.text:0010452C ctx             = dword ptr  8
.text:0010452C type            = dword ptr  0Ch
.text:0010452C num_active_sessions= dword ptr  10h
.text:0010452C
.text:0010452C ctx_ptr = esi
                               ...
.text:0010455B type_ok:
.text:0010455B                 mov     dword ptr [ebp+csme2guc.command], GUC_MSG_GET_ACTIVE_SESSIONS ; =6
.text:00104562                 mov     [ebp+csme2guc.data1], al
.text:00104565                 lea     eax, [ebp+guc2csme.value]
.text:00104568                 mov     [ebp+guc2csme.value], 0
.text:0010456F                 push    eax             ; guc2csme
.text:00104570                 lea     eax, [ebp+csme2guc]
.text:00104573                 push    eax             ; csme2guc
.text:00104574                 push    ctx_ptr         ; ctx
.text:00104575                 call    GUC_send_message
```

GUC_send_message() gets two parameters in addition to the PAVP context: a CSME2GUC structure and a GUC2CSME structure. How does it work?
It tries to send the message several times in a loop, each time waiting for a short timeout. The first iteration of the loop also wakes the GuC by enabling it through managment functions (if it isn't already enabled), and sending a special wake message using a function I named `GUC_send_VDM()`.

```nasm
.text:001041FF ; int __cdecl GUC_send_message(PavpCtx *ctx, CSME2GUC_MSG *csme2guc, GUC2CSME_MSG *guc2csme)
.text:001041FF GUC_send_message proc near              ; CODE XREF: GUC_get_active_sessions+49↓p
.text:001041FF                                         ; sub_1045C5+3F↓p
.text:001041FF
.text:001041FF ctx             = dword ptr  8
.text:001041FF csme2guc        = dword ptr  0Ch
.text:001041FF guc2csme        = dword ptr  10h
.text:001041FF
.text:001041FF attempt = esi
.text:001041FF ctx_ptr = ebx
.text:001041FF                 push    ebp
.text:00104200                 mov     ebp, esp
.text:00104202                 push    edi
.text:00104203                 push    attempt
.text:00104204                 xor     attempt, attempt
.text:00104206                 push    ctx_ptr
.text:00104207                 mov     ctx_ptr, [ebp+ctx]
.text:0010420A
.text:0010420A send_loop:                              ; CODE XREF: GUC_send_message+A3↓j
.text:0010420A                 inc     attempt
.text:0010420B                 cmp     attempt, 1
.text:0010420E                 jnz     short send_wake_msg_loop
.text:00104210
.text:00104210 first_attempt:
.text:00104210                 push    ctx_ptr
.text:00104211                 call    GUC_disable_power_gate?
.text:00104216                 mov     edi, eax
.text:00104218                 pop     eax
.text:00104219                 test    edi, edi
.text:0010421B                 jnz     loc_1042A8
.text:00104221
.text:00104221 send_wake_msg_loop:                     ; CODE XREF: GUC_send_message+F↑j
.text:00104221                                         ; GUC_send_message+4E↓j
.text:00104221                 push    VDM_CSME_TO_GUC_WAKE_REQ
.text:00104223                 push    0               ; msg
.text:00104225                 push    ctx_ptr
.text:00104226                 call    GUC_send_VDM    ; VDM == Vendor Defined Message?
.text:0010422B                 add     esp, 0Ch
.text:0010422E                 mov     edi, eax
.text:00104230                 test    eax, eax
.text:00104232                 jnz     msg_error
.text:00104238                 push    [ebp+guc2csme]
.text:0010423B                 push    GUC_IS_AWAKE
.text:0010423D                 push    ctx_ptr
.text:0010423E                 call    GUC_wait_for_message ; wait for GUC is awake message
.text:00104243                 add     esp, 0Ch
.text:00104246                 mov     edi, eax
.text:00104248                 cmp     eax, PAVP_STATUS_TRY_AGAIN
.text:0010424D                 jz      short send_wake_msg_loop
.text:0010424F                 cmp     eax, PAVP_STATUS_TIMEOUT
.text:00104254                 jnz     short got_awake_msg
.text:00104256
.text:00104256 timeout:                                ; CODE XREF: GUC_send_message+92↓j
.text:00104256                                         ; GUC_send_message+C9↓j
.text:00104256                 mov     edi, PAVP_STATUS_TIMEOUT
.text:0010425B                 jmp     short loc_104297
.text:0010425D ; ---------------------------------------------------------------------------
.text:0010425D
```

Once the GuC awake message was received the actually GuC message is send, again with `GUC_send_VDM()`.

```nasm
.text:0010425D got_awake_msg:                          ; CODE XREF: GUC_send_message+55↑j
.text:0010425D                 test    eax, eax
.text:0010425F                 jnz     short loc_1042A8
.text:00104261                 mov     eax, [ebp+csme2guc]
.text:00104264                 push    VDM_FROM_CSME
.text:00104266                 push    dword ptr [eax+CSME2GUC_MSG.command]
.text:00104268                 push    ctx_ptr
.text:00104269                 call    GUC_send_VDM
.text:0010426E                 add     esp, 0Ch
.text:00104271                 mov     edi, eax
.text:00104273                 test    eax, eax
.text:00104275                 jnz     short loc_1042A8
.text:00104277                 push    [ebp+guc2csme]
.text:0010427A                 mov     eax, [ebp+csme2guc]
.text:0010427D                 movzx   eax, [eax+CSME2GUC_MSG.command]
.text:00104280                 push    eax
.text:00104281                 push    ctx_ptr
.text:00104282                 call    GUC_wait_for_message
```

Its then waits for the return message ```GUC_wait_for_message()```.
Now you have to say - Wise guy, how do you know this is actually releated to GuC? What is this VDM stuff? Did *Ded Moroz* drop them in your cabin?

**VDM**s are *Vendor Defined Messages*, a way to send custom messages to devices over a PCI bus. They are sent through IOCTLs to the VDM driver in CSME. The IOCTL gets data through a message:

```nasm
00000000 IOCTL_VDM_WRITE struc ; (sizeof=0x12, mappedto_145)
00000000 addr_offset     dd ?
00000004 data            dd ?          ; This is a bitfield per the spec
00000008 info            VDM_TX ?
00000012 IOCTL_VDM_WRITE ends
```

```nasm
00000000 VDM_TX          struc ; (sizeof=0xA, mappedto_142)
00000000                                         ; XREF: GucCtx/r
00000000                                         ; IOCTL_VDM_WRITE/r
00000000 msg             dd ?                    ; XREF: setup_guc_vdm+F/r
00000004 pci_req_id      dw ?                    ; XREF: setup_guc_vdm+12/w
00000006 tag             dw ?
00000008 pci_tgt_id      dw ?                    ; XREF: setup_guc_vdm+1C/w
0000000A VDM_TX          ends
```

Here you have the first hint of how I connected all this to the GuC. Lets just get the VDM function out of the way:

```nasm
.text:0014889D VDM_write       proc near               ; CODE XREF: sub_1028DB+CE↑p
.text:0014889D                                         ; GUC_send_VDM+4F↑p ...
.text:0014889D
.text:0014889D var_40          = byte ptr -40h
.text:0014889D vdm_ioctl       = IOCTL_VDM_WRITE ptr -3Ch
.text:0014889D var_10          = dword ptr -10h
.text:0014889D fd              = dword ptr  8
.text:0014889D addr_info       = dword ptr  0Ch
.text:0014889D addr_offset     = dword ptr  10h
.text:0014889D data            = dword ptr  14h
.text:0014889D
.text:0014889D                 push    ebp
.text:0014889E                 mov     ebp, esp
.text:001488A0                 push    edi
.text:001488A1                 push    esi
.text:001488A2                 push    ebx
.text:001488A3                 sub     esp, 34h
.text:001488A6                 mov     ebx, [ebp+fd]
.text:001488A9                 mov     eax, ds:stack_cookie_ptr
.text:001488AE                 mov     [ebp+var_10], eax
.text:001488B1                 xor     eax, eax
.text:001488B3                 mov     edi, [ebp+addr_info]
.text:001488B6                 test    ebx, ebx
.text:001488B8                 js      short invalid_parameter
.text:001488BA                 test    edi, edi
.text:001488BC                 jz      short invalid_parameter
.text:001488BE                 lea     esi, [ebp+vdm_ioctl]
.text:001488C1
.text:001488C1 build_ioctl_data:
.text:001488C1                 push    44 ; sizeof(vdm_ioctl)
.text:001488C3                 push    0
.text:001488C5                 push    esi
.text:001488C6                 call    near ptr memset
.text:001488CB                 mov     eax, [ebp+addr_offset]
.text:001488CE                 mov     [ebp+vdm_ioctl.addr_offset], eax
.text:001488D1                 mov     eax, [ebp+data]
.text:001488D4                 mov     [ebp+vdm_ioctl.data], eax
.text:001488D7                 lea     eax, [ebp+vdm_ioctl.info]
.text:001488DA                 push    0Ah             ; sizeof(TX info)
.text:001488DC                 push    edi
.text:001488DD                 push    0Ah
.text:001488DF                 push    eax
.text:001488E0                 call    near ptr memcpy_s
.text:001488E5                 lea     eax, [ebp+var_40]
.text:001488E8                 push    eax
.text:001488E9                 push    44
.text:001488EB                 push    esi
.text:001488EC                 push    44
.text:001488EE                 push    esi
.text:001488EF                 push    2        ; IOCTL write
.text:001488F1                 push    ebx
.text:001488F2                 call    near ptr ioctl_s
```

The IOCTL is sent to a file handle. Where is it set? We now go back to the PAVP init code and look for all places where file handles are init. There we find to functions I am pretty sure initialize the GuC and the Graphics Key Manager (GKM), thus I appropriatly named them `GUC_init()` and `GKM_init()` (I keep reminding you I named these functions as I have no clue what is their realy name, these are my *guesses*).

As usual, the function begins by checking it\'s input argument:

```nasm
.text:001043C3 GUC_init        proc near               ; CODE XREF: pavp_init+259↑p
.text:001043C3
.text:001043C3 ctx             = dword ptr  8
.text:001043C3
.text:001043C3 ctx_ptr = ebx
.text:001043C3                 push    ebp
.text:001043C4                 mov     ebp, esp
.text:001043C6                 push    esi
.text:001043C7                 push    ctx_ptr
.text:001043C8                 mov     esi, 1005h
.text:001043CD                 mov     ctx_ptr, [ebp+ctx]
.text:001043D0                 test    ctx_ptr, ctx_ptr
.text:001043D2                 jz      invalid_paramter
.text:001043D8                 cmp     [ctx_ptr+PavpCtx.guc_ctx], 0
.text:001043DC                 jnz     invalid_paramter
```

Next it allocates a context for GuC operations:

```nasm
.text:001043E2                 push    90 ; sizeof(GucContext
.text:001043E4                 push    1
.text:001043E6                 call    near ptr calloc ; allocate GucContext (0x5A bytes)
.text:001043EB                 mov     [ctx_ptr+PavpCtx.guc_ctx], eax
.text:001043EE                 test    eax, eax
.text:001043F0                 pop     esi
.text:001043F1                 pop     edx
.text:001043F2                 jnz     short alloc_ok  ; start with no FD
```

The struct itself:
```nasm
00000000 GucCtx          struc ; (sizeof=0x5A, mappedto_140)
00000000 vdm_file_descriptor dd ?                ; XREF: GUC_init:alloc_ok/w
00000000                                         ; GUC_init+5C/w ...
00000004 pg_timer        Timer ?
00000028 watchdog        Timer ?                 ; XREF: GUC_command_handler+8C/o
0000004C vdm             VDM_TX ?                ; XREF: GUC_init:loc_104441/o
00000056 state           dd ?                    ; XREF: GUC_pg_timer_routine+39/w
00000056                                         ; GUC_init+127/w
0000005A GucCtx          ends
```

It first checks if a file descriptor has already been setup by the Graphics Key Manager, and if so uses the same file descriptor - apparently they share the same VDM channel. Otherwise a new FD is setup in setup_guc_vdm(). The rest of the code initializes two timers - one related to some kind of watchdog and the other to power managment.

```nasm
.text:0010440C
.text:0010440C alloc_ok:                               ; CODE XREF: GUC_init+2F↑j
.text:0010440C                 mov     [eax+GucCtx.vdm_file_descriptor], 0FFFFFFFFh ; start with no FD
.text:00104412                 mov     eax, [ctx_ptr+PavpCtx.graphic_key_mgr]
.text:00104415                 test    eax, eax
.text:00104417                 jz      short no_gkm
.text:00104419                 mov     edx, [ctx_ptr+PavpCtx.guc_ctx]
.text:0010441C                 mov     eax, [eax+GkmCtx.vdm_file_descriptor]
.text:0010441F                 mov     [edx+GucCtx.vdm_file_descriptor], eax
.text:00104421
.text:00104421 no_gkm:                                 ; CODE XREF: GUC_init+54↑j
.text:00104421                 mov     eax, [ctx_ptr+PavpCtx.guc_ctx]
.text:00104424                 cmp     [eax+GucCtx.vdm_file_descriptor], 0
.text:00104427                 jns     short loc_104441
.text:00104429                 push    4B00FDh
.text:0010442E                 mov     esi, 100Eh
.text:00104433                 push    2
.text:00104435                 call    near ptr log_printf_0
.text:0010443A                 pop     eax
.text:0010443B                 pop     edx
.text:0010443C                 jmp     invalid_paramter
.text:00104441 ; ---------------------------------------------------------------------------
.text:00104441
.text:00104441 loc_104441:                             ; CODE XREF: GUC_init+64↑j
.text:00104441                 add     eax, GucCtx.vdm
.text:00104444                 push    eax
.text:00104445                 call    setup_guc_vdm
.text:0010444A                 mov     esi, eax
```

And this is the part we have been waiting for:
```nasm
.text:00102810 setup_guc_vdm   proc near               ; CODE XREF: GKM_init+2D↓p
.text:00102810                                         ; GUC_init+82↓p
.text:00102810
.text:00102810 vdm             = dword ptr  8
.text:00102810
.text:00102810 vdm_ptr = edx
.text:00102810                 push    ebp
.text:00102811                 mov     eax, 1005h
.text:00102816                 mov     ebp, esp
.text:00102818                 mov     vdm_ptr, [ebp+vdm]
.text:0010281B                 test    vdm_ptr, vdm_ptr
.text:0010281D                 jz      short loc_10284A
.text:0010281F                 mov     al, byte ptr [vdm_ptr+(VDM_TX.msg+3)]
.text:00102822                 mov     dword ptr [vdm_ptr+VDM_TX.pci_req_id], 0B0h ; CSME: bus: 0, device: 22, function 0
.text:00102829                 or      eax, 7
.text:0010282C                 mov     [vdm_ptr+VDM_TX.pci_tgt_id], 10h ; GUC: buf: 0, device: 2, function 0
.text:00102832                 and     eax, 0FFFFFF8Fh
.text:00102835                 mov     byte ptr [vdm_ptr], 0D3h
.text:00102838                 mov     [vdm_ptr+3], al
.text:0010283B                 mov     al, [vdm_ptr+2]
.text:0010283E                 or      byte ptr [vdm_ptr+1], 0Fh
.text:00102842                 and     eax, 0FFFFFF80h
.text:00102845                 mov     [vdm_ptr+2], al
.text:00102848                 xor     eax, eax
.text:0010284A
.text:0010284A loc_10284A:                             ; CODE XREF: setup_guc_vdm+D↑j
.text:0010284A                 pop     ebp
.text:0010284B                 retn
.text:0010284B setup_guc_vdm   endp
```

Here we have the internal bus IDs for the GuC and CSME.

Results are retrieved using `GUC_wait_for_message()` - it uses `select()` to wait on the VDM file handle and parses the message.
Something interesting I found out it that messages are not initiated only by the CSME - the GuC can initiate messages to the CSME and the CSME responds. GUC_wait_for_message() uses a handler table with 11 entries, but 4 are NULL.

For example, one message I decoded gets some production information for the chip:

```nasm
.text:00103EDA GUC_api_get_production_info proc near
.text:00103EDA
.text:00103EDA var_14          = byte ptr -14h
.text:00103EDA var_13          = byte ptr -13h
.text:00103EDA var_E           = byte ptr -0Eh
.text:00103EDA var_D           = byte ptr -0Dh
.text:00103EDA var_C           = dword ptr -0Ch
.text:00103EDA ctx             = dword ptr  8
.text:00103EDA
.text:00103EDA ctx_ptr = esi
.text:00103EDA                 push    ebp
.text:00103EDB                 mov     ebp, esp
.text:00103EDD                 push    ctx_ptr
.text:00103EDE                 push    ebx
.text:00103EDF                 sub     esp, 0Ch
.text:00103EE2                 mov     [ebp+var_14], 0
.text:00103EE6                 mov     ctx_ptr, [ebp+ctx]
.text:00103EE9                 mov     eax, ds:stack_cookie_ptr
.text:00103EEE                 mov     [ebp+var_C], eax
.text:00103EF1                 xor     eax, eax
.text:00103EF3                 push    ctx_ptr
.text:00103EF4                 call    GUC_enable_power_gate
.text:00103EF9                 lea     eax, [ebp+var_14]
.text:00103EFC                 push    eax
.text:00103EFD                 call    test_byte_12h_from_snowball_rbe_sku
.text:00103F02                 pop     ecx
.text:00103F03                 test    eax, eax
.text:00103F05                 pop     ebx
.text:00103F06                 mov     ebx, 109h
.text:00103F0B                 jnz     short loc_103F48
.text:00103F0D                 mov     ebx, 9
.text:00103F12                 cmp     [ebp+var_14], 0
.text:00103F16                 jnz     short loc_103F48
.text:00103F18                 lea     eax, [ebp+var_13]
.text:00103F1B                 mov     ebx, 109h
.text:00103F20                 push    eax
.text:00103F21                 call    get_7_bytes_from_snowball_rbe_sku
.text:00103F26                 pop     edx
.text:00103F27                 test    eax, eax
.text:00103F29                 jnz     short loc_103F48
.text:00103F2B                 mov     bl, [ebp+var_E]
.text:00103F2E                 mov     al, [ebp+var_D]
.text:00103F31                 shr     bl, 2           ; actuall data from CPUs looks like production year & week
.text:00103F34                 and     eax, 0Fh
.text:00103F37                 shl     eax, 9
.text:00103F3A                 and     ebx, 3Fh
.text:00103F3D                 shl     ebx, 0Dh
.text:00103F40                 or      ebx, 109h
.text:00103F46                 or      ebx, eax
.text:00103F48
.text:00103F48 loc_103F48:                             ; CODE XREF: GUC_api_get_production_info+31↑j
.text:00103F48                                         ; GUC_api_get_production_info+3C↑j ...
.text:00103F48                 push    ctx_ptr
.text:00103F49                 call    GUC_enable_power_gate
.text:00103F4E                 push    2
.text:00103F50                 push    ebx
.text:00103F51                 push    ctx_ptr
.text:00103F52                 call    GUC_send_VDM
.text:00103F57                 mov     edx, [ebp+var_C]
.text:00103F5A                 xor     edx, ds:stack_cookie_ptr
.text:00103F60                 jz      short loc_103F67
.text:00103F62                 call    near ptr __stkchk
.text:00103F67
.text:00103F67 loc_103F67:                             ; CODE XREF: GUC_api_get_production_info+86↑j
.text:00103F67                 lea     esp, [ebp-8]
.text:00103F6A                 pop     ebx
.text:00103F6B                 pop     ctx_ptr
.text:00103F6C                 pop     ebp
.text:00103F6D                 retn
.text:00103F6D GUC_api_get_production_info endp
```

Why do I think this is related to production information? Because it reads data from a file called \"/snowball/rbe_sku\" (Intel's name!).
I don't have any idea what *Snowball* means, RBE usualy means *ROM Boot Extenion*, so it reads data from the ROM?
The actuall data from a few processors appears to be correlated to production year and work week for the CPU.

```nasm
.text:00148AF7 test_byte_12h_from_snowball_rbe_sku proc near
.text:00148AF7                                         ; CODE XREF: pavp_init+10A↑p
.text:00148AF7                                         ; GUC_api_get_production_info+23↑p ...
.text:00148AF7
.text:00148AF7 buffer          = byte ptr -24h
.text:00148AF7 stack_cookie    = dword ptr -8
.text:00148AF7 var_4           = dword ptr -4
.text:00148AF7 out_byte_12h    = dword ptr  8
.text:00148AF7
.text:00148AF7                 push    ebp
.text:00148AF8                 mov     ebp, esp
.text:00148AFA                 push    ebx
.text:00148AFB                 sub     esp, 20h
.text:00148AFE                 mov     eax, ds:stack_cookie_ptr
.text:00148B03                 mov     [ebp+stack_cookie], eax
.text:00148B06                 xor     eax, eax
.text:00148B08                 lea     eax, [ebp+buffer]
.text:00148B0B                 push    1Ch
.text:00148B0D                 mov     ebx, [ebp+out_byte_12h]
.text:00148B10                 push    eax
.text:00148B11                 push    offset aSnowballRbeSku_0 ; "/snowball/rbe_sku"
.text:00148B16                 call    read_file_completely
.text:00148B1B                 add     esp, 0Ch
.text:00148B1E                 test    eax, eax
.text:00148B20                 jnz     short loc_148B2A
.text:00148B22                 mov     dl, [ebp+buffer+12h]
.text:00148B25                 and     edx, 1
.text:00148B28                 mov     [ebx], dl
.text:00148B2A
.text:00148B2A loc_148B2A:                             ; CODE XREF: test_byte_12h_from_snowball_rbe_sku+29↑j
.text:00148B2A                 mov     ecx, [ebp+stack_cookie]
.text:00148B2D                 xor     ecx, ds:stack_cookie_ptr
.text:00148B33                 jz      short loc_148B3A
.text:00148B35                 call    near ptr __stkchk
.text:00148B3A
.text:00148B3A loc_148B3A:                             ; CODE XREF: test_byte_12h_from_snowball_rbe_sku+3C↑j
.text:00148B3A                 mov     ebx, [ebp+var_4]
.text:00148B3D                 leave
.text:00148B3E                 retn
.text:00148B3E test_byte_12h_from_snowball_rbe_sku endp

.text:00148A54 read_file_completely proc near          ; CODE XREF: get_7_bytes_from_snowball_rbe_sku+21↓p
.text:00148A54                                         ; test_byte_12h_from_snowball_rbe_sku+1F↓p ...
.text:00148A54
.text:00148A54 filename        = dword ptr  8
.text:00148A54 buffer          = dword ptr  0Ch
.text:00148A54 byte_count      = dword ptr  10h
.text:00148A54
.text:00148A54                 push    ebp
.text:00148A55                 mov     ebp, esp
.text:00148A57                 push    edi
.text:00148A58                 push    esi
.text:00148A59                 push    ebx
.text:00148A5A                 push    0
.text:00148A5C count = esi
.text:00148A5C                 mov     count, [ebp+byte_count]
.text:00148A5F
.text:00148A5F open_file:
.text:00148A5F                 push    [ebp+filename]
.text:00148A62                 call    near ptr open
.text:00148A67 file_handle = ebx
.text:00148A67                 mov     file_handle, eax
.text:00148A69                 pop     eax
.text:00148A6A                 test    file_handle, file_handle
.text:00148A6C                 pop     edx
.text:00148A6D                 mov     eax, 222
.text:00148A72                 js      short loc_148A98
.text:00148A74
.text:00148A74 read_file:
.text:00148A74                 push    count
.text:00148A75                 push    [ebp+buffer]
.text:00148A78                 push    file_handle
.text:00148A79                 call    near ptr read
.text:00148A7E
.text:00148A7E close_file:
.text:00148A7E                 push    file_handle
.text:00148A7F                 mov     edi, eax
.text:00148A81                 call    near ptr close
.text:00148A86                 add     esp, 10h
.text:00148A89                 test    edi, edi
.text:00148A8B                 js      short loc_148A93
.text:00148A8D                 xor     eax, eax
.text:00148A8F                 cmp     edi, count
.text:00148A91                 jz      short loc_148A98
.text:00148A93
.text:00148A93 loc_148A93:                             ; CODE XREF: read_file_completely+37↑j
.text:00148A93                 mov     eax, 99
.text:00148A98
.text:00148A98 loc_148A98:                             ; CODE XREF: read_file_completely+1E↑j
.text:00148A98                                         ; read_file_completely+3D↑j
.text:00148A98                 lea     esp, [ebp-0Ch]
.text:00148A9B                 pop     ebx
.text:00148A9C                 pop     esi
.text:00148A9D                 pop     edi
.text:00148A9E                 pop     ebp
.text:00148A9F                 retn
.text:00148A9F read_file_completely endp
```
## Conclusion
I am still actively working on this to see what attack surfaces there are from GuC->CSME and CSME->GuC, but it looks like Intel did a really good job checking bounds and arguments. The Graphics Key Manager is next in the queue, it look like the surface there is more promising.

There is also a lot more to decode in PAVP, I only decoded a small part of the context structure:
```nasm
PavpCtx         struc ; (sizeof=0x80, mappedto_123)
00000000 field_0         dd ?
00000004 field_4         dd ?
00000008 heci_client     dd ?
0000000C server_ctx      dd ?
00000010 graphic_key_mgr dd ?                    ; XREF: GUC_init+4F/r
00000014 vkm             dd ?
00000018 guc_ctx         dd ?                    ; XREF: GUC_pg_timer_routine+32/r
00000018                                         ; GUC_disable_power_gate?+1E/r ...
0000001C Lspcon          dd ?                    ; XREF: LSPCON_command_handler+22/r
0000001C                                         ; LSPCON_playback_done+39/r ...
00000020 field_20        dd ?
00000024 timer_ctx       dd ?                    ; XREF: GUC_disable_power_gate?+56/r
00000024                                         ; GUC_command_handler+90/r ... ; struct offset (PavpPortConfig)
00000028 field_28        dd ?
0000002C port_cfg        PavpPortConfig ?
00000044 field_44        dd ?
00000048 field_48        dd ?
0000004C field_4C        dd ?
00000050 field_50        dd ?
00000054 handlers        dd ?                    ; XREF: GUC_command_handler+29/r
00000058 field_58        dd ?
0000005C field_5C        dd ?
00000060 field_60        dd ?
00000064 field_64        dd ?
00000068 field_68        dd ?
0000006C field_6C        dd ?
00000070 field_70        dd ?
00000074 field_74        dd ?
00000078 field_78        dd ?
0000007C field_7C        dd ?
00000080 PavpCtx         ends
```

Enough for today, especially as my day job has warmed up a bit in the last three weeks - more on that later! I promise it will be very interesting (but not hardware related).


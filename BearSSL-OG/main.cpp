#include "stdafx.h"

#include "network_utility.h"
#include "client.h"
#include "server.h"
#include "debug_utility.h"
#include "data_store.h"

bool mount_e_drive()
{
	char* mountPoint = "\\??\\E:";
	char* systemPath = "\\Device\\Harddisk0\\Partition1";
	STRING sMountPoint = {(USHORT)strlen(mountPoint), (USHORT)strlen(mountPoint) + 1, mountPoint};
	STRING sSystemPath = {(USHORT)strlen(systemPath), (USHORT)strlen(systemPath) + 1, systemPath};
	int result = IoCreateSymbolicLink(&sMountPoint, &sSystemPath);
	return result == 0;
}

void __cdecl main()
{
	if (network_utility::init() == false)
	{
		return;
	}

	if (network_utility::wait_ready() == false)
	{
		return;
	}

	mount_e_drive();

	uint16_t port = 443;

	//const char* url = "https://codeload.github.com/Team-Resurgent/PrometheOS-Firmware/archive/refs/tags/V1.5.0.zip";
	const char* url = "https://codeload.github.com/Team-Resurgent/PrometheOS-Firmware/zip/refs/tags/V1.5.0";
	const char* file_path = "E:\\testfile.bin";

	//With Redirect
	//const char* url = "https://github.com/Team-Resurgent/Modxo/releases/download/V1.0.8/modxo_official_pico.bin";
	//const char* file_path = "E:\\modxo_official_pico.bin";

	//Chunked (saves as webp)
	//const char* url = "https://www.etechnophiles.com/wp-content/uploads/2021/02/pinout_923x768.jpg";
	//const char* file_path = "E:\\pinout_923x768.webp";

	//Non Chunked
	//const char* url = "https://download.winamp.com/winamp/winamp_latest_full.exe";
	//const char* file_path = "E:\\winamp_latest_full.exe";

	client* client_instance = new client();
	//client_instance->download_file(url, port, file_path);
	
	server* server_instance = new server();
	server_instance->start(443);

	while (true) 
	{
		Sleep(100);
	}
}



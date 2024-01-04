#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "protocol.h"
#include "pkt_handler.h"

#ifdef _WIN32
#include <tchar.h>

BOOL LoadNpcapDlls() // Npcap을 설치했는지 확인하는 함수
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

int get_modenum();

int main()
{
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls()) // Npcap이 설치되지 않았으면 종료
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	printf("====================== Intrusion Detection Tool ======================\n");

	int b_open = 1;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* fp;

	while (1) {
		printf("[1] Offline\n[2] Live\n[3] Exit\n");
		printf("Enter the mode: ");

		switch (get_modenum())
		{
		case 1:
			{
				char pcap_file_path[MAX_PATH + _MAX_FNAME];

				printf("Enter pcap file path: ");
				scanf_s("%s", pcap_file_path, MAX_PATH + _MAX_FNAME);

				/* Open the capture file */
				if ((fp = pcap_open_offline(pcap_file_path, errbuf)) == NULL)
				{
					printf("\nUnable to open the file: %s.\n", pcap_file_path);
					b_open = 0;
				}
				break;
			}
		case 2:
			{
				pcap_if_t* alldevs;
				pcap_if_t* d;
				int inum;
				int i = 0;

				/* Retrieve the device list */
				if (pcap_findalldevs(&alldevs, errbuf) == -1) // Device 확인
				{
					printf("Error in pcap_findalldevs: %s\n", errbuf);
					b_open = 0;
				}

				/* Print the list */
				for (d = alldevs; d; d = d->next) // Device list 나열
				{
					printf("%d. %s", ++i, d->name);
					if (d->description)
						printf(" (%s)\n", d->description);
					else
						printf(" (No description available)\n");
				}

				if (i == 0)
				{
					printf("\nNo interfaces found! Make sure Npcap is installed.\n");
					b_open = 0;
				}

				printf("Enter the interface number (1-%d):", i);
				scanf_s("%d", &inum, 1);

				if (inum < 1 || inum > i)
				{
					printf("\nInterface number out of range.\n");
					/* Free the device list */
					pcap_freealldevs(alldevs);
					b_open = 0;
				}

				/* Jump to the selected adapter */
				for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

				/* Open the device */
				/* Open the adapter */
				if ((fp = pcap_open_live(d->name,	// name of the device
									65536,			// portion of the packet to capture. 
													// 65536 grants that the whole packet will be captured on all the MACs.
									1,				// promiscuous mode (nonzero means promiscuous)
									1000,			// read timeout
									errbuf			// error buffer
								)) == NULL)
				{
					printf("\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
					/* Free the device list */
					pcap_freealldevs(alldevs);
					b_open = 0;
				}

				printf("\nlistening on %s...\n", d->description);

				/* At this point, we don't need any more the device list. Free it */
				pcap_freealldevs(alldevs);
				break;
			};
		case 3:
			{
				printf("============================== The End ===============================\n");
				system("pause");
				return 0;
			}
		default:
			printf("Invalid Mode Number.\n");
		}
		if (b_open == 0) continue;

		char log_file_path[MAX_PATH + _MAX_FNAME] = "log.txt";
		FILE* log_file = fopen(log_file_path, "w");

		/* start the capture */
		pcap_loop(fp, 0, packet_handler, (u_char*)log_file);

		pcap_close(fp);
		fclose(log_file);
	}
}

int get_modenum()
{
	int mode_num;

	scanf_s("%d", &mode_num, 1);

	if (mode_num < 1 || mode_num > 3) return 0;

	return mode_num;
}
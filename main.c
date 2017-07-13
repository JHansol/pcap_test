#include <pcap.h>
#include <stdio.h>
#include <string.h>

	 int main(int argc, char *argv[])
	 {
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
                struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

		/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	
		struct pcap_pkthdr *headers;
		const unsigned char *pkt_data;
		/* Grab a packet */
                while(( pcap_next_ex(handle, &headers, &pkt_data))>=0){
                    //for(int i=0;i<headers->len;i++)
                    //    printf("%x ",pkt_data[i]);
                    int count = 0;
                    if(headers->len > 53 && pkt_data[12] == 0x08 && pkt_data[13] == 0x00){ //

                        // ether packet //
                        printf("destination mac : ");
                        for(int i=0;i<6;i++)
                           printf("%x ",pkt_data[i]);
                        printf("\nsource mac : ");
                        for(int i=6;i<12;i++)
                           printf("%x ",pkt_data[i]);
                        printf("\nprotocol type : ");
                        for(int i=12;i<14;i++)
                           printf("%x ",pkt_data[i]);
                        printf("\n");

                        // network layer - IP pakcet // 9 - tcp
                        count = 26;
                        printf("source ip : ");
                        printf("%d.%d.%d.%d\n",pkt_data[count],pkt_data[count+1],pkt_data[count+2],pkt_data[count+3]);

                        count = 30;
                        printf("dest ip : ");
                        printf("%d.%d.%d.%d\n",pkt_data[count],pkt_data[count+1],pkt_data[count+2],pkt_data[count+3]);

                        count = 34;
                        printf("source port : ");
                        printf("%d \n",(pkt_data[count]<<8) + pkt_data[count+1]);

                        count = 36;
                        printf("dest port : ");
                        printf("%d \n",(pkt_data[count]<<8) + pkt_data[count+1]);

                        //54
                        count = 54;
                        printf("data:");
                        if(pkt_data[count] != 0){
                            for(int i=count;i<(headers->len)-54;i++){
                                printf("%x ",pkt_data[i]);
                            }
                        }else{
                            printf("data is nothing");
                        }
                        printf("\n");

                        printf("/////////////////////////////////////////////////\n");

                    }
                    headers->len = 0;
                }

		pcap_close(handle);
		return(0);
	 }

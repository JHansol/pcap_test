#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <libnet.h>

#define ether_len  14

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
		if (argc <2) { exit(0);}
                /* Open the session in promiscuous mode */
                handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
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

                struct libnet_ethernet_hdr *eth;
                struct libnet_ipv4_hdr *ipv4;
                struct libnet_tcp_hdr *tcph;
                // TCP PACKET sniffer //
                while(( pcap_next_ex(handle, &headers, &pkt_data))>=0){ // return 1 - receive
                     eth = (struct libnet_ethernet_hdr*)pkt_data;

                     // print mac address //
                     printf("destination mac : ");
                     for(int i=0;i<6;i++)
                        printf("%02X ",eth->ether_dhost[i]);
                     printf("\nsource mac : ");
                     for(int i=0;i<6;i++)
                        printf("%02X ",eth->ether_shost[i]);
                     printf("\n");
                     // print mac //

                     if(eth->ether_type == htons(ETHERTYPE_IP)){ // IPv4 = 0x0800
                         ipv4 = (struct libnet_ipv4_hdr*)(pkt_data+ether_len);
                         int ip_header_size = (ipv4->ip_hl*4);

			char buf[20];
                         // print ip address //
                         printf("source ip : ");
			 printf("%s \n",inet_ntop(AF_INET,&ipv4->ip_src,buf,sizeof(buf))); //ip_src, ip_dst;
                         printf("dest ip : ");
                         printf("%s \n",inet_ntop(AF_INET,&ipv4->ip_dst,buf,sizeof(buf))); //ip_src, ip_dst;

                         if(ipv4->ip_p == IPPROTO_TCP){ // tcp = 0x06
                             tcph = (struct libnet_tcp_hdr*)(pkt_data+ether_len+(ipv4->ip_hl*4));
                             int tcp_header_size = (tcph->th_off*4);
                             int data_start_off = ether_len + ip_header_size + tcp_header_size;
                             int data_size = ntohs(ipv4->ip_len) - ip_header_size - tcp_header_size;

                             // print port address //
                             printf("source port : ");
                             printf("%d \n",htons(tcph->th_sport));
                             printf("dest port : ");
                             printf("%d \n",htons(tcph->th_dport));

                             if(data_size > 0){
                                 printf("data : ");
                                 for(int i=data_start_off;i<data_size;i++){
                                     printf("%02X ",pkt_data[i]);
                                 }
                             }else{
                                 printf("data is nothing");
                             }
                             printf("\n////////////////////////////////////////////////////////////////////\n");
                         }
                     }

                     /*
                     int count = 0;
                     if(headers->len > 53 && pkt_data[12] == 0x08 && pkt_data[13] == 0x00){ //

                         ipv4 = (struct libnet_ipv4_hdr*)(pkt_data+ether_len);
                         tcph = (struct libnet_tcp_hdr*)(pkt_data+ether_len+(ipv4->ip_hl*4));

                         int ip_header_size = (ipv4->ip_hl*4);
                         int tcp_header_size = (tcph->th_off*4);
                         int data_size = ntohs(ipv4->ip_len) - ip_header_size - tcp_header_size;

                         // ether packet size 14 //
                         printf("destination mac : ");
                         for(int i=0;i<6;i++)
                            printf("%02X ",pkt_data[i]);
                         printf("\nsource mac : ");
                         for(int i=6;i<12;i++)
                            printf("%02X ",pkt_data[i]);
                         printf("\nprotocol type : ");
                         for(int i=12;i<14;i++)
                            printf("%02X ",pkt_data[i]);
                         printf("\n");

                         // network layer - IP pakcet size 20 // 9 - tcp
                         count = 26;
                         printf("source ip : ");
                         printf("%d.%d.%d.%d\n",pkt_data[count],pkt_data[count+1],pkt_data[count+2],pkt_data[count+3]);

                         count = 30;
                         printf("dest ip : ");
                         printf("%d.%d.%d.%d\n",pkt_data[count],pkt_data[count+1],pkt_data[count+2],pkt_data[count+3]);

                         if(pkt_data[14+9] == 0x06){ // tcp - 6
                         // tcp size 20 //
                         count = 34;
                         printf("source port : ");
                         printf("%d \n",(pkt_data[count]<<8) + pkt_data[count+1]);

                         count = 36;
                         printf("dest port : ");
                         printf("%d \n",(pkt_data[count]<<8) + pkt_data[count+1]);

                         //20+20+14=54 ,54 : data
                         count = 54;
                         printf("data:");
                         if(pkt_data[count] != 0){
                             for(int i=count;i<(headers->len)-54;i++){
                                 printf("%02X ",pkt_data[i]);
                             }
                         }else{
                             printf("data is nothing");
                         }
                         printf("\n");
                         }else{
                             printf("no Tcp Protocol \n");
                         }

                         printf("/////////////////////////////////////////////////\n");

                     }
                     headers->len = 0;
                    */
                }

		pcap_close(handle);
		return(0);
	 }

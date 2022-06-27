#include "lora/LoRa.h"
#include "block.h"
#include "configparse.h"
#include "/usr/include/postgresql/libpq-fe.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

int lastBinBlockLen = 0;
char * currentConfig = 0;


void rx_f(rxData *rx){
    printf("rx done \n");
    printf("RX size: %d\n", rx->size);
    lastBinBlockLen += rx->size - 1 ;
    //printf("CRC error: %d\n", rx->CRC);
    //printf("string: %s\n", rx->buf);//Data we'v received
    //printf("RSSI: %d\n", rx->RSSI);
    //printf("SNR: %f\n", rx->SNR);
    int x = rx->size;
    for (size_t i = 0; i < x - 1; i++)
    {  
        lastBinBlock[((rx->buf[0] >> 4) * maxPacketSize) + i] = rx->buf[1 + i];
    }

    //buf[x] = 0;
    //char str[100];
    //int lastRSSI = lora_packet_rssi();
    //int snlevel = lora_packet_snr();
    printf("Received block part");
   // for (int i = 0; i < x; i++)
    //    printf("%i ", buf[i]);
    
   printf("\nData Size = %i,  PACKET NUM %i OF %i \n",rx->size, rx->buf[0] >> 4, rx->buf[0] & 15);
    //ssd1306_clear_screen(&dev, false);
    //sprintf(str, "Num: %i", buf[x - 1]);
    //ssd1306_display_text(&dev, 0, str, strlen(str), false);
    //sprintf(str, "RSSI: %i dBm", lastRSSI);
    //ssd1306_display_text(&dev, 1, str, strlen(str), false);
    //sprintf(str, "S/N: %i", snlevel);
    //ssd1306_display_text(&dev, 2, str, strlen(str), false);
    //sprintf(str, "Size: %i", x);
    //ssd1306_display_text(&dev, 3, str, strlen(str), false);
    //lora_send_packet((uint8_t*)buf, x);
    //printf("1\n");
    //printf("2\n");
    //vTaskDelay(10);
    //lora_receive();
    //printf("3\n");
    if ((rx->buf[0] >> 4) == (rx->buf[0] & 15)){
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        
        
        printf("LoRa key address: 0x%x\n", config_lora_key);
        
        printf("Using lora key:");

        for (size_t i = 0; i < 32; i++)
        {
            printf("%x",config_lora_key[i]);
        }
       // printf("\n");

        int err = mbedtls_aes_setkey_dec(&aes, (unsigned char *)config_lora_key, 256);
        if(err!=0){
            printf("ERR CODE NOT 0, ERR: %i", err);
        }
        unsigned char iv[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        printf("\ncbc encrypted | ");
        for (size_t i = 0; i < lastBinBlockLen; i++)
        {
            if (lastBinBlock[i]<16)
            {
               printf("0");
            }
            
           printf("%x ",lastBinBlock[i]);
        }
        printf("\n");
        unsigned char * decrypt_output = malloc(lastBinBlockLen);

        //printf("iv empty | ");
        //for (size_t i = 0; i < 16; i++)
        //{
        //    printf("%x ",iv[i]);
        //}
        //printf("\n");
        //printf("RECIEVE DECRYPT | LEN OF DATA: %i\n", lastBinBlockLen);
        err = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
                                         lastBinBlockLen, iv, lastBinBlock, decrypt_output);
        if(err!=0){
            printf("ERR CODE NOT 0, ERR: %i", err);
        }
        //ESP_LOG_BUFFER_HEX("cbc", decrypt_output, x);
        printf("cbc decrypted | ");
        for (size_t i = 0; i < lastBinBlockLen; i++)
        {
            printf("%x ",decrypt_output[i]);
        }
        printf("\n");
        
        free(lastBinBlock);
        lastBinBlock = decrypt_output;
        if (!verifyBlock(lastBinBlock))
        {
            blocks = realloc(blocks, (blockNum + 1) * sizeof *blocks);
            blocks[blockNum] = blockFromBytes(lastBinBlock);
            blockNum++;
            int sockfd, portno, n;
            struct sockaddr_in serv_addr;
            struct hostent *server;
            char buffer[256];
            portno = 444;
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) 
                error("ERROR opening socket");
            server = gethostbyname("qapi.local");
            if (server == NULL) {
                fprintf(stderr,"ERROR, no such host\n");
                exit(0);
            }
            bzero((char *) &serv_addr, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            bcopy((char *)server->h_addr, 
                (char *)&serv_addr.sin_addr.s_addr,
                server->h_length);
            serv_addr.sin_port = htons(portno);
            if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
                error("ERROR connecting");            
            n = write(sockfd, lastBinBlock, lastBinBlockLen);
            if (n < 0) 
                error("ERROR writing to socket");
            bzero(buffer,256);
            n = read(sockfd, buffer, 255);
            if (n < 0) 
                error("ERROR reading from socket");
            printf("%s\n", buffer);
            close(sockfd);
    
        }
        else
        {
            printf("BLOCK NOT VERIFIED\n");
        }
        lastBinBlockLen = 0;
        mbedtls_aes_free(&aes);

    }    

}

int main(){

    printf("WELCOME TO QSERVER\n");
    FILE *fptr;
    
    map_init(&devices_list);

    if ((fptr = fopen("config_file","rb")) == NULL){
       printf("Error! opening file");
       exit(1);
    }
    long length;
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    fseek (fptr, 0, SEEK_SET);
    currentConfig = malloc (length);
    if (currentConfig)
    {
        fread(currentConfig, 1, length, fptr);
    }
    fclose (fptr);

    currentConfig[length-1]=0;

    if ((fptr = fopen("devices_list","rb")) == NULL){
       printf("Error! opening file");
       exit(1);
    }
    
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    fseek (fptr, 0, SEEK_SET);
    devicesListBinary = malloc (length);
    if (devicesListBinary)
    {
        fread(devicesListBinary, 1, length, fptr);
    }
    fclose (fptr);

    devicesListBinary[length-1]=0;



    if ((fptr = fopen("blocks_list","rb")) == NULL){
       printf("Error! opening file");
       exit(1);
    }
    
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    fseek (fptr, 0, SEEK_SET);
    blocksListBinary = malloc (length);
    if (blocksListBinary)
    {
        fread(blocksListBinary, 1, length, fptr);
    }
    fclose (fptr);

    blocksListBinary[length-1]=0;


    printf("START OF CONFIG PRASE\n");
    //printf("CONFIG %s",currentConfig);

    //if(parseTimestamp()){
       // printf("parseTimestamp\tOK\n");
    //}else
    //{
    //    printf("parseTimestamp\tERROR\n");
   // }

    

    if(parseRootCert()){
        printf("parseRootCert\tOK\n");
    }else
    {
        printf("parseRootCert\tERROR\n");
    }

    if(parseHostname()){
        printf("parseHostname\tOK\n");
    }else
    {
        printf("parseHostname\tERROR\n");
    }

    if(parseLoraFreq()){
        printf("parseLoraFreq\tOK\n");
    }else
    {
        printf("parseLoraFreq\tERROR\n");
    }

    if(parseLoraBand()){
        printf("parseLoraBand\tOK\n");
    }else
    {
        printf("parseLoraBand\tERROR\n");
    }

    if(parseLoraSF()){
        printf("parseLoraSF\tOK\n");
    }else
    {
        printf("parseLoraSF\tERROR\n");
    }

    if(parseLoraTXPower()){
        printf("parseLoraTXPower\tOK\n");
    }else
    {
        printf("parseLoraTXPower\tERROR\n");
    }

    if(parseLoraKey()){
        printf("parseLoraKey\tOK\n");
    }else
    {
        printf("parseLoraKey\tERROR\n");
    }

   //  if(parseHTTPSCert()){
     //   printf("parseHTTPSCERT\tOK\n");
    //}else
    //{
    //    printf("parseHTTPSCERT\tERROR\n");
    //}

    //if(parseHTTPSKey()){
    //    printf("parseHTTPSKey\tOK\n");
    //}else
    //{
    //    printf("parseHTTPSKey\tERROR\n");
    //}

    //if(parseDeviceType()){
       // printf("parseHTTPSKey\tOK\n");
    //}else
    //{
     //   printf("parseDeviceType\tERROR\n");
    //}

    if(parseBlockSignatures()){
        printf("parseBlockSignatures\tOK\n");
    }else
    {
       printf("parseBlockSignatures\tERROR\n");
    }

    if(parseDevicesList()){
        printf("parseDevicesList\tOK\n");
    }else
    {
       printf("parseDevicesList\tERROR\n");
    }
   char rxbuf[255];
    LoRa_ctl modem;
    lastBinBlock = malloc(maxBlockSize);
    //See for typedefs, enumerations and there values in LoRa.h header file
    modem.spiCS = 0;//Raspberry SPI CE pin number
    modem.rx.callback = rx_f;
    modem.rx.data.buf = rxbuf;
    modem.eth.payloadLen = 5;//payload len used in implicit header mode
    modem.eth.preambleLen=6;
    modem.eth.bw = BW250;//Bandwidth 250KHz
    modem.eth.sf = SF8;//Spreading Factor 12
    modem.eth.ecr = CR8;//Error coding rate CR4/8
    modem.eth.CRC = 1;//Turn on CRC checking
    modem.eth.freq = config_lora_freq * 1000000;
    modem.eth.resetGpioN = 4;//GPIO4 on lora RESET pi
    modem.eth.dio0GpioN = 17;//GPIO17 on lora DIO0 pin to control Rxdone and Txdone interrupts
    modem.eth.outPower = OP20;//Output power
    modem.eth.powerOutPin = PA_BOOST;//Power Amplifire pin
    modem.eth.AGC = 1;//Auto Gain Control
    modem.eth.OCP = 240;// 45 to 240 mA. 0 to turn off protection
    modem.eth.implicitHeader = 0;//Implicit header mode
    modem.eth.syncWord = 0x12;
    //For detail information about SF, Error Coding Rate, Explicit header, Bandwidth, AGC, Over current protection and other features refer to sx127x datasheet https://www.semtech.com/uploads/documents/DS_SX1276-7-8-9_W_APP_V5.pdf

     
    blocks = malloc(1 * sizeof *blocks);

   
    LoRa_begin(&modem);

    LoRa_receive(&modem);

    while(LoRa_get_op_mode(&modem) != SLEEP_MODE){
        sleep(1);
    }

    printf("end\n");
    LoRa_end(&modem);
}
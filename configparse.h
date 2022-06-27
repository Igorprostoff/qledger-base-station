#ifndef _CONFIG_PARSE_
#define _CONFIG_PARSE_
#include "stdio.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>
#include "mbedtls/sha256.h"
#include "mymap.h"
#include "block.h"



int parseHostname(){
    
    for(int i = 0; i<6; i++)
        config_hostname[i]='\0';
    
    char * hostnamePosStr = strstr(currentConfig, "hostname '");
    
    for (int i = 0; hostnamePosStr[10+i]!='\'' && hostnamePosStr[10+i]!='\n' && i<6; i++)
    {
        config_hostname[i]=hostnamePosStr[10+i];
    }

    config_hostname[5]=0;
    /*printf("\nNew hostname: %c%c%c%c%c%c", config_hostname[0],config_hostname[1],
    config_hostname[2],config_hostname[3],config_hostname[4],config_hostname[5]);*/
    return 1;
}

int parseRouterSSID(){
    char * posStr = strstr(currentConfig, "router_ssid '");
    int i =0;
    for (i = 0; posStr[13+i]!='\n' && posStr[13+i]!='\''; i++)
    {
        config_router_ssid = realloc(config_router_ssid, i+1);
        config_router_ssid[i]=posStr[13+i];
    }
    config_router_ssid = realloc(config_router_ssid, i+1);
    config_router_ssid[i]=0;
    
    printf("New config_router_ssid: %s\n", config_router_ssid);
    return 1;
}

int parseRouterPass(){
    char * posStr = strstr(currentConfig, "router_password '");
    int i =0;
    for ( i = 0; posStr[17+i]!='\n' && posStr[17+i]!='\''; i++)
    {
        config_router_password = realloc(config_router_password, i+1);
        config_router_password[i]=posStr[17+i];
        
    }
    config_router_password = realloc(config_router_password, i+1);
    config_router_password[i]=0;
    
    printf("New config_router_password: %s\n", config_router_password);
    return 1;
}

int parseECDSACert(){
    char * posStr = strstr(currentConfig, "ecdsa_cert '");
    int i =0;
    for ( i = 0; posStr[12+i]!='\''; i++)
    {
        pubKey = realloc(pubKey, i+1);
        pubKey[i]=posStr[12+i];
    }
    pubKey = realloc(pubKey, i+1);
    pubKey[i]=0;
    
    //printf("\nNew pubKey: %s", pubKey);

    return 1;
}

int parseECDSAKey(){
    char * posStr = strstr(currentConfig, "ecdsa_key '");
    int i =0;
    for ( i = 0; posStr[11+i]!='\''; i++)
    {
        privKey = realloc(privKey, i+1);
        privKey[i]=posStr[11+i];
    }
    privKey = realloc(privKey, i+1);
    privKey[i]=0;
    //printf("\nNew privKey: %s", privKey);
    
    //printf("\nNew pubKey: %s", pubKey);

    return 1;
}

int parseRootCert(){
    printf("NOR A FAULT");
    char * posStr = strstr(currentConfig, "root_cert '");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[11+i]!='\''; i++)
    {
        rootCert = realloc(rootCert, i+1);
        rootCert[i]=posStr[11+i];
    }
    rootCert = realloc(rootCert, i+1);
    rootCert[i]=0;
    //printf("\nNew rootCert: %s", rootCert);
    
    return 1;
}

int parseHTTPSCert(){
    char * posStr = strstr(currentConfig, "https_cert '");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[12+i]!='\''; i++)
    {
        httpsCert = realloc(httpsCert, i+1);
        httpsCert[i]=posStr[12+i];
    }
    httpsCert = realloc(httpsCert, i+1);
    httpsCert[i]=0;
    //printf("\nNew httpsCert: %s\n", httpsCert);
    
    return 1;
}

int parseHTTPSKey(){
    char * posStr = strstr(currentConfig, "https_key '");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[11+i]!='\''; i++)
    {
        httpsKey = realloc(httpsKey, i+1);
        httpsKey[i]=posStr[11+i];
    }
    httpsKey = realloc(httpsKey, i+1);
    httpsKey[i]=0;
    //printf("\nNew httpsKey: %s\n", httpsKey);
    
    return 1;
}

int parseLoraFreq(){
    char * buf = malloc(0);
    
    char * posStr = strstr(currentConfig, "lora_frequency ");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[15+i]!='\n'; i++)
    {
        buf = realloc(buf, i+1);
        buf[i]=posStr[15+i];
    }
    buf = realloc(buf, i+1);
    buf[i]=0;
    config_lora_freq = strtol(buf, buf+i, 10);
    printf("\nNew lora frequency: %li\n", config_lora_freq);
    
    return 1;
}

int parseLoraBand(){
    char * buf = malloc(0);
    
    char * posStr = strstr(currentConfig, "lora_bandwidth ");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[15+i]!='\n'; i++)
    {
        buf = realloc(buf, i+1);
        buf[i]=posStr[15+i];
    }
    buf = realloc(buf, i+1);
    buf[i]=0;
    config_lora_bandwidth = strtol(buf, buf+i, 10);
    printf("New lora bandwidth: %li\n", config_lora_bandwidth);
    
    return 1;
}

int parseLoraSF(){
    char * buf = malloc(0);
    
    char * posStr = strstr(currentConfig, "lora_sf ");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[8+i]!='\n'; i++)
    {
        buf = realloc(buf, i+1);
        buf[i]=posStr[8+i];
    }
    buf = realloc(buf, i+1);
    buf[i]=0;
    config_lora_sf = strtol(buf, buf+i, 10);
    printf("New lora SF: %li\n", config_lora_sf);
    
    return 1;
}

int parseLoraTXPower(){
    char * buf = malloc(0);
    
    char * posStr = strstr(currentConfig, "lora_tx_power ");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[14+i]!='\n'; i++)
    {
        buf = realloc(buf, i+1);
        buf[i]=posStr[14+i];
    }
    buf = realloc(buf, i+1);
    buf[i]=0;
    config_lora_tx_level = strtol(buf, buf+i, 10);
    printf("New lora TX power: %li\n", config_lora_tx_level);
    
    return 1;
}


int parseDevicesList(){
    
    uint64_t numOfDevices =  (uint64_t)devicesListBinary[0] |
                    (uint64_t)devicesListBinary[1]<<8 |
                    (uint64_t)devicesListBinary[2]<<16 | 
                    (uint64_t)devicesListBinary[3]<<24 |
                    (uint64_t)devicesListBinary[4]<<32 |
                    (uint64_t)devicesListBinary[5]<<40 |
                    (uint64_t)devicesListBinary[6]<<48 |
                    (uint64_t)devicesListBinary[7]<<56;
    uint64_t passedBytes = 8;
    printf("NUM OF DEVICES %lli",numOfDevices);
    for (size_t i = 0; i < numOfDevices; i++)
    {
        char deviceName[6] = {
            devicesListBinary[passedBytes],
            devicesListBinary[passedBytes+1],
            devicesListBinary[passedBytes+2],
            devicesListBinary[passedBytes+3],
            devicesListBinary[passedBytes+4],
            devicesListBinary[passedBytes+5]
        };
        passedBytes+=6;

        printf("\nDEVICE NAME %s",deviceName);

        int pubKeyLen = (devicesListBinary[passedBytes]<<8) + devicesListBinary[passedBytes+1];
        printf("\npubKeyLen %i\n",pubKeyLen);

        passedBytes+=2;
        char * devicepubKey = malloc(pubKeyLen+1);

        memcpy(devicepubKey, devicesListBinary+passedBytes, pubKeyLen);
        devicepubKey[pubKeyLen] = 0;
        passedBytes+=pubKeyLen;
        for(int i =0; i < pubKeyLen+1; i++)
            printf("%c", devicepubKey[i]);
        //printf("\nSETTING DEVICE NAME %s, \n WITH KEY %s", deviceName, devicepubKey);
        map_set(&devices_list, deviceName, devicepubKey);
    }
    
    
    return 1;
}


int parseBlockSignatures(){
    
    uint64_t numOfBlocks =  (uint64_t)blocksListBinary[0] |
                    (uint64_t)blocksListBinary[1]<<8 |
                    (uint64_t)blocksListBinary[2]<<16 | 
                    (uint64_t)blocksListBinary[3]<<24 |
                    (uint64_t)blocksListBinary[4]<<32 |
                    (uint64_t)blocksListBinary[5]<<40 |
                    (uint64_t)blocksListBinary[6]<<48 |
                    (uint64_t)blocksListBinary[7]<<56;
    uint64_t passedBytes = 8;
    blockNum = numOfBlocks;
    blocks = malloc(numOfBlocks * sizeof * blocks);

    printf("PARSE BLOCKS SIGS NUM OF blocks %lli\n",numOfBlocks);
    for (size_t i = 0; i < numOfBlocks; i++)
    {

        uint8_t sigLen = blocksListBinary[passedBytes];
        printf("PARSE BLOCKS SIGS sigLen %i\n",sigLen);

        passedBytes++;
        uint8_t * sig = malloc(sigLen);

        memcpy(sig, blocksListBinary+passedBytes, sigLen);
        passedBytes+=sigLen;
        printf("PARSE BLOCKS SIGS sigNature %s\n",sig);
        
       /* blocks[i].blockId = 0;

        blocks[i].timestamp = 0;

        blocks[i].dataSize = ;
        blocks[i].data = {0};
    
        blocks[i].par1SigSize = 0;
        blocks[i].par1Sig = {0};

        blocks[i].par2SigSize = 0;
        blocks[i].par2Sig = {0};

        blocks[i].mac = {0,0,0,0,0,0};*/


        blocks[i].signature=sig;
        blocks[i].sigSize=(uint64_t)sigLen;

    }
    
    return 1;
}


int parseLoraKey(){
    char * posStr = strstr(currentConfig, "lora_encryption_key '");
    if(posStr==NULL){
        return 0;
    }
    int i =0;
    for ( i = 0; posStr[21+i]!='\''; i++)
    {
        config_lora_key = realloc(config_lora_key, i+1);
        config_lora_key[i]=posStr[21+i];
    }
    config_lora_key = realloc(config_lora_key, i+1);
    config_lora_key[i]=0;

    unsigned char lora_sha256_key[32];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    const unsigned CALL_SZ = i;
    mbedtls_sha256_starts(&sha256_ctx, 0);
    
    for (int c = 0; c < 16; c++)
    {
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);

        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);

        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);

        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
        mbedtls_sha256_update(&sha256_ctx, (unsigned char *)config_lora_key, CALL_SZ);
    }
        //ESP_LOGI("CREATE BLOCK", "OK8");

    //free(config_lora_key);
    //ESP_LOGI("CREATE BLOCK", "OK81");
    mbedtls_sha256_finish(&sha256_ctx, lora_sha256_key);
    //ESP_LOGI("CREATE BLOCK", "OK82");
    mbedtls_sha256_free(&sha256_ctx);
    free(config_lora_key);
    
    config_lora_key = malloc(32);
    
    memcpy(config_lora_key, lora_sha256_key, 32);

    printf("New lora key:");

        for (size_t i = 0; i < 32; i++)
        {
            printf("%x",config_lora_key[i]);
        }
    printf("\n");
    printf("LoRa key address: 0x%x\n", config_lora_key);
    
    return 1;
}
#endif
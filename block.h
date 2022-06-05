#ifndef _BLOCK_C_
#define _BLOCK_C_

#include "mbedtls/entropy.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>
#include "mbedtls/sha256.h"
#include "configparse.h"
#include "mbedtls/aes.h"
#include "mymap.h"

typedef struct
{

    uint64_t blockId;

    time_t timestamp;

    uint64_t dataSize;
    uint8_t *data;
    
    uint64_t par1SigSize;
    uint8_t *par1Sig;

    uint64_t par2SigSize;
    uint8_t *par2Sig;

    uint8_t mac[6];

    uint64_t sigSize;
    uint8_t *signature;


} __attribute__((packed)) dag_block;

uint8_t *lastBinBlock;
int maxBlockSize = 2048;
uint8_t *buf;
int maxPacketSize = 200;
int blockNum = 1;
dag_block * blocks;
map devices_list;
/**
 *  A function to convert a block into bytes array.
 * \param[in] block a block to be converted
 * \param[out] msg pointer to an array of bytes
 */
void blockToBytes(dag_block block, uint8_t * msg){
    
    //uint8_t * msg = malloc(24+block.dataSize+8+block.par1SigSize+block.par2SigSize+6+8+block.sigSize);

    msg[0]= (block.blockId<<56)>>56;
    msg[1]= (block.blockId<<48)>>56;
    msg[2]= (block.blockId<<40)>>56;
    msg[3]= (block.blockId<<32)>>56;
    msg[4]= (block.blockId<<24)>>56;
    msg[5]= (block.blockId<<16)>>56;
    msg[6]= (block.blockId<<8)>>56;
    msg[7]= block.blockId>>56;

    msg[8]= ((uint64_t)block.timestamp<<56)>>56;
    msg[9]= ((uint64_t)block.timestamp<<48)>>56;
    msg[10]= ((uint64_t)block.timestamp<<40)>>56;
    msg[11]= ((uint64_t)block.timestamp<<32)>>56;
    msg[12]= ((uint64_t)block.timestamp<<24)>>56;
    msg[13]= ((uint64_t)block.timestamp<<16)>>56;
    msg[14]= ((uint64_t)block.timestamp<<8)>>56;
    msg[15]= (uint64_t)block.timestamp>>56;


    msg[16]= (block.dataSize<<56)>>56;
    msg[17]= (block.dataSize<<48)>>56;
    msg[18]= (block.dataSize<<40)>>56;
    msg[19]= (block.dataSize<<32)>>56;
    msg[20]= (block.dataSize<<24)>>56;
    msg[21]= (block.dataSize<<16)>>56;
    msg[22]= (block.dataSize<<8)>>56;
    msg[23]= block.dataSize>>56;

    for(int i = 0; i<block.dataSize; i++){
        msg[24+i]=block.data[i];
    } 


    msg[24+block.dataSize]= (block.par1SigSize<<56)>>56;
    msg[24+block.dataSize+1]= (block.par1SigSize<<48)>>56;
    msg[24+block.dataSize+2]= (block.par1SigSize<<40)>>56;
    msg[24+block.dataSize+3]= (block.par1SigSize<<32)>>56;
    msg[24+block.dataSize+4]= (block.par1SigSize<<24)>>56;
    msg[24+block.dataSize+5]= (block.par1SigSize<<16)>>56;
    msg[24+block.dataSize+6]= (block.par1SigSize<<8)>>56;
    msg[24+block.dataSize+7]= block.par1SigSize>>56;

    for(int i = 0; i<block.par1SigSize; i++){
        msg[24+block.dataSize+8+i]=block.par1Sig[i];
    } 
    
    msg[24+block.dataSize+8+block.par1SigSize]= (block.par2SigSize<<56)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+1]= (block.par2SigSize<<48)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+2]= (block.par2SigSize<<40)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+3]= (block.par2SigSize<<32)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+4]= (block.par2SigSize<<24)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+5]= (block.par2SigSize<<16)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+6]= (block.par2SigSize<<8)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+7]= block.par2SigSize>>56;

    for(int i = 0; i<block.par2SigSize; i++){
        msg[24+block.dataSize+8+block.par1SigSize+8+i]=block.par2Sig[i];
    } 

    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize]=block.mac[0];
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+1]=block.mac[1];
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+2]=block.mac[2];
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+3]=block.mac[3];
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+4]=block.mac[4];
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+5]=block.mac[5];


    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6]= (block.sigSize<<56)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+1]= (block.sigSize<<48)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+2]= (block.sigSize<<40)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+3]= (block.sigSize<<32)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+4]= (block.sigSize<<24)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+5]= (block.sigSize<<16)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+6]= (block.sigSize<<8)>>56;
    msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+7]= block.sigSize>>56; 


    for(int i = 0; i<block.sigSize; i++){
        msg[24+block.dataSize+8+block.par1SigSize+8+block.par2SigSize+6+8+i]=block.signature[i];
    }
    
    //return msg;
}

/**
 *  A function to verify block, recieved from another device by LoRa.
 * \param[in] blockBytes recieeved block in binary
 * \return true if block is verified, false if not 
 */
int verifyBlock(uint8_t * blockBytes){
    
uint64_t blockId =  (uint64_t)blockBytes[0] |
                    (uint64_t)blockBytes[1]<<8 |
                    (uint64_t)blockBytes[2]<<16 | 
                    (uint64_t)blockBytes[3]<<24 |
                    (uint64_t)blockBytes[4]<<32 |
                    (uint64_t)blockBytes[5]<<40 |
                    (uint64_t)blockBytes[6]<<48 |
                    (uint64_t)blockBytes[7]<<56;
 

    printf("BLOCKID = %lli \n", blockId);
    time_t timestamp =  (uint64_t)blockBytes[8] | 
                        (uint64_t)blockBytes[9]<<8 | 
                        (uint64_t)blockBytes[10]<<16 | 
                        (uint64_t)blockBytes[11]<<24 | 
                        (uint64_t)blockBytes[12]<<32 | 
                        (uint64_t)blockBytes[13]<<40 | 
                        (uint64_t)blockBytes[14]<<48 |
                        (uint64_t)blockBytes[15]<<56;

    printf("TIMESTAMP = %lli \n", (uint64_t)timestamp);

    uint64_t dataSize = (uint64_t)blockBytes[16] | 
                        (uint64_t)blockBytes[17]<<8 | 
                        (uint64_t)blockBytes[18]<<16 | 
                        (uint64_t)blockBytes[19]<<24 | 
                        (uint64_t)blockBytes[20]<<32 | 
                        (uint64_t)blockBytes[21]<<40 | 
                        (uint64_t)blockBytes[22]<<48 |
                        (uint64_t)blockBytes[23]<<56;

    if(dataSize>4096){
        return 0;
    }
    uint8_t * blockData = malloc(dataSize);

    for (size_t i = 0; i < dataSize; i++)
    {
        blockData[i] = blockBytes[24+i];
    }
    
    
    
    printf("DATASIZE = %lli \n", dataSize);    
    uint64_t par1SigSize =  (uint64_t)blockBytes[24+dataSize] | 
                            (uint64_t)blockBytes[24+dataSize+1]<<8 |
                            (uint64_t)blockBytes[24+dataSize+2]<<16 | 
                            (uint64_t)blockBytes[24+dataSize+3]<<24 |
                            (uint64_t)blockBytes[24+dataSize+4]<<32 |
                            (uint64_t)blockBytes[24+dataSize+5]<<40 |
                            (uint64_t)blockBytes[24+dataSize+6]<<48 |
                            (uint64_t)blockBytes[24+dataSize+7]<<56;
    if(par1SigSize>255){
        return 0;
    }
    
    printf("PAR1SIGSIZE = %lli \n", par1SigSize);
    uint64_t par2SigSize = (uint64_t)blockBytes[24+dataSize+8+par1SigSize] | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+1]<<8 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+2]<<16 | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+3]<<24 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+4]<<32 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+5]<<40 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+6]<<48 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+7]<<56;
    
    printf("PAR2SIGSIZE = %lli \n", par2SigSize);
     if(par2SigSize>255){
        return 0;
    }
    

    uint8_t messageType = blockData[0];
    uint8_t * localPubkey;
    char * senderName = malloc(6);
    senderName[0]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize];
    senderName[1]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+1];
    senderName[2]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+2];
    senderName[3]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+3];
    senderName[4]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+4];
    senderName[5]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+5];
   
    if (messageType == 0){
        localPubkey = malloc(dataSize);
        
        for (size_t i = 0; i < dataSize-1; i++)
        {
            
            localPubkey[i]=blockData[1+i];
        }
        char * errortxt = malloc(128);
        mbedtls_x509_crt notYetVerifiedCert;
        mbedtls_x509_crt_init(&notYetVerifiedCert);
        unsigned int err = mbedtls_x509_crt_parse(&notYetVerifiedCert,
                                            (unsigned char*)localPubkey,
                                            strlen((char*)localPubkey)+1);
        if (err!=0){
            mbedtls_strerror(err, errortxt, 128);
            printf("ERR parse new cert: %hx, %s", err, errortxt);
            
            return 0;
        }
        mbedtls_x509_crt rootMbedCert;
        mbedtls_x509_crt_init(&rootMbedCert);
        err = mbedtls_x509_crt_parse(&rootMbedCert,
                                            (unsigned char*)rootCert,
                                            strlen(rootCert)+1);
        if (err!=0){
            mbedtls_strerror(err, errortxt, 128);
            printf("ERR parse ca cert: %hx, %s", err, errortxt);
            
            return 0;
        }
        uint32_t flags;
        err = mbedtls_x509_crt_verify(&notYetVerifiedCert,&rootMbedCert,NULL,NULL, &flags, NULL, NULL);
        if (err!=0){
            mbedtls_strerror(err, errortxt, 128);
            printf("ERR mbedtls_x509_crt_verify: %hx, %s", err, errortxt);
           
            return 0;
        }
        free(errortxt);

        localPubkey[dataSize-1] = 0;
        printf("ADDRESS OF MAP IN SET: 0x%x\n", &devices_list);
        printf("ADDRESS OF senderName IN SET: 0x%x\n", senderName);
        printf("ADDRESS OF LOCAL PUB KEY IN SET: 0x%x\n", localPubkey);
        map_set(&devices_list, senderName, localPubkey);

        
        printf("NEW DEVICE IS NOW IN LIST: %s\n", senderName);

        printf("TEST OF MAP_GET FUNCTION AFTER SET: %s\n", map_get(&devices_list, senderName));

    }
    else
    {
        localPubkey = map_get(&devices_list, senderName);
        printf("ADDRESS OF MAP IN GET: 0x%x\n", &devices_list);
        printf("ADDRESS OF senderName IN GET: 0x%x\n", senderName);
        printf("ADDRESS OF LOCAL PUB KEY IN GET: 0x%x\n", localPubkey);
        
        
        if (localPubkey==0x0)
        {
            printf("DEVICE IS NOT IN LIST");
            return 0;
        }
        
        printf("reading 100 bytes of cert: \n");
        for (size_t i = 0; i < 100; i++)
        {
            printf("%c",localPubkey[i]);
        }
        printf("\n");
        
    }

    uint64_t sigSize = (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6] | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+1]<<8 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+2]<<16 | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+3]<<24 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+4]<<32 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+5]<<40 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+6]<<48 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+7]<<56;
    printf("SIGSIZE = %lli \n", sigSize);
     if(sigSize>255){
        return 0;
    }
    uint8_t *signature = malloc(sigSize);
    for (size_t i = 0; i < sigSize; i++)
    {
       signature[i]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+8+i];
	   
    }
    const unsigned CALL_SZ = 24+dataSize+8+par1SigSize+8+par2SigSize+6;
    mbedtls_sha256_context sha256_ctx;
    unsigned char sha256[32];
    uint8_t* dataToSign = malloc(24+dataSize+8+par1SigSize+8+par2SigSize+6);

	
    for (size_t i = 0 ; i <(24+dataSize+8+par1SigSize+8+par2SigSize+6); i++)
    {
        dataToSign[i]=blockBytes[i];
        //printf("%x", dataToSign[i]);
    }
    //printf("\n");
    mbedtls_sha256_init(&sha256_ctx);

    mbedtls_sha256_starts(&sha256_ctx, 0);
        
    for (int c = 0; c < 256; c++)
    {
        mbedtls_sha256_update(&sha256_ctx, dataToSign, CALL_SZ);
        
    }
    mbedtls_sha256_finish(&sha256_ctx, sha256);
    mbedtls_sha256_free(&sha256_ctx);
    /*printf("HASH TO CHEC: ");
    for (size_t i = 0; i < 32; i++)
    {
        printf("%x",sha256[i]);
    }
    printf("\n");*/
    
    mbedtls_ecdsa_context ctxECDSA;
    mbedtls_ecdsa_init(&ctxECDSA);
    //
    mbedtls_x509_crt pubKeymbtls;
    mbedtls_x509_crt_init(&pubKeymbtls);
    
    char * errortxt = malloc(128);

    printf("USING THIS LOCAL PUB KEY:\n");
    for (size_t i = 0; i < strlen(localPubkey); i++)
    {
        printf("%c",localPubkey[i]);
    }
    printf("\n");
    
    unsigned int err = mbedtls_x509_crt_parse(&pubKeymbtls, (unsigned char*)localPubkey, strlen(pubKey)+1);
    
    if (err!=0){
        mbedtls_strerror(err, errortxt, 128);
        printf("ERR DURING mbedtls_x509_crt_parse, %s",errortxt);
    }
    //printf("tag", "ERR parse: %hx, %s", err, errortxt);
     err = mbedtls_pk_setup(&pubKeymbtls, mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA));
     if (err!=0){
        mbedtls_strerror(err, errortxt, 128);
        printf("ERR DURING mbedtls_pk_setup, %s",errortxt);
    } 
    //printf("tag", "ERR setup: %hx, %s", err, errortxt);

    //printf("tag", "init cool");
    ctxECDSA.d = mbedtls_pk_ec(pubKeymbtls.pk)->d;
    //printf("tag", "assign d cool");
    ctxECDSA.grp = mbedtls_pk_ec(pubKeymbtls.pk)->grp;
    //printf("tag", "assign grp cool");
    ctxECDSA.Q = mbedtls_pk_ec(pubKeymbtls.pk)->Q;
    //printf("tag", "assign q cool");
    err = mbedtls_ecdsa_read_signature(&ctxECDSA, sha256, 32, signature, sigSize);

    free(signature);
    free(dataToSign);

if(err==0){
    printf("BLOCK VERIFY", "BLOCK VERIFIED");
    free(errortxt);
    return 1;
}
mbedtls_strerror(err, errortxt, 128);
printf(errortxt);
printf("BLOCK VERIFY", "BLOCK NOT VERIFIED");
free(errortxt);
return 0;
}

/**
 *  A function to create block from binary data block.
 * \param[in] blockBytes  block in binary
 * \return dag_block structure
 */
dag_block blockFromBytes(uint8_t* blockBytes){
    dag_block retBlock;

    uint64_t blockId =  (uint64_t)blockBytes[0] |
                    (uint64_t)blockBytes[1]<<8 |
                    (uint64_t)blockBytes[2]<<16 | 
                    (uint64_t)blockBytes[3]<<24 |
                    (uint64_t)blockBytes[4]<<32 |
                    (uint64_t)blockBytes[5]<<40 |
                    (uint64_t)blockBytes[6]<<48 |
                    (uint64_t)blockBytes[7]<<56;
 
    retBlock.blockId = blockId;

    //printf("BLOCKFROMBYTES BLOCKID = %lli \n", blockId);
    time_t timestamp =  (uint64_t)blockBytes[8] | 
                        (uint64_t)blockBytes[9]<<8 | 
                        (uint64_t)blockBytes[10]<<16 | 
                        (uint64_t)blockBytes[11]<<24 | 
                        (uint64_t)blockBytes[12]<<32 | 
                        (uint64_t)blockBytes[13]<<40 | 
                        (uint64_t)blockBytes[14]<<48 |
                        (uint64_t)blockBytes[15]<<56;
    
    retBlock.timestamp = timestamp;

    //printf("BLOCKFROMBYTES TIMESTAMP = %lli \n", (uint64_t)timestamp);

    uint64_t dataSize = (uint64_t)blockBytes[16] | 
                        (uint64_t)blockBytes[17]<<8 | 
                        (uint64_t)blockBytes[18]<<16 | 
                        (uint64_t)blockBytes[19]<<24 | 
                        (uint64_t)blockBytes[20]<<32 | 
                        (uint64_t)blockBytes[21]<<40 | 
                        (uint64_t)blockBytes[22]<<48 |
                        (uint64_t)blockBytes[23]<<56;

    retBlock.dataSize = dataSize;

    /*if(dataSize>255){
        return false;
    }*/
    
    //printf("BLOCKFROMBYTES DATASIZE = %lli \n", dataSize);   
    uint8_t * blockData = malloc(dataSize);
    for (size_t i = 0; i < dataSize; i++)
    {
        blockData[i]=blockBytes[24+i];
    }
    retBlock.data = blockData;

    uint64_t par1SigSize =  (uint64_t)blockBytes[24+dataSize] | 
                            (uint64_t)blockBytes[24+dataSize+1]<<8 |
                            (uint64_t)blockBytes[24+dataSize+2]<<16 | 
                            (uint64_t)blockBytes[24+dataSize+3]<<24 |
                            (uint64_t)blockBytes[24+dataSize+4]<<32 |
                            (uint64_t)blockBytes[24+dataSize+5]<<40 |
                            (uint64_t)blockBytes[24+dataSize+6]<<48 |
                            (uint64_t)blockBytes[24+dataSize+7]<<56;
    /*if(par1SigSize>255){
        return false;
    }*/
    
    //printf("BLOCKFROMBYTES PAR1SIGSIZE = %lli \n", par1SigSize);
    retBlock.par1SigSize = par1SigSize;
    uint8_t * par1Sig = malloc(par1SigSize);
    for (size_t i = 0; i < par1SigSize; i++)
    {
        par1Sig[i]=blockBytes[24+dataSize+8+i];
    }
    retBlock.par1Sig = par1Sig;

    uint64_t par2SigSize = (uint64_t)blockBytes[24+dataSize+8+par1SigSize] | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+1]<<8 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+2]<<16 | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+3]<<24 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+4]<<32 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+5]<<40 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+6]<<48 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+7]<<56;
    
    //printf("BLOCKFROMBYTES PAR2SIGSIZE = %lli \n", par2SigSize);
     /*if(par2SigSize>255){
        return false;
    }*/
    retBlock.par2SigSize = par2SigSize;
    uint8_t * par2Sig = malloc(par2SigSize);
    for (size_t i = 0; i < par2SigSize; i++)
    {
        par2Sig[i]=blockBytes[24+dataSize+8+par1SigSize+8];
    }
    retBlock.par2Sig = par2Sig;
    
    //uint8_t * mac=malloc(6);
    retBlock.mac[0]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize];
    retBlock.mac[1]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+1];
    retBlock.mac[2]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+2];
    retBlock.mac[3]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+3];
    retBlock.mac[4]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+4];
    retBlock.mac[5]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+5];

    //printf("BLOCKFROMBYTES MAC: %i:%i:%i:%i:%i:%i \n",retBlock.mac[0],retBlock.mac[1],retBlock.mac[2],retBlock.mac[3],retBlock.mac[4],retBlock.mac[5]);
    //mac = mac;
    

    uint64_t sigSize = (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6] | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+1]<<8 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+2]<<16 | 
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+3]<<24 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+4]<<32 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+5]<<40 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+6]<<48 |
                            (uint64_t)blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+7]<<56;
    //printf("BLOCKFROMBYTES SIGSIZE = %lli \n", sigSize);
    /* if(sigSize>255){
        return false;
    }*/
    retBlock.sigSize = sigSize;
    uint8_t *signature = malloc(sigSize);
    for (size_t i = 0; i < sigSize; i++)
    {
       signature[i]=blockBytes[24+dataSize+8+par1SigSize+8+par2SigSize+6+8+i];
    }

    retBlock.signature = signature;

    return retBlock;
}

#endif
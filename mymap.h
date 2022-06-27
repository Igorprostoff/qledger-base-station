#ifndef _MAP_C_
#define _MAP_C_

#include "stdio.h"

typedef struct
{

    int num;
    char * key;
    int keylen;
    char * value;
    int valueLen;

} __attribute__((packed)) element;

typedef struct
{

    element * elements;
    int elementsLen;

} __attribute__((packed)) map;

int map_init(map * m){
    m->elementsLen = 0;
    m->elements = malloc(1 * sizeof(element));
    return 0;
}

char * map_get(map * m, char * key){
    //printf("6");

    for (size_t i = 0; i < m->elementsLen; i++)
    {
        printf("\nCOMPARING KEY %s WITH %s", key, m->elements[i].key);
        if(strcmp(key, m->elements[i].key)==0){
            return m->elements[i].value;
        }
    }
    //printf("7");
    
    return NULL;
    
}

int map_set(map * m, char * key, char * value){
    //printf("1");
    element * possibleDuplicate = map_get(m,key);
    //printf(" 11");
    if(possibleDuplicate != NULL){
        m->elements[possibleDuplicate->num].key = key;
        m->elements[possibleDuplicate->num].value = value;
        return 0;
    }
    //printf("2");

    m->elementsLen ++;

    m->elements = realloc(m->elements, (1+m->elementsLen) * sizeof(element*));
    //printf("3");
    //printf("SETTING KEY %s ON ADDRESS %i",key,key);
   // m->elements[m->elementsLen-1].key=key;
    m->elements[m->elementsLen-1].key = malloc(strlen(key)+1);
    memcpy(m->elements[m->elementsLen-1].key, key, strlen(key)+1);
    m->elements[m->elementsLen-1].keylen = strlen(key)+1;
    //printf("4");

    //m->elements[m->elementsLen-1].value=value;
    printf("ALLOCATING %i BYTES",strlen(value)+1);
    m->elements[m->elementsLen-1].value = malloc(strlen(value)+1);
    memcpy(m->elements[m->elementsLen-1].value, value, strlen(value)+1);
    m->elements[m->elementsLen-1].value[strlen(value)] = 0;
    m->elements[m->elementsLen-1].valueLen = strlen(value)+1;
    //printf("5");

    m->elements[m->elementsLen-1].num = m->elementsLen-1;
    
    return 0;
}



#endif
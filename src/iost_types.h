/*******************************************************************************
*   Taras Shchybovyk
*   (c) 2018 Taras Shchybovyk
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef __IOST_TYPES_H__
#define __IOST_TYPES_H__

#include <stdint.h>

typedef number variant32_t;
typedef char[12] name_t;

/* Possible Remaining Items in Transaction Object
Name	Type	Description
hash	String	transaction hash
publisher	String	transaction publisher
referred_tx	String	referred transaction hash */

typedef struct transaction_header_t {
    uint32_t time;
    uint32_t expiration;
    variant32_t gas_ratio;
    variant32_t gas_limit;
    variant32_t delay_sec;
} transaction_header_t;

typedef struct action_t {
    name_t contract;
    name_t action_name;
    char[512] data;
} action_t;

typedef struct signer_t {
    name_t signer;
} signer_t;

typedef struct amountlimit_t {
    name_t token; 
    uint64_t value;
} amountlimit_t;


uint32_t unpack_variant32(uint8_t *in, uint32_t length, variant32_t *value);

name_t buffer_to_name_type(uint8_t *in, uint32_t size);
uint8_t name_to_string(name_t value, char *out, uint32_t size);

uint8_t amountlimit_to_string(amountlimit_t *amountlimit, char *out, uint32_t size);

uint32_t public_key_to_wif(uint8_t *publicKey, uint32_t keyLength, char *out, uint32_t outLength);
uint32_t compressed_public_key_to_wif(uint8_t *publicKey, uint32_t keyLength, char *out, uint32_t outLength);

#endif // __IOST_TYPES_H__

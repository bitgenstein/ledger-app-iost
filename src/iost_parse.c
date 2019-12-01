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

#include "iost_parse.h"
#include "os.h"
#include "cx.h"
#include "iost_types.h"
#include <stdbool.h>
#include <string.h>

void printString(const char in[], const char fieldName[], actionArgument_t *arg) {
    uint32_t inLength = strlen(in);
    uint32_t labelLength = strlen(fieldName);

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);
    os_memmove(arg->data, in, inLength);
}

void parseNameField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(name_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));
    
    os_memmove(arg->label, fieldName, labelLength);
    name_t name = buffer_to_name_type(in, sizeof(name_t));
    uint32_t writtenToBuff = name_to_string(name, arg->data, sizeof(arg->data)-1);

    *read = sizeof(name_t);
    *written = writtenToBuff;
}

void parsePublicKeyField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < 33) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);
    uint32_t writtenToBuff = compressed_public_key_to_wif(in, 33, arg->data, sizeof(arg->data)-1);

    *read = 33;
    *written = writtenToBuff;
}

void parseUInt64Field(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(uint64_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }
    
    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));
    
    os_memmove(arg->label, fieldName, labelLength);
    uint64_t value;
    os_memmove(&value, in, sizeof(uint64_t));
    ui64toa(value, arg->data);
    
    *read = sizeof(uint64_t);
    *written = strlen(arg->data);
}

void parseAmountlimitField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    if (inLength < sizeof(amountlimit_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);
    amountlimit_t amountlimit;
    os_memmove(&amountlimit, in, sizeof(asset));
    uint32_t writtenToBuff = amountlimit_to_string(&amountlimit, arg->data, sizeof(arg->data)-1); 

    *read = sizeof(amountlimit_t);
    *written = writtenToBuff;
}

void parseStringField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    uint32_t labelLength = strlen(fieldName);
    if (labelLength > sizeof(arg->label)) {
        PRINTF("parseActionData Label too long\n");
        THROW(EXCEPTION);
    }

    os_memset(arg->label, 0, sizeof(arg->label));
    os_memset(arg->data, 0, sizeof(arg->data));

    os_memmove(arg->label, fieldName, labelLength);

    uint32_t fieldLength = 0;
    uint32_t readFromBuffer = unpack_variant32(in, inLength, &fieldLength);
    if (fieldLength > sizeof(arg->data) - 1) {
        PRINTF("parseActionData Insufficient bufferg\n");
        THROW(EXCEPTION);
    } 

    if (inLength < fieldLength) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }

    in += readFromBuffer;
    inLength -= readFromBuffer;

    os_memmove(arg->data, in, fieldLength);

    in += fieldLength;
    inLength -= fieldLength;

    *read = readFromBuffer + fieldLength;
    *written = fieldLength;
}

void parsePermissionField(uint8_t *in, uint32_t inLength, const char fieldName[], actionArgument_t *arg, uint32_t *read, uint32_t *written) {
    uint32_t accountWrittenLength = 0;
    
    parseNameField(in, inLength, fieldName, arg, read, &accountWrittenLength);
    strcat(arg->data, "@");
    
    in += *read; inLength -= *read;
    if (inLength < sizeof(name_t)) {
        PRINTF("parseActionData Insufficient buffer\n");
        THROW(EXCEPTION);
    }
    name_t name = buffer_to_name_type(in, sizeof(name_t));
    
    *written = name_to_string(name, arg->data + accountWrittenLength + 1, sizeof(arg->data) - accountWrittenLength - 1) + accountWrittenLength;
    *read += sizeof(name_t);
}

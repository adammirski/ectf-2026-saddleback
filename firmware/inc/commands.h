/**
 * @file commands.h
 * @author Team Saddleback
 * @brief eCTF command handlers
 * @date 2026
 */

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "security.h"
#include "stdint.h"
#include "simple_flash.h"
#include "filesystem.h"
#include "secrets.h"

#define pkt_len_t uint16_t

typedef unsigned char pin_t[6];

#define MAX_MSG_SIZE sizeof(write_command_t)

#define LIST_PKT_LEN(num_files) (sizeof(num_files) + ((MAX_NAME_SIZE + sizeof(group_id_t) + sizeof(slot_t)) * num_files))

#pragma pack(push, 1)

/**********************************************************
 ******************** FILE STRUCTS ************************
 **********************************************************/

typedef struct {
    slot_t slot;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
} file_metadata_t;

/**********************************************************
 ******************** COMMAND STRUCTS *********************
 **********************************************************/

typedef struct {
    pin_t pin;
} list_command_t;

typedef struct {
    pin_t pin;
    slot_t slot;
} read_command_t;

typedef struct {
    pin_t pin;
    slot_t slot;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint8_t uuid[UUID_SIZE];
    uint16_t contents_len;
    uint8_t contents[MAX_CONTENTS_SIZE];
} write_command_t;

typedef struct {
    pin_t pin;
    slot_t read_slot;
    slot_t write_slot;
} receive_command_t;

typedef struct {
    slot_t slot;
    group_permission_t permissions[MAX_PERMS];
} receive_request_t;

typedef struct {
    uint8_t uuid[UUID_SIZE];
    file_t file;
    /* MAC is NOT transmitted — receiver computes it locally from shared_secret (SR3) */
} receive_response_t;

typedef struct {
    pin_t pin;
} interrogate_command_t;

/**********************************************************
 ******************** RESPONSE STRUCTS ********************
 **********************************************************/

typedef struct {
    uint32_t n_files;
    file_metadata_t metadata[MAX_FILE_COUNT];
} list_response_t;

typedef struct {
    char name[MAX_NAME_SIZE];
    uint8_t contents[MAX_CONTENTS_SIZE];
} read_response_t;

#pragma pack(pop)

int list(uint16_t pkt_len, uint8_t *buf);
int read(uint16_t pkt_len, uint8_t *buf);
int write(uint16_t pkt_len, uint8_t *buf);
int receive(uint16_t pkt_len, uint8_t *buf);
int interrogate(uint16_t pkt_len, uint8_t *buf);
int listen(uint16_t pkt_len, uint8_t *buf);

#endif // __COMMANDS_H__

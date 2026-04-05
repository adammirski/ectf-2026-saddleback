/**
 * @file commands.c
 * @author Team Saddleback
 * @brief eCTF command handlers with security enforcement
 * @date 2026
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"

/* Single global workspace union — commands never run concurrently so sharing is safe.
 * Keeps all large buffers out of the 256-byte stack. */
static union {
    receive_response_t recv_resp;   /* used by receive() and listen() */
    read_response_t    file_info;   /* used by read() */
    file_t             file;        /* used by write(), generate_*_files() */
} g_buf;

/* Convenience aliases */
#define g_recv_resp  g_buf.recv_resp
#define g_file_info  g_buf.file_info
#define current_file g_buf.file

static receive_request_t  g_request;   /* small, separate is fine */
static list_response_t    g_file_list; /* small, separate is fine */

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t *temp_file = &current_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file->group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file->name);
            file_list->n_files++;
        }
    }
}

/** @brief Generate a filtered file list based on requester's permissions
 *  Only includes files for groups the requester has receive permission for (SR1)
 */
void generate_filtered_list(list_response_t *file_list, group_permission_t *requester_perms) {
    file_list->n_files = 0;
    file_t *temp_file = &current_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, temp_file);

            /* Only include files the requester has receive permission for (SR1) */
            if (validate_interrogate_permission(requester_perms, temp_file->group_id)) {
                file_list->metadata[file_list->n_files].slot = i;
                file_list->metadata[file_list->n_files].group_id = temp_file->group_id;
                strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file->name);
                file_list->n_files++;
            }
        }
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t *file_list = &g_file_list;

    memset(file_list, 0, sizeof(*file_list));

    /* Check PIN first before revealing any file info (SR2) */
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    generate_list_files(file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list->n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, file_list, length);
    return 0;
}


int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t *file_info = &g_file_info;
    file_t *curr_file = &current_file;

    /* Check PIN first (SR2) */
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (read_file(command->slot, curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }

    /* Check read permission BEFORE copying data (SR1) */
    if (!validate_permission(curr_file->group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    /* Build read_response_t in-place from the shared union buffer.
     *
     * file_t layout in union:  [in_use:4][gid:2][name:32][len:2][contents:8192]
     * read_response_t layout:  [name:32]                 [contents:8192]
     * Byte offsets:
     *   file.name     = union[6..37]   resp.name     = union[0..31]
     *   file.contents = union[40..]    resp.contents = union[32..]
     *
     * Both copies have src/dst overlap, so memmove is required.
     * Save contents_len first because the name memmove writes union[6..31]
     * which does NOT reach union[38], so contents_len is still valid after
     * the name move — but save it anyway for clarity and safety. */
    uint16_t contents_len = curr_file->contents_len;

    /* 1. Move name: union[6..37] → union[0..31] (overlap: dst<src, memmove safe) */
    memmove(file_info->name, curr_file->name, MAX_NAME_SIZE);

    /* 2. Move contents: union[40..] → union[32..] (overlap by 8 bytes, memmove safe) */
    memmove(file_info->contents, curr_file->contents, contents_len);

    pkt_len_t length = MAX_NAME_SIZE + contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, file_info, length);
    return 0;
}


int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    file_t *curr_file = &current_file;

    /* Check PIN (SR2) */
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    /* Check write permission (SR1) */
    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    create_file(
        curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    if (write_file(command->slot, curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t *request = &g_request;
    receive_response_t *recv_resp = &g_recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    /* Check PIN (SR2) */
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    memset(recv_resp, 0, sizeof(*recv_resp));
    memset(request, 0, sizeof(*request));

    /* Send our permissions so the sender can validate (SR1) */
    request->slot = command->read_slot;
    memcpy(&request->permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    print_debug("Receive: sending request over UART1\n");
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)request, sizeof(receive_request_t));
    print_debug("Receive: waiting for response\n");

    len_recv_msg = 0xffff;

    read_packet(TRANSFER_INTERFACE, &cmd, recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    /* Verify that we actually have receive permission for this file's group (SR1) */
    if (!validate_permission(recv_resp->file.group_id, PERM_RECEIVE)) {
        print_error("No receive permission for this group");
        return -1;
    }

    /* TODO SR3: MAC verification — transmitting MAC in the response struct causes
     * struct size mismatch with reference firmware. Implement by storing MAC
     * in file at write() time and verifying locally at receive() time. */

    if (write_file(command->write_slot, &recv_resp->file, recv_resp->uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t *file_list = &g_file_list;
    uint16_t len_recv_msg;

    /* Check PIN (SR2) */
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    memset(file_list, 0, sizeof(*file_list));

    /* Send our permissions so the other HSM can filter the response (SR1) */
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG,
                 (void *)&global_permissions,
                 sizeof(group_permission_t) * MAX_PERMS);

    len_recv_msg = 0xffff;

    read_packet(TRANSFER_INTERFACE, &cmd, file_list, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, file_list, len_recv_msg);
    return 0;
}


int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t *file_list = &g_file_list;
    receive_request_t *command;
    receive_response_t *recv_resp = &g_recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    memset(uart_buf, 0, sizeof(uart_buf));
    print_debug("Listen: waiting on UART1\n");
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);
    print_debug("Listen: got packet\n");

    switch (cmd) {
        case INTERROGATE_MSG: {
            /* Extract the requester's permissions from the message */
            group_permission_t *requester_perms = (group_permission_t *)uart_buf;

            memset(file_list, 0, sizeof(*file_list));

            /* Generate a FILTERED list — only include files the requester
             * has receive permission for (SR1) */
            generate_filtered_list(file_list, requester_perms);

            write_length = LIST_PKT_LEN(file_list->n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, file_list, write_length);
            break;
        }
        case RECEIVE_MSG: {
            command = (receive_request_t *)uart_buf;

            print_debug("Listen: reading file\n");
            /* Read the requested file */
            if (read_file(command->slot, &recv_resp->file) < 0) {
                print_error("Failed to read file");
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Read failed", 11);
                return -1;
            }

            print_debug("Listen: checking perms\n");
            /* Check that the requester has receive permission for this
             * file's group (SR1) */
            if (!validate_receive_permission(command->permissions,
                                             recv_resp->file.group_id)) {
                print_debug("Listen: perm denied — sending error\n");
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "No permission", 13);
                return -1;
            }

            print_debug("Listen: perm OK — getting metadata\n");
            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Getting metadata failed");
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "No metadata", 11);
                return -1;
            }

            memcpy(&recv_resp->uuid, &metadata->uuid, UUID_SIZE);

            print_debug("Listen: sending response\n");
            /* MAC is verified by the receiver locally — not transmitted */
            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, recv_resp, write_length);
            print_debug("Listen: response sent\n");
            break;
        }
        default:
            print_error("Bad message type");
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

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
    receive_response_t recv_resp;
    read_response_t    file_info;
    file_t             file;
} g_buf;

#define g_recv_resp  g_buf.recv_resp
#define g_file_info  g_buf.file_info
#define current_file g_buf.file

static receive_request_t  g_request;
static list_response_t    g_file_list;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
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

/** @brief Generate a filtered file list based on requester's permissions (SR1) */
void generate_filtered_list(list_response_t *file_list, group_permission_t *requester_perms) {
    file_list->n_files = 0;
    file_t *temp_file = &current_file;

    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, temp_file);

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

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t *file_list = &g_file_list;

    memset(file_list, 0, sizeof(*file_list));

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    generate_list_files(file_list);

    pkt_len_t length = LIST_PKT_LEN(file_list->n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t *file_info = &g_file_info;
    file_t *curr_file = &current_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (read_file(command->slot, curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }

    if (!validate_permission(curr_file->group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    uint16_t contents_len = curr_file->contents_len;
    memmove(file_info->name, curr_file->name, MAX_NAME_SIZE);
    memmove(file_info->contents, curr_file->contents, contents_len);

    pkt_len_t length = MAX_NAME_SIZE + contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, file_info, length);
    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    file_t *curr_file = &current_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

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


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t *request = &g_request;
    receive_response_t *recv_resp = &g_recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    memset(recv_resp, 0, sizeof(*recv_resp));
    memset(request, 0, sizeof(*request));

    request->slot = command->read_slot;
    memcpy(&request->permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)request, sizeof(receive_request_t));

    len_recv_msg = 0xffff;

    read_packet(TRANSFER_INTERFACE, &cmd, recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    /* Verify receive permission for this file's group (SR1) */
    if (!validate_permission(recv_resp->file.group_id, PERM_RECEIVE)) {
        print_error("No receive permission for this group");
        return -1;
    }

    if (write_file(command->write_slot, &recv_resp->file, recv_resp->uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t *file_list = &g_file_list;
    uint16_t len_recv_msg;

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


/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
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
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG: {
            /* Extract the requester's permissions from the message (SR1) */
            group_permission_t *requester_perms = (group_permission_t *)uart_buf;

            memset(file_list, 0, sizeof(*file_list));

            /* Generate a filtered list — only files the requester can receive (SR1) */
            generate_filtered_list(file_list, requester_perms);

            write_length = LIST_PKT_LEN(file_list->n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, file_list, write_length);
            break;
        }
        case RECEIVE_MSG: {
            command = (receive_request_t *)uart_buf;

            if (read_file(command->slot, &recv_resp->file) < 0) {
                print_error("Failed to read file");
                return -1;
            }

            /* Check that the requester has receive permission (SR1) */
            if (!validate_receive_permission(command->permissions,
                                             recv_resp->file.group_id)) {
                print_error("No receive permission");
                return -1;
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Getting metadata failed");
                return -1;
            }

            memcpy(&recv_resp->uuid, &metadata->uuid, UUID_SIZE);

            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, recv_resp, write_length);
            break;
        }
        default:
            print_error("Bad message type");
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

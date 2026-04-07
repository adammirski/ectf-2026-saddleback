/**
 * @file "simple_uart.c"
 * @author Samuel Meyers
 * @brief UART Interrupt Handler Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_uart.h"

/**********************************************************
 *************** HARDWARE ABSTRACTIONS ********************
 **********************************************************/

// This holds the two UART configurations necessary for communication
UART_Regs *uart_inst[] = {UART_0_INST, UART_1_INST};

UART_Regs *get_uart_handle(int uart_id) {
    if (uart_id < 0 || uart_id > CONFIG_UART_COUNT) {
        // Default on bad input is 0
        return uart_inst[0];
    }
    else {
        return uart_inst[uart_id];
    }
}

/** @brief Reads the next available character from UART.
 *
 *  Blocks until a byte is available on either interface.
 *  The original MITRE reference design uses blocking reads on BOTH UARTs.
 *  A polling timeout on TRANSFER prevents the simulation from context-
 *  switching to the other board, causing the 2-second timeout to fire
 *  before the other board can respond.
 *
 *  @param uart_id The index of UART to use
 *  @return The byte read as an unsigned value (0-255).
*/
int uart_readbyte(int uart_id) {
    return (int)(uint8_t)DL_UART_receiveDataBlocking(get_uart_handle(uart_id));
}

/** @brief Writes a byte to UART (blocking).
 *
 *  @param uart_id The index of UART to use
 *  @param data The byte to be written.
*/
void uart_writebyte(int uart_id, uint8_t data) {
    DL_UART_transmitDataBlocking(get_uart_handle(uart_id), data);
}

/** @brief Check if UART has data available without blocking.
 *
 *  @param uart_id The index of UART to use
 *  @return true if RX FIFO is not empty.
*/
bool uart_has_data(int uart_id) {
    return !DL_UART_Main_isRXFIFOEmpty(get_uart_handle(uart_id));
}


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
 *  For CONTROL_INTERFACE (UART0): blocks indefinitely (host always responds).
 *  For TRANSFER_INTERFACE (UART1): polls with a timeout of ~2 seconds at
 *  32 MHz (≈ 2 000 000 iterations × ~32 cycles each).  Returns -1 on timeout
 *  so callers can unblock without hanging the board.
 *
 *  @param uart_id The index of UART to use
 *  @return The byte read as an unsigned value (0-255), or -1 on timeout.
*/
int uart_readbyte(int uart_id) {
    UART_Regs *uart = get_uart_handle(uart_id);
    if (uart_id == TRANSFER_INTERFACE) {
        /* Non-blocking poll with timeout for board-to-board UART.
         * Without this the board hangs forever when the other side
         * never responds (e.g. engineer not in listen mode), making
         * every subsequent CONTROL_INTERFACE command also time out. */
        for (uint32_t i = 12000000UL; i > 0; i--) {
            if (!DL_UART_Main_isRXFIFOEmpty(uart)) {
                return (int)(uint8_t)DL_UART_Main_receiveData(uart);
            }
        }
        return -1;  /* timeout — let callers handle it */
    }
    return (int)(uint8_t)DL_UART_receiveDataBlocking(uart);
}

/** @brief Writes a byte to UART.
 *
 *  For TRANSFER_INTERFACE: polls with timeout (~2s at 32 MHz) so the board
 *  doesn't hang permanently when the other side has stopped reading.
 *  For CONTROL_INTERFACE: blocks indefinitely (host always reads).
 *
 *  @param uart_id The index of UART to use
 *  @param data The byte to be written.
 *  @return 0 on success, -1 on timeout (TRANSFER only).
*/
int uart_writebyte(int uart_id, uint8_t data) {
    UART_Regs *uart = get_uart_handle(uart_id);
    if (uart_id == TRANSFER_INTERFACE) {
        /* Poll with timeout — symmetric with uart_readbyte timeout.
         * DL_UART_transmitDataBlocking just spins on isBusy/isTXFIFOFull
         * then calls transmitData; we replicate that with a timeout. */
        for (uint32_t i = 12000000UL; i > 0; i--) {
            if (!DL_UART_isBusy(uart)) {
                DL_UART_transmitDataBlocking(uart, data);
                return 0;
            }
        }
        return -1;  /* timeout — other board stopped reading */
    }
    DL_UART_transmitDataBlocking(uart, data);
    return 0;
}

/** @brief Check if UART has data available without blocking.
 *
 *  @param uart_id The index of UART to use
 *  @return true if RX FIFO is not empty.
*/
bool uart_has_data(int uart_id) {
    return !DL_UART_Main_isRXFIFOEmpty(get_uart_handle(uart_id));
}


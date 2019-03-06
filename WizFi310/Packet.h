/*
 * Copyright (c) 2015 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WIZFI310_PACKET_H__
#define WIZFI310_PACKET_H__

#include "mbed.h"

/** Received packet.
 *
 * @warning Packets keep a reference into their source network interface.
 * They shall never outlive this interface.
 */
class Packet {
public:
    /**
     * Creates a new packet tracking memory usage in heap_usage.
     *
     * @param size          Size of the packet.
     * @param heap_usage    reference to a volatile long integer thread safely
     *                      keeping track of the memory usage.
     * @return A new packet or NULL on failure.
     */
    static Packet *new_packet(uint32_t size, volatile uint32_t &heap_usage);

    /**
     * Size of the packet.
     */
    uint32_t size() const
    {
        return m_size;
    }
    /**
     * Amount of data store in the packet.
     */
    uint32_t len() const
    {
        return m_len;
    }
    /**
     * Pointer to the internal buffer.
     */
    const char *data() const
    {
        return m_data;
    }
    /**
     * Pointer to the next packet in the chain or NULL if none.
     */
    Packet *next() const
    {
        return m_next;
    }

    /**
     * Appends up to `len` bytes from `data` into this packet and returns
     * the number of bytes copied.
     * @param   data    Source buffer.
     * @param   len     Source length.
     * @return number of bytes copied.
     */
    uint32_t append(const char *data, uint32_t len);
    /**
     * Consumes up to `len` bytes from this packet in to `data`.
     * @param   data    Output buffer.
     * @param   len     Output buffer length.
     * @return number of bytes copied into `data`.
     */
    uint32_t consume(char *data, uint32_t len);
    /**
     * Sets the pointer to next target.
     * @note Setting to NULL will not delete the next packet but simply detach it.
     */
    void set_next(Packet *next);

    /**
     * Deletes this packet and its following packets in the chain.
     * @warning it is unsafe to delete a packet that is referenced by another packet.
     */
    ~Packet();

private:
    Packet *m_next;
    // packet's payload len.
    uint32_t m_len;
    // packet's size/capacity
    uint32_t m_size;
    // packet's payload.
    char *m_data;
    volatile uint32_t &m_ref_heap_usage;

    Packet(uint32_t size, volatile uint32_t &heap_usage): m_next(NULL), m_len(0), m_size(size), m_data(NULL), m_ref_heap_usage(heap_usage)
    {
        // this construct also prevents public from
        // using new by disabling generic constructors.
    }
};

#endif

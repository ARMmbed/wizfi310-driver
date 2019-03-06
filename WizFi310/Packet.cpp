/*
 * Copyright (c) 2018 ARM Limited
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

#include "Packet.h"

// =================================================================================================
// Packet class members.
Packet *Packet::new_packet(uint32_t size, volatile uint32_t &heap_usage)
{
    Packet *p = new (std::nothrow) Packet(size, heap_usage);
    if (p != NULL) {
        char *data = new (std::nothrow) char[size];
        if (data != NULL) {
            p->m_data = data;
            uint32_t l = heap_usage;
            uint32_t l2 = core_util_atomic_incr_u32(&heap_usage, size);
            // tr_debug("%p: allocating heap (%p)%lu+%lu=%lu", p, &heap_usage, l, size, l2);
            (void)l;
            (void)l2;
        } else {
            delete p;
            p = NULL;
        }
    }
    return p;
}

uint32_t Packet::append(const char *data, uint32_t len)
{
    uint32_t cpy_len = m_size - m_len;
    if (cpy_len > len) {
        cpy_len = len;
    }
    // tr_debug("%p::append(%p, %lu){%lu/%lu}: %lu", this, data, len, m_len, m_size, cpy_len);
    memcpy(m_data + m_len, data, cpy_len);
    m_len += cpy_len;
    return cpy_len;
}

uint32_t Packet::consume(char *data, uint32_t len)
{
    uint32_t read = m_len;
    if (len < read) {
        read = len;
    }
    // tr_debug("%p::consume(%p, %lu){%lu/%lu}: %lu", this, data, len, m_len, m_size, read);
    memcpy(data, m_data, read);
    m_len -= read;
    memmove(m_data, m_data + read, m_len);
    return read;
}

void Packet::set_next(Packet *next)
{
    // if (m_next != NULL) {
    //     tr_debug("%p::set_next(%p): detaching from %p", this, next, m_next);
    // }
    // tr_debug("%p::set_next(%p): attaching to %p", this, next, next);
    m_next = next;
}

Packet::~Packet()
{
    if (m_data != NULL) {
        delete m_data;
    }
    if (m_next != NULL) {
        // tr_debug("%p: delete next: %p", this, m_next);
        delete m_next;
    }
    uint32_t l = m_ref_heap_usage;
    uint32_t l2 = core_util_atomic_decr_u32(&m_ref_heap_usage, m_size);
    // tr_debug("%p: freeing heap: (%p)%lu-%lu=%lu", this, &m_ref_heap_usage, l, m_size, l2);
    (void)l;
    (void)l2;
}

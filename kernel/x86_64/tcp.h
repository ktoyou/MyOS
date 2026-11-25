#ifndef X86_64_TCP_H
#define X86_64_TCP_H

#include "../types.h"

struct tcp64_connection;

long tcp64_open(u64 now, u32 source, u16 local_port, u32 destination, u16 remote_port,
                struct tcp64_connection **out);
bool tcp64_port_used(u16 port);
long tcp64_connect_result(const struct tcp64_connection *connection);
i32 tcp64_error(struct tcp64_connection *connection, bool clear);
u16 tcp64_events(const struct tcp64_connection *connection);
/* Копирование не удаляет данные. После успешной записи пользователю вызывается consume. */
long tcp64_read(struct tcp64_connection *connection, void *buffer, u32 length);
void tcp64_consume(struct tcp64_connection *connection, u32 bytes);
long tcp64_write(struct tcp64_connection *connection, const void *buffer, u32 length);
void tcp64_shutdown(struct tcp64_connection *connection, i32 how);
void tcp64_close(struct tcp64_connection *connection, u64 now);
bool tcp64_tick(u64 now);
void tcp64_input(u64 now, u32 source, u32 destination, const u8 *segment, u32 length);

#endif

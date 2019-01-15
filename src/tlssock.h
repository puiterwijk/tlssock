/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Nathaniel McCallum
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#pragma once

#include <linux/types.h>
#include <bits/posix1_lim.h>
#include <bits/sockaddr.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#define AF_DNS 253
#define IPPROTO_TLS 253
#define TLS_CLT_HANDSHAKE 1
#define TLS_SRV_HANDSHAKE 2

struct sockaddr_dns {
  sa_family_t sdns_family;
  __be16 sdns_port;                             /* Port number                  */
  char sdns_hostname[_POSIX_HOST_NAME_MAX+1];  /* NULL-terminated */
};

typedef struct {
  void *misc;

  ssize_t (*psk)(void *misc, char **username, uint8_t **key);
} tls_clt_handshake_t;

typedef struct {
  void *misc;

  ssize_t (*psk)(void *misc, const char *username, uint8_t **key);
} tls_srv_handshake_t;

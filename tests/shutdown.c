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

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

static void
test_errno(int expected)
{
  if (errno != expected) {
    fprintf(stderr, "expected: %d: %s\n", expected, strerror(expected));
    fprintf(stderr, "received: %d: %m\n", errno);
    _exit(1);
  }
}

static void
test(int domain, int type)
{
  int fd;

  fd = socket(domain, type, 0);
  assert(fd >= 0);

  assert(shutdown(fd, SHUT_RDWR) == -1);
  test_errno(ENOTCONN);
}

int
main(int argc, const char *argv[])
{
  assert(shutdown(-1, SHUT_RDWR) == -1);
  test_errno(EBADF);

  assert(shutdown(1011, SHUT_RDWR) == -1);
  test_errno(EBADF);

  test(AF_INET, SOCK_STREAM);
  test(AF_INET, SOCK_DGRAM);
  test(AF_INET6, SOCK_STREAM);
  test(AF_INET6, SOCK_DGRAM);
}

/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/helper.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

uint64_t cw_uint64_t_to_the_power(uint64_t base, uint64_t exponent)
{
    if (base == 0)
        return 0;

    if (exponent == 0)
        return 1;

    if (exponent == 1)
        return base;

    if (exponent == 2)
        return base * base;

    uint64_t power = 1;

    for (uint64_t i = 0; i < exponent; i++)
    {
        power *= base;
    }

    return power;
}

int cw_cipher_misc_compare_file_pointers_internal(FILE *one, FILE *two)
{
    if (one == NULL || two == NULL)
        return 0;

    struct stat stat1, stat2;

    int fd1 = fileno(one);
    int fd2 = fileno(two);

    if (fstat(fd1, &stat1) < 0)
        return -1;
    if (fstat(fd2, &stat2) < 0)
        return -1;
    return (stat1.st_dev == stat2.st_dev) && (stat1.st_ino == stat2.st_ino);
}
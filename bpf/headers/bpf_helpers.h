/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Minimal bpf_helpers.h — subset of libbpf's upstream header, pinned
 * here so the repository builds reproducibly without vendoring all of
 * libbpf. If we later need more helpers (for example, ring buffers or
 * CO-RE read helpers), extend this file rather than adding a libbpf
 * submodule: the goal is one owned BPF program, not a full libbpf
 * integration.
 *
 * Derived from the definitions that ship with libbpf (BSD-2-Clause /
 * LGPL-2.1) and that the upstream kernel exposes in
 * tools/lib/bpf/bpf_helpers.h.
 */

#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef __array
#define __array(name, val) typeof(val) *name[]
#endif

/* Helper call IDs used below. */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3

/* Matches the upstream BPF helper signatures. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;

static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;

static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;

#endif /* __BPF_HELPERS_H */

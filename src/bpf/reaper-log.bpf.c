// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jan Glauber @ Digitalocean.com

#include "vmlinux.h"

// from kernel tools/lib/bpf/ or libbpf-dev
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// BTF doesn't support defines. Keep these in sync with kernel!
#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)
#define TASK_COMM_LEN	16
#define DISK_NAME_LEN	32


#define MAX_ENTRIES	102400
#define MAX_SLOTS	27

const volatile unsigned int linux_kernel_version;

#define INT_FLAG_TRACE_REQ	1
#define INT_FLAG_TRACE_BIO	2

/*
 * Warning: This must match byte-for-byte go's struct ioEvent or received data will be corrupted!
 * Also, values must align naturally to a __packed layout, e.g. adding a u32 at the beginning breaks
 * the alignment and perf event reads garbage.
 */
struct io_event_t {
	u32 pid;
	u32 rwflag;
	u32 major;
	u32 minor;
	u32 old_major;
	u32 old_minor;
	u64 len;
	u64 delta;
	u64 sector;
	u64 old_sector;
	char name[TASK_COMM_LEN];
	char disk_name[DISK_NAME_LEN];
	u32 int_flag;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_ENTRIES);
} events SEC(".maps");

struct taskinfo_t {
	u32 pid;
	char name[TASK_COMM_LEN];
};

// hashes for bio tracking

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct bio *);
	__type(value, struct taskinfo_t);
	__uint(max_entries, MAX_ENTRIES);
} bio_taskinfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct bio *);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} bio_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct bio *);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} bio_len SEC(".maps");

/*
 * Raw tracepoint args are from the tracepoints _before_ TP_fast_assign
 * See: TRACE_EVENT and TP_PROTO in include/trace/events/block.h
 * args are passed as u64[]. No pt_regs here, perf_submit accepts the args
 * pointer instead.
 */

// struct request_queue was removed after 5.10 from trace_block_bio_queue
SEC("raw_tracepoint/block_bio_queue")
int BPF_PROG(trace_bio_start, struct bio *bio)
{
	u64 ts = bpf_ktime_get_ns();
	u64 len;

	bpf_map_update_elem(&bio_start, &bio, &ts, 0);

	struct taskinfo_t ti = {};
	bpf_get_current_comm(&ti.name, sizeof(ti.name));
	ti.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&bio_taskinfo, &bio, &ti, 0);

	len = BPF_CORE_READ(bio, bi_iter.bi_size); // XXX maybe need to split into two lookups
	bpf_map_update_elem(&bio_len, &bio, &len, 0);

	return 0;
}

// error argument got removed by commit d24de76af836260a99ca2ba281a937bd5bc55591 in 5.8
SEC("raw_tracepoint/block_bio_complete")
int BPF_PROG(trace_bio_done, struct request_queue *q, struct bio *bio)
{
	u64 now = bpf_ktime_get_ns();
	struct io_event_t data = {};
	struct taskinfo_t *ti;
	u64 *tsp, *lenp, delta;

	// fetch timestamp and calculate delta
	tsp = bpf_map_lookup_elem(&bio_start, &bio);
	if (!tsp) {
		return 0;   // missed issue or disk not traced
	}

	data.sector = BPF_CORE_READ(bio, bi_iter.bi_sector);
	// ignore if sector is 0
	if (!data.sector)
		goto cleanup;

	struct block_device *bdev;
	struct gendisk *disk;
        bdev = BPF_CORE_READ(bio, bi_bdev);
        disk = BPF_CORE_READ(bdev, bd_disk);

	bpf_probe_read_kernel_str(&data.disk_name, sizeof(data.disk_name), disk->disk_name);
	data.major = BPF_CORE_READ(disk, major);
	data.minor = BPF_CORE_READ(disk, first_minor);

	delta = now - *tsp;
	delta /= 1000;
	data.delta = delta;

	ti = bpf_map_lookup_elem(&bio_taskinfo, &bio);
	if (!ti) {
		bpf_get_current_comm(&data.name, sizeof(data.name));
		data.pid = bpf_get_current_pid_tgid() >> 32;
	} else {
		data.pid = ti->pid;
		bpf_probe_read_kernel_str(&data.name, sizeof(data.name), ti->name);
	}

	lenp = bpf_map_lookup_elem(&bio_len, &bio);
	if (!lenp) {
		data.len = 0;	// cannot happen
	} else {
		data.len = *lenp;
	}

	data.rwflag = BPF_CORE_READ(bio, bi_opf);
	data.rwflag &= REQ_OP_MASK;
	data.int_flag = INT_FLAG_TRACE_BIO;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

cleanup:
	bpf_map_delete_elem(&bio_start, &bio);
	bpf_map_delete_elem(&bio_taskinfo, &bio);
	bpf_map_delete_elem(&bio_len, &bio);
	return 0;
}

char _license[] SEC("license") = "GPL";

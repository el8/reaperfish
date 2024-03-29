// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jan Glauber @ Digitalocean.com

#include "vmlinux.h"

// from kernel tools/lib/bpf/
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// BTF doesn't support defines. Keep these in sync with kernel!
#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)
#define TASK_COMM_LEN	16
#define DISK_NAME_LEN	32

#define REQ_OP_READ	0
#define	REQ_OP_WRITE	1
#define	REQ_OP_FLUSH	2
#define	REQ_OP_DISCARD	3

#define MAX_ENTRIES	102400

struct taskinfo_t {
	u32 pid;
	char name[TASK_COMM_LEN];
};

struct hist_key {
        u32 pid;
	u32 flag;
};

#define MAX_SLOTS       32

struct hist {
        __u32 rd_slots[MAX_SLOTS];
        __u32 wr_slots[MAX_SLOTS];
};

struct bpf_map_def SEC("maps/hists") hists = {
	.type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct hist_key),
	.value_size = sizeof(struct hist),
	.max_entries = MAX_ENTRIES,
};

struct iodata_key {
        u32 pid;
        u32 flag;
};

// time values are in microseconds
struct iodata_val {
        u64 read_nr;
        u64 write_nr;
        u64 read_bytes;
        u64 write_bytes;
        u64 read_time;
        u64 write_time;
};

struct bpf_map_def SEC("maps/iodata") process_iodata = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct iodata_key),
        .value_size = sizeof(struct iodata_val),
        .max_entries = MAX_ENTRIES,
};

static __always_inline u64 log2(u32 v)
{
        u32 shift, r;

        r = (v > 0xFFFF) << 4; v >>= r;
        shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
        shift = (v > 0xF) << 2; v >>= shift; r |= shift;
        shift = (v > 0x3) << 1; v >>= shift; r |= shift;
        r |= (v >> 1);

        return r;
}

static __always_inline u64 log2l(u64 v)
{
        u32 hi = v >> 32;

        if (hi)
                return log2(hi) + 32;
        else
                return log2(v);
}

// hashes for bio tracking

// TODO: structify
struct bpf_map_def SEC("maps/bio_taskinfo") bio_taskinfo = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct bio *),
	.value_size = sizeof(struct taskinfo_t),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps/bio_start") bio_start = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct bio *),
	.value_size = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps/bio_len") bio_len = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct bio *),
	.value_size = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};

/*
 * Raw tracepoint args are from the tracepoints _before_ TP_fast_assign
 * See: TRACE_EVENT and TP_PROTO in include/trace/events/block.h
 * args are passed as u64[]. No pt_regs here, perf_submit accepts the args
 * pointer instead.
 */

SEC("raw_tracepoint/block_bio_queue")
int BPF_PROG(trace_bio_start, struct bio *bio)
{
	u64 ts = bpf_ktime_get_ns();
	u64 len;
	struct hist_key key = {};
	struct hist *histp;
	struct hist initial_hist = {};
	struct iodata_key iokey = {};
	struct iodata_val *iodata;
        struct iodata_val initial_data = {};

	bpf_map_update_elem(&bio_start, &bio, &ts, 0);

	struct taskinfo_t ti = {};
	bpf_get_current_comm(&ti.name, sizeof(ti.name));
	ti.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&bio_taskinfo, &bio, &ti, 0);

	len = BPF_CORE_READ(bio, bi_iter.bi_size); // XXX maybe need to split into two lookups
	bpf_map_update_elem(&bio_len, &bio, &len, 0);

	key.pid = ti.pid;
	iokey.pid = ti.pid;
	histp = bpf_map_lookup_elem(&hists, &key);
	if (!histp) {
		// unknown, create new histograms
		bpf_map_update_elem(&hists, &key, &initial_hist, 0);
	}

	iodata = bpf_map_lookup_elem(&process_iodata, &iokey);
        if (!iodata) {
                // unknown process, create new entry
                bpf_map_update_elem(&process_iodata, &iokey, &initial_data, 0);
        }

	return 0;
}

SEC("raw_tracepoint/block_bio_complete")
int BPF_PROG(trace_bio_done, struct request_queue *q, struct bio *bio)
{
	u64 now = bpf_ktime_get_ns();
	u64 *tsp, *lenp, delta, slot;
	char disk_name[DISK_NAME_LEN];
	u32 major, minor;
	struct taskinfo_t *ti;
	struct hist_key key = {};
	struct hist *histp;
	struct iodata_key iokey = {};
	struct iodata_val *iodata;

	// fetch timestamp and calculate delta
	tsp = bpf_map_lookup_elem(&bio_start, &bio);
	if (!tsp) {
		return 0;   // missed issue or untraced disk
	}

	u64 sector = BPF_CORE_READ(bio, bi_iter.bi_sector);
	// ignore if sector is 0
	if (!sector) {
		goto cleanup;
	}

	delta = now - *tsp;
	delta /= 1000;

	struct block_device *bdev;
	struct gendisk *disk;
        bdev = BPF_CORE_READ(bio, bi_bdev);
	disk = BPF_CORE_READ(bdev, bd_disk);

	bpf_probe_read_kernel_str(&disk_name, sizeof(disk_name), disk->disk_name);
	major = BPF_CORE_READ(disk, major);
	minor = BPF_CORE_READ(disk, first_minor);

	char name[TASK_COMM_LEN];
	u32 pid;
	ti = bpf_map_lookup_elem(&bio_taskinfo, &bio);
	if (!ti) {
		bpf_get_current_comm(&name, sizeof(name));
		pid = bpf_get_current_pid_tgid() >> 32;
	} else {
		pid = BPF_CORE_READ(ti, pid);
		bpf_probe_read_kernel_str(&name, sizeof(name), ti->name);
	}

	u64 len;
	lenp = bpf_map_lookup_elem(&bio_len, &bio);
	if (!lenp) {
		len = 0;	// cannot happen
	} else {
		len = *lenp;
	}

	u32 rwflag = BPF_CORE_READ(bio, bi_opf);
	rwflag &= REQ_OP_MASK;

	key.pid = pid;
	iokey.pid = pid;

	// sort delta into histogram bucket for pid
	histp = bpf_map_lookup_elem(&hists, &key);
	if (!histp) {
		// can happen but should not happen often
		goto cleanup;
	}

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	if (rwflag == REQ_OP_READ) {
		__sync_fetch_and_add(&histp->rd_slots[slot], 1);

		__sync_fetch_and_add(&iodata->read_nr, 1);
		__sync_fetch_and_add(&iodata->read_bytes, len);
		__sync_fetch_and_add(&iodata->read_time, delta);
	} else if (rwflag == REQ_OP_WRITE) {
		__sync_fetch_and_add(&histp->wr_slots[slot], 1);

		__sync_fetch_and_add(&iodata->write_nr, 1);
		__sync_fetch_and_add(&iodata->write_bytes, len);
		__sync_fetch_and_add(&iodata->write_time, delta);
	}

cleanup:
	bpf_map_delete_elem(&bio_start, &bio);
	bpf_map_delete_elem(&bio_taskinfo, &bio);
	bpf_map_delete_elem(&bio_len, &bio);
	return 0;
}

char _license[] SEC("license") = "GPL";

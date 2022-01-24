// bpftool btf dump file /sys/kernel/btf/vmlinux format c
#include "include/vmlinux.h"

// from kernel tools/lib/bpf/
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

#include <linux/version.h>
extern int LINUX_KERNEL_VERSION __kconfig;

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

static __always_inline
int disk_traced(struct bio *bio)
{
	u32 major, minor;
	struct block_device *bdev;
	struct gendisk *disk;
	disk = BPF_CORE_READ(bio, bi_disk);
	major = BPF_CORE_READ(disk, major);
	minor = BPF_CORE_READ(disk, first_minor);

	// drop all events that are not originating from lvm/dm, can even filter for /var/lib/libvirt/images
	// this needs either hardcoded major:minor values or some better way of telling BPF what to filter here
	if (major != 253)
		return 0;
	else
		return 1;
}

static __always_inline
int process_traced(void)
{
	char name[TASK_COMM_LEN];
	const char filter[] = "qemu-system-x86_64";
	bpf_get_current_comm(&name, sizeof(name));

	// LLVM issue, no memcmp available
	//return __builtin_memcmp(filter, (const char *)name, 18) == 0;
	if (name[0] == 'q' && name[1] == 'e' && name[2] == 'm' && name[3] == 'u')
		return 1;
	else
		return 0;
}

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)

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
int BPF_PROG(trace_bio_start, struct request_queue *q, struct bio *bio)
{
	u64 ts = bpf_ktime_get_ns();
	u64 len;
	struct hist_key key = {};
	struct hist *histp;
	struct hist initial_hist = {};

	if (!disk_traced(bio))
		return 0;
	if (!process_traced())
		return 0;
	bpf_map_update_elem(&bio_start, &bio, &ts, 0);

	struct taskinfo_t ti = {};
	bpf_get_current_comm(&ti.name, sizeof(ti.name));
	ti.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&bio_taskinfo, &bio, &ti, 0);

	len = BPF_CORE_READ(bio, bi_iter.bi_size); // XXX maybe need to split into two lookups
	bpf_map_update_elem(&bio_len, &bio, &len, 0);

	key.pid = ti.pid;
	histp = bpf_map_lookup_elem(&hists, &key);
	if (!histp) {
		// unknown droplet, create new histograms
		//bpf_printk("new droplet pid: %d  comm: %s\n", ti.pid, ti.name);
		bpf_map_update_elem(&hists, &key, &initial_hist, 0);
	} else {
		//bpf_printk("known droplet pid: %d  comm: %s\n", ti.pid, ti.name);
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

	struct gendisk *disk;
	disk = BPF_CORE_READ(bio, bi_disk);
	bpf_probe_read_kernel_str(&disk_name, sizeof(disk_name), disk->disk_name);
	major = BPF_CORE_READ(disk, major);
	minor = BPF_CORE_READ(disk, first_minor);

	// drop all but dm/lvm, should be catched by !tsp above already
	if (major != 253) {
		goto cleanup;
	}

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
		len = 666;	// cannot happen
	} else {
		len = *lenp;
	}

	u32 rwflag = BPF_CORE_READ(bio, bi_opf);
	rwflag &= REQ_OP_MASK;

	//bpf_printk("PID: %d  comm: %s\n", pid, name);

	// sort delta into histogram bucket for pid
	key.pid = pid;
	histp = bpf_map_lookup_elem(&hists, &key);
	if (!histp) {
		// can happen but should not happen often
		bpf_printk("debug: missing histogram for pid: %d\n", pid);
		goto cleanup;
	}

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	if (rwflag == REQ_OP_READ)
		__sync_fetch_and_add(&histp->rd_slots[slot], 1);
	else if (rwflag == REQ_OP_WRITE)
		__sync_fetch_and_add(&histp->wr_slots[slot], 1);
	//bpf_printk("hist++ pid: %d  slot: %d  delta: %d\n", pid, slot, delta);

cleanup:
	bpf_map_delete_elem(&bio_start, &bio);
	bpf_map_delete_elem(&bio_taskinfo, &bio);
	bpf_map_delete_elem(&bio_len, &bio);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

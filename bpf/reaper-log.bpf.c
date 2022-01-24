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


#define MAX_ENTRIES	102400
#define MAX_SLOTS	27

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
	u32 internal;	// 1 = req, 2 = bio
};

struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = MAX_ENTRIES,
};

struct taskinfo_t {
	u32 pid;
	char name[TASK_COMM_LEN];
};

// hashes for request tracking
struct bpf_map_def SEC("maps/req_taskinfo") req_taskinfo = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct request *),
	.value_size = sizeof(struct taskinfo_t),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps/req_start") req_start = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct request *),
	.value_size = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps/req_len") req_len = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct request *),
	.value_size = sizeof(u64),
	.max_entries = MAX_ENTRIES,
};


#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)

// cache PID and comm by-req
SEC("kprobe/blk_account_io_start")
int BPF_KPROBE(trace_pid_start, struct request *req)
{
	struct taskinfo_t ti = {};

	if (bpf_get_current_comm(&ti.name, sizeof(ti.name)) == 0) {
		ti.pid = bpf_get_current_pid_tgid() >> 32;
	} else {
	    ti.pid = 667;	// cannot happen
	}
	bpf_map_update_elem(&req_taskinfo, &req, &ti, 0);
	return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(trace_req_start, struct request *req)
{
	u64 ts = bpf_ktime_get_ns();
	u64 len;

	bpf_map_update_elem(&req_start, &req, &ts, 0);

	// need to record len here as it will become 0 when the request is finished
	len = BPF_CORE_READ(req, __data_len);
	bpf_map_update_elem(&req_len, &req, &len, 0);
	return 0;
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(trace_req_done, struct request *req)
{
	u64 *tsp, *lenp, delta;
	struct io_event_t data = {};
	struct taskinfo_t *ti;
	u64 now = bpf_ktime_get_ns();
	u64 slot;

	// fetch timestamp and calculate delta
	tsp = bpf_map_lookup_elem(&req_start, &req);
	if (!tsp) {
		return 0;   // missed issue
	}

	/*
	 * Sanity check sector, it might be zero (re-allocated req after missing an end event?)
	 * and would produce a too large delta so drop these spurious latency outliers.
	 */
	data.sector = BPF_CORE_READ(req, __sector);
	if (!data.sector) {
		bpf_map_delete_elem(&req_start, &req);
		bpf_map_delete_elem(&req_len, &req);
		return 0;
	}

	delta = now - *tsp;
	delta /= 1000;
	data.delta = delta;

	ti = bpf_map_lookup_elem(&req_taskinfo, &req);
	if (!ti) {
		bpf_get_current_comm(&data.name, sizeof(data.name));
		data.pid = bpf_get_current_pid_tgid() >> 32;
	} else {
		data.pid = BPF_CORE_READ(ti, pid);
		bpf_probe_read_kernel_str(&data.name, sizeof(data.name), ti->name);

	}

	struct gendisk *rq_disk = BPF_CORE_READ(req, rq_disk);
	bpf_probe_read_kernel_str(&data.disk_name, sizeof(data.disk_name),
				rq_disk->disk_name);
	data.major = BPF_CORE_READ(req, rq_disk, major);
	data.minor = BPF_CORE_READ(req, rq_disk, first_minor);

	lenp = bpf_map_lookup_elem(&req_len, &req);
	if (!lenp) {
		data.len = 0;	// shouldn't happen but does with bio, TODO: debug
	} else {
		data.len = *lenp;
	}
	data.rwflag = BPF_CORE_READ(req, cmd_flags) & REQ_OP_MASK;
	data.internal = 1;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

cleanup:
	bpf_map_delete_elem(&req_taskinfo, &req);
	bpf_map_delete_elem(&req_start, &req);
	bpf_map_delete_elem(&req_len, &req);
	return 0;
}

// hashes for bio tracking

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

// bi_disk is replaced by struct block_device *bi_bdev
// 309dca309fc39a9e3c31b916393b74bd174fd74e
// after 5.11
static __always_inline
int disk_traced(struct bio *bio)
{
	u32 major, minor;
	struct block_device *bdev;
	struct gendisk *disk;
//if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0)) {
//	bdev = BPF_CORE_READ(bio, bi_bdev);
//	disk = BPF_CORE_READ(bdev, bd_disk);
//} else {
//}
//	bdev = bpf_core_field_exists(bio->bi_bdev) ? BPF_CORE_READ(bio, bi_bdev) : NULL;
//	if (!bdev)
//		disk = BPF_CORE_READ(bdev, bd_disk);
//	else
//		disk = BPF_CORE_READ(bio, bi_disk);
	bdev = BPF_CORE_READ(bio, bi_bdev);
	disk = BPF_CORE_READ(bdev, bd_disk);

	major = BPF_CORE_READ(disk, major);
	minor = BPF_CORE_READ(disk, first_minor);

	// drop all events that are not originating from lvm/dm, can even filter for /var/lib/libvirt/images
	// this needs either hardcoded major:minor values or some better way of telling BPF what to filter here
	if (major != 253)
		return 0;
	else
		return 1;
}

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

	if (!disk_traced(bio))
		return 0;

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
	if (!data.sector) {
		goto cleanup;
	}

	struct block_device *bdev;
	struct gendisk *disk;
        bdev = BPF_CORE_READ(bio, bi_bdev);
        disk = BPF_CORE_READ(bdev, bd_disk);

	bpf_probe_read_kernel_str(&data.disk_name, sizeof(data.disk_name), disk->disk_name);
	data.major = BPF_CORE_READ(disk, major);
	data.minor = BPF_CORE_READ(disk, first_minor);

	// drop everything that is not lvm/dm. Should not happen as these will fail on tsp already.
	if (data.major != 253) {
		goto cleanup; // might be redundant with !tsp check above
	}

	delta = now - *tsp;
	delta /= 1000;
	data.delta = delta;

	ti = bpf_map_lookup_elem(&bio_taskinfo, &bio);
	if (!ti) {
		bpf_get_current_comm(&data.name, sizeof(data.name));
		data.pid = bpf_get_current_pid_tgid() >> 32;
	} else {
		data.pid = BPF_CORE_READ(ti, pid);
		bpf_probe_read_kernel_str(&data.name, sizeof(data.name), ti->name);
	}

	lenp = bpf_map_lookup_elem(&bio_len, &bio);
	if (!lenp) {
		data.len = 666;	// cannot happen
	} else {
		data.len = *lenp;
	}

	data.rwflag = BPF_CORE_READ(bio, bi_opf);
	data.rwflag &= REQ_OP_MASK;
	data.internal = 2;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

cleanup:
	bpf_map_delete_elem(&bio_start, &bio);
	bpf_map_delete_elem(&bio_taskinfo, &bio);
	bpf_map_delete_elem(&bio_len, &bio);
	return 0;
}

// from: include/linux/kdev_t.h
#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)

#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))

SEC("raw_tracepoint/block_bio_remap")
int BPF_PROG(trace_bio_remap, struct request_queue *q, struct bio *bio, dev_t dev, sector_t from)
{
	struct io_event_t data = {};
	struct taskinfo_t *ti;
	u64 *lenp;

	data.sector = BPF_CORE_READ(bio, bi_iter.bi_sector);
	if (!data.sector) {
		return 0;
	}

	ti = bpf_map_lookup_elem(&bio_taskinfo, &bio);
	if (!ti) {
		bpf_get_current_comm(&data.name, sizeof(data.name));
		data.pid = 123456;
	} else {
		data.pid = BPF_CORE_READ(ti, pid);
		bpf_probe_read_kernel_str(&data.name, sizeof(data.name), ti->name);
	}

	struct block_device *bdev;
	struct gendisk *disk;

	bdev = BPF_CORE_READ(bio, bi_bdev);
	disk = BPF_CORE_READ(bdev, bd_disk);

	bpf_probe_read_kernel_str(&data.disk_name, sizeof(data.disk_name), disk->disk_name);
	data.major = BPF_CORE_READ(disk, major);
	data.minor = BPF_CORE_READ(disk, first_minor);

	lenp = bpf_map_lookup_elem(&bio_len, &bio);
	if (!lenp) {
		data.len = 666;	// cannot happen
	} else {
		data.len = *lenp;
	}

	data.rwflag = BPF_CORE_READ(bio, bi_opf);
	data.rwflag &= REQ_OP_MASK;
	data.delta = -1;
	data.internal = 3;

	data.old_sector = from;
	data.old_major = dev >> 20;
	data.old_minor = dev & MINORMASK;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;

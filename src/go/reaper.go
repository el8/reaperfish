package main

import (
	"bufio"
	"bytes"
	"C"
	"encoding/binary"
	"io/ioutil"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"math"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
        "syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	REQ_OP_READ = 0
	REQ_OP_WRITE = 1
	REQ_OP_FLUSH = 2
	REQ_OP_DISCARD = 3
)

/*
 * Warning: This must match byte-for-byte BPF's struct io_event_t or received data will be corrupted!
 */
type ioEvent struct {
	Pid		int32		// using int does not work as it breaks reading the perf events...
	RWFlag		uint32		// REQ_OP_* include/linux/blk_types.h
	Major		uint32
	Minor		uint32
	OldMajor	uint32
	OldMinor	uint32
	Len		uint64
	Delta		uint64
	Sector		uint64
	OldSector	uint64
	Comm		[16]byte
	Disk		[32]byte
	Internal	int32		// event type (req or bio)
}

var optMonitor		bool
var optLogEvents	bool
var optDebug		bool
var optTraceReq		bool
var optTraceBio		bool
var optHeadless		bool
var optCSV		bool
var optBPFHist		bool
var optColor		bool

// handle SIGINT
var exiting bool

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

// store these so deferred close on Link object does not close it on exiting the helper function
// TODO: doesn't work...
var Progs = []*ebpf.Program{}
var Points = []*link.Link{}

// helper for kprobes
func register_kprobe(coll *ebpf.Collection, bpf_fname string, kprobe_name string) (error) {
	prog := coll.DetachProgram(bpf_fname)
	if prog == nil {
		fmt.Fprintf(os.Stderr, "BPF kprobe %s not found", bpf_fname)
	}
	defer prog.Close()

	kp, err := link.Kprobe(kprobe_name, prog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opening kprobe %s error: %s", kprobe_name, err)
        }
        defer kp.Close()
	Progs = append(Progs, prog)
	Points = append(Points, &kp)
	fmt.Fprintf(os.Stderr, "Attached kprobe: %s\n", kprobe_name)
	return nil
}

// helper for raw tracepoints
func register_raw_tp(coll *ebpf.Collection, bpf_fname string, tp_name string) (error) {
	prog := coll.DetachProgram(bpf_fname)
	if prog == nil {
		log.Fatalf("BPF raw tracepoint %s not found", bpf_fname)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions {
		Name:    tp_name,
		Program: prog,
        })

	if err != nil {
		log.Fatalf("opening raw tracepoint %s error: %s", tp_name, err)
        }

	Progs = append(Progs, prog)
	Points = append(Points, &tp)
	fmt.Fprintf(os.Stderr, "Attached raw tracepoint: %s\n", tp_name)
	return nil
}

func CleanupBPF() {
	//for _, tp := range Points {
	//	tp.Close()
	//}
	for _, p := range Progs {
		p.Close()
	}
}

// go does not provide anything to name goroutines (that sucks but does not stop us)
func name_goroutine(name string) {
	var tname [16]byte

	copy(tname[:], name)
	err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&tname)), 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not set thread name: %v", err)
	}
}

// I'm soo glad golang is easier than C...
func getKernelVersion() (int, int, int, error) {
	var (
		uts                  syscall.Utsname
		kernel, major, minor int
		err                  error
	)

	if err := syscall.Uname(&uts); err != nil {
		return 0, 0, 0, err
	}

	release := make([]byte, len(uts.Release))

	i := 0
	for _, c := range uts.Release {
		release[i] = byte(c)
		i++
	}

	// Remove the \x00 from the release for Atoi to parse correctly
	release = release[:bytes.IndexByte(release, 0)]

	tmp := strings.SplitN(string(release), "-", 2)
	tmp2 := strings.SplitN(tmp[0], ".", 3)

	if len(tmp2) > 0 {
		kernel, err = strconv.Atoi(tmp2[0])
		if err != nil {
			return 0, 0, 0, err
		}
	}

	if len(tmp2) > 1 {
		major, err = strconv.Atoi(tmp2[1])
		if err != nil {
			return 0, 0, 0, err
		}
	}

	if len(tmp2) > 2 {
		minor, err = strconv.Atoi(tmp2[2])
		if err != nil {
			return 0, 0, 0, err
		}
	}

	return kernel, major, minor, nil
}

func detectProcessType(pid int32, comm string) process_type {
	// check if pid is a kernel thread: /proc/pid/stat [8] flag: 0x00200000 -> Bit21
	kthread, err := ReadStatFile("/proc/", fmt.Sprintf("%d", pid), "/stat")
	if err != nil {
		if optDebug {
			fmt.Fprintf(os.Stderr, "error reading /proc/%d/stat\n", pid)
		}
		// process might already be dead again
		return TypeDead
	}
	if kthread == true {
		if optDebug {
			fmt.Fprintf(os.Stderr, "%s -> kernel thread\n", comm)
		}
		return TypeKthread
	}

	// not detecting all kworker's as threads (why?)...
	// check if PPID is 2 and if maybe also name (kworker)

	// check if pid is VM: comm starts with qemu and TODO: entry in machine-qemu.../libvirt/cgroup.procs
	if strings.HasPrefix(comm, "qemu") {
		if optDebug {
			fmt.Fprintf(os.Stderr, "%s -> VM\n", comm)
		}
		return TypeVM
	}

	// optional: detect service

	// pid is a "normal" process :)
	if optDebug {
		fmt.Fprintf(os.Stderr, "%s -> process\n", comm)
	}
	return TypeProcess
}

var bpfprogramFile string

func run_bpf_log() {
	// subscribe to signals for terminating the program
        stopper := make(chan os.Signal, 1)
        signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	//signal.Notify(sig, os.Interrupt, os.Kill)

        // increase rlimit so the BPF map and program can be loaded
        if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
                Cur: unix.RLIM_INFINITY,
                Max: unix.RLIM_INFINITY,
        }); err != nil {
                log.Fatalf("Error setting temporary rlimit: %s", err)
        }

	// load BPF program and maps from ELF object file
	program, err := ioutil.ReadFile(bpfprogramFile)
	if err != nil {
		panic("Error reading BPF program:" + err.Error())
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if err != nil {
		panic("Error ebpf.LoadCollectionSpecFromReader:" + err.Error())

	}

	maj, min, sub, err := getKernelVersion()
	if err != nil {
		panic("Error getKernelVersion");
	}
	var kver uint32 = uint32(maj * 65536 + min * 256 + sub)
	consts := map[string]interface{} {
		"linux_kernel_version": kver,
        }

        if err := spec.RewriteConstants(consts); err != nil {
                panic("error RewriteConstants:" + err.Error())
        } else {
		fmt.Fprintf(os.Stderr, "Set kernel version to: %d.%d.%d\n", maj, min, sub)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic("Error ebpf.NewCollection:" + err.Error())
	}

	// get perf events buffer from BPF
	events := coll.DetachMap("events")
	if events == nil {
		log.Fatalf("BPF perf events %s not found")
	} else {
		fmt.Fprintf(os.Stderr, "Attached to perf events ringbuffer\n")
	}
        defer events.Close()

        // open a perf reader into the perf event array
        rd, err := perf.NewReader(events, os.Getpagesize())
        if err != nil {
                log.Fatalf("Error creating event reader: %s", err)
        }
        defer rd.Close()

	// close the reader when the process receives a signal, which will exit the read loop.
        go func() {
                <-stopper
                rd.Close()
        }()

	// TODO: list of progs and kprobes
	if optTraceReq {
		//register_kprobe(coll, "trace_pid_start", "blk_account_io_start")
		//register_kprobe(coll, "trace_req_start", "blk_mq_start_request")
		//register_kprobe(coll, "trace_req_done", "blk_account_io_done")

		prog_kp := coll.DetachProgram("trace_pid_start")
		defer prog_kp.Close()
		kp, err := link.Kprobe("blk_account_io_start", prog_kp)
		if err != nil {
	                log.Fatalf("opening : %s", err)
		}
	        defer kp.Close()

		prog_kp2 := coll.DetachProgram("trace_req_start")
		defer prog_kp2.Close()
		kp2, err := link.Kprobe("blk_mq_start_request", prog_kp2)
		if err != nil {
	                log.Fatalf("opening : %s", err)
		}
	        defer kp2.Close()

		prog_kp3 := coll.DetachProgram("trace_req_done")
		defer prog_kp3.Close()
		kp3, err := link.Kprobe("blk_account_io_done", prog_kp3)
		if err != nil {
	                log.Fatalf("opening : %s", err)
		}
	        defer kp3.Close()
	}

	if optTraceBio {
		//register_raw_tp(coll, "trace_bio_start", "block_bio_queue")
		//register_raw_tp(coll, "trace_bio_done", "block_bio_complete")
		prog_tp := coll.DetachProgram("trace_bio_start")
		defer prog_tp.Close()
		tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
	                Name:    "block_bio_queue",
		        Program: prog_tp,
	        })
		if err != nil {
			log.Fatalf("opening block_bio_queue : %s", err)
	        }
		defer tp.Close()

		prog_tp2 := coll.DetachProgram("trace_bio_done")
		defer prog_tp2.Close()
		tp2, err := link.AttachRawTracepoint(link.RawTracepointOptions{
	                Name:    "block_bio_complete",
		        Program: prog_tp2,
	        })
		if err != nil {
			log.Fatalf("opening block_bio_complete : %s", err)
	        }
		defer tp2.Close()
	}

	// bpf perf event reading func
	fmt.Fprintf(os.Stderr, "Starting BPF\n")
	//go func() {
		var event ioEvent

		name_goroutine("events")
		for {
			record, err := rd.Read()
			if err != nil {
				log.Fatalf("error reading from reader: %s", err)
			}
			//if optDebug {
			//	log.Println("Record:", record)
			//}

			total_events++

			if record.LostSamples != 0 {
				dropped_events += record.LostSamples
				// lost samples contain no useful data
				continue
			}

			// Parse the perf event entry into an Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("error parsing perf event: %s", err)
				continue
			}

			// ignore all but read and write
			//if event.RWFlag == REQ_OP_READ || event.RWFlag == REQ_OP_WRITE {
			//	continue
			//}

			// Filter devices we don't want to track.
			if int64(event.Major) != def_major || int64(event.Minor) != def_minor {
				if optDebug {
					fmt.Fprintf(os.Stdout, "debug: dropping event for disk %d:%d\n", event.Major, event.Minor)
				}
				continue
			}

			comm := C.GoString((*C.char)(unsafe.Pointer(&event.Comm)))
			disk := C.GoString((*C.char)(unsafe.Pointer(&event.Disk)))

			if optLogEvents {
				if event.Internal == 1 {
					fmt.Fprintf(os.Stdout, "[ req ] pid: %d  rwflag: %d  sector: %d len: %d  delta: %d  comm: %s  disk: %s (%d:%d)\n",
						    event.Pid, event.RWFlag, event.Sector, event.Len, event.Delta, comm, disk, event.Major, event.Minor)
				} else if event.Internal == 2 {
					fmt.Fprintf(os.Stdout, "[ bio ] pid: %d  rwflag: %d  sector: %d len: %d  delta: %d  comm: %s  disk: %s (%d:%d)\n",
							event.Pid, event.RWFlag, event.Sector, event.Len, event.Delta, comm, disk, event.Major, event.Minor)
				} else if event.Internal == 3 {
					//fmt.Fprintf(os.Stdout, "[remap] pid: %d  sector: %d -> %d  flag: %d  comm: %s  disk: %s (%d:%d) -> (%d:%d)\n",
					//	event.Pid, event.OldSector, event.Sector, event.RWFlag, comm, disk, event.OldMajor, event.OldMinor, event.Major, event.Minor)
					continue // logging-only
				}
			}

			if event.RWFlag == REQ_OP_READ {
				lat.read_total += event.Delta
				lat.read_nr++
				if lat.read_max < event.Delta {
					lat.read_max = event.Delta
				}
			} else if event.RWFlag == REQ_OP_WRITE {
				lat.write_total += event.Delta
				lat.write_nr++
				if lat.write_max < event.Delta {
					lat.write_max = event.Delta
				}
			}

			// check if we know the PID and create if neccesary
			p, known := pinfo[int(event.Pid)]
			if !known {
				if optDebug {
					fmt.Fprintf(os.Stderr, "[event] new pid %d  comm: %s\n", event.Pid, event.Comm)
				}
				str := string(event.Comm[:])

				var p *process_info
				p = new(process_info)
				p.pid = int(event.Pid)
				p.ptype = detectProcessType(event.Pid, str)
				p.comm = str

				// TODO: if VM detect ID
				//d.ID = id

				// TODO: not sure if I need this
				//p.dir = dirCgroup.Name()

				p.scanned = true

				if p.ptype != TypeDead {
					pinfo[p.pid] = p

					if optDebug {
						fmt.Fprintf(os.Stderr, "debug: added pid: %d  info @ %p\n", p.pid, p)
					}
				}
			}

			// re-fetch p if it was re-created (why?)
			p, known = pinfo[int(event.Pid)]
			if !known {
				if optDebug {
					fmt.Fprintf(os.Stderr, "error: missing pinfo!\n")
				}
				continue
			}

			// account event
			if event.RWFlag == REQ_OP_READ {
				p.act.read_ops++
				p.act.read_bytes += event.Len
				p.lat.read_total += event.Delta
				if event.Delta > p.lat.read_max {
					p.lat.read_max = event.Delta
				}
				p.lat.read_nr++
			} else if event.RWFlag == REQ_OP_WRITE {
				p.act.write_ops++
				p.act.write_bytes += event.Len
				p.lat.write_total += event.Delta
				if event.Delta > p.lat.write_max {
					p.lat.write_max = event.Delta
				}
				p.lat.write_nr++
			}

			// account blocksize
			p.bs_total += event.Len
			p.bs_nr++

			// store raw deltas for percentile accounting
			if event.RWFlag == REQ_OP_READ {
				p.rd_perc = append(p.rd_perc, event.Delta)
			} else if event.RWFlag == REQ_OP_WRITE {
				p.wr_perc = append(p.wr_perc, event.Delta)
			}
		}
	//}()

	//<-stopper
	exiting = true

	// TODO: more cleanup?
	//CleanupBPF()
	fmt.Fprintf(os.Stderr, "Stopped BPF\n")
}

// hist_key and hist must match byte-for-byte with the BPF side
type hist_key struct {
	Pid  uint32
	Flag uint32
}

type hist_val struct {
	RdSlots [32]uint32
	WrSlots [32]uint32
}

// list of droplets with histogram data
var hists *ebpf.Map

func run_bpf_hist() {
	// subscribe to signals for terminating the program
        stopper := make(chan os.Signal, 1)
        signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

        // increase rlimit so the BPF map and program can be loaded
        if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
                Cur: unix.RLIM_INFINITY,
                Max: unix.RLIM_INFINITY,
        }); err != nil {
                log.Fatalf("Error setting temporary rlimit: %s", err)
        }

	// load BPF program and maps from ELF object file
	program, err := ioutil.ReadFile(bpfprogramFile)
	if err != nil {
		panic("Error reading BPF program:" + err.Error())
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if err != nil {
		panic(fmt.Errorf("ebpf.LoadCollectionSpecFromReader"))
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Errorf("ebpf.NewCollection"))
	}

	if optTraceBio {
		prog_tp := coll.DetachProgram("trace_bio_start")
		defer prog_tp.Close()
		tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
	                Name:    "block_bio_queue",
		        Program: prog_tp,
	        })
		if err != nil {
			log.Fatalf("opening block_bio_queue: %s", err)
	        }
		defer tp.Close()

		prog_tp2 := coll.DetachProgram("trace_bio_done")
		defer prog_tp2.Close()
		tp2, err := link.AttachRawTracepoint(link.RawTracepointOptions{
	                Name:    "block_bio_complete",
		        Program: prog_tp2,
	        })
		if err != nil {
			log.Fatalf("opening block_bio_complete: %s", err)
	        }
		defer tp2.Close()
	}

	fmt.Fprintf(os.Stderr, "Starting BPF\n")

	// read histograms
	hists = coll.DetachMap("hists")
	if hists == nil {
		panic(fmt.Errorf("no map named hists found"))
	} else {
		fmt.Fprintf(os.Stderr, "Using BPF hists map\n")
	}
	defer hists.Close()

	for true {
		var k hist_key
		var v hist_val

		fmt.Println("...\n")
		entries := hists.Iterate()
		for entries.Next(&k, &v) {
			fmt.Fprintf(os.Stderr, "key-pid: %d\t", k.Pid)
			fmt.Fprintf(os.Stderr, "read: %v    ", v.RdSlots)
			fmt.Fprintf(os.Stderr, "write: %v\n", v.WrSlots)
		}
		SleepInterruptible()
	}

	exiting = true
	fmt.Fprintf(os.Stderr, "Stopped BPF\n")
}

// IOs & bandwidth
type traffic struct {
	read_bytes uint64
	write_bytes uint64
	read_ops uint64
	write_ops uint64
}

// max and avgerage latencies
type latency struct {
	read_total	uint64
	read_nr		uint64
	read_max	uint64
	write_total	uint64
	write_nr	uint64
	write_max	uint64
}

type process_type int

const (
	TypeProcess = iota
	TypeKthread
	TypeVM
	TypeHVGlobal	// XXX maybe kill
	TypeService	// XXX maybe kill
	TypeDead	// dying or dead process
)

// process description, this can be a droplet, HV service or other process (e.g. kworker threads)
type process_info struct {
	pid			int		// used as key in map
	ID			int		// unique VM id (virsh list --all) for droplets
	ptype			process_type
	comm			string
	dir			string
	last			traffic
	act			traffic
	lat			latency
	usable			bool
	scanned			bool
	lat_read_avg		uint64		// last interval read latency
	lat_write_avg		uint64		// last interval write latency
	bs_total		uint64
	bs_nr			uint64
	timestamp		time.Time	// start of measuring interval
	rd_perc			[]uint64	// slice to calculate read percentiles
	wr_perc			[]uint64	// slice to calculate write percentiles
}

// temporary for output
type output struct {
	pid		int
	ID		int
	timestamp	time.Time
	rd_bytes	uint64
	wr_bytes	uint64
	rd_ops		uint64
	wr_ops		uint64
        rd_avg		uint64
	wr_avg		uint64
	rd_max		uint64
	wr_max		uint64
	rd_perc		int
	wr_perc		int
	rd_p50		uint64
	rd_p90		uint64
	rd_p99		uint64
	wr_p50		uint64
	wr_p90		uint64
	wr_p99		uint64
	bs_avg		uint64
	name		string
}

// global process map storing last cycle data indexed by pid
var pinfo = make(map[int]*process_info)

// global HV struct storing last cycle data
var HV_global process_info

var cycle_secs int
// global last-cycle latencies
var lat latency

// dropped events for log target per cycle
var dropped_events uint64
var total_events uint64

var CSV_File string = "reaper.csv"
//var CSV *os.File

// do we have any virtual machines running?
var noVMs bool = true

// cgroupv1 vs. cgroupv2 configuration
var cgroupVersion int
var basedirCgroupVM string
var basedirCgroupHV string
var blkioServiceBytes string
var blkioServiced string
var blkioThrottleReads string
var blkioThrottleWrites string

// Get cgroup configuration on the HV
func ConfigureCgroupVars() (error) {

	f, err := os.Open("/proc/mounts")
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// format: cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
		fields := strings.FieldsFunc(sc.Text(), splitFileLine)
		if fields[0] == "cgroup2" {
			cgroupVersion = 2
			fmt.Fprintf(os.Stderr, "Found cgroupv2\n")
		}
	}

	if cgroupVersion != 2 {
		panic("Error: Failed to find cgroupv2")
	}

	basedirCgroupHV = "/sys/fs/cgroup/system.slice/"
	blkioServiceBytes = "io.stat"
	blkioServiced = "io.stat"
	blkioThrottleReads = "io.max"
	blkioThrottleWrites = "io.max"

	if _, err := os.Stat("/sys/fs/cgroup/machine.slice"); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No virtual machines detected\n")
	} else {
		basedirCgroupVM = "/sys/fs/cgroup/machine.slice/"
		noVMs = false
		fmt.Fprintf(os.Stderr, "Virtual machines detected\n")
	}
	return nil
}

func LifeCheck() {
	// mark all existing processes to detect dead ones
	for _, p := range pinfo {
		p.scanned = false
	}

	// find dead processes
	for _, p := range pinfo {
		if p.scanned == false {
			// remove it
			var k hist_key

			k.Pid = uint32(p.pid)
			// Deleting a process directly from the BPF map should be race-safe
			// as the process is gone and no new events will therefore be added from BPF side
			if err := hists.Delete(&k); err != nil {
				fmt.Fprintf(os.Stderr, "Can't delete droplet %d map entry:", p.pid, err)
			}
			delete(pinfo, p.pid)
		}
	}
}

// TODO: call this with a pid on VM (qemu-) detection to fill out ID and cgroup
// Get VM-IDs parsing blkio cgroup (avoiding libvirt)
func GetVMIDs() (error) {
	dirsCgroup, err := ioutil.ReadDir(basedirCgroupVM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blkio cgroup is not configured")
		return err
	}

	// Iterate over the base directory
	for _, dirCgroup := range dirsCgroup {
		// Find only dirs that contain VM info
		if !dirCgroup.IsDir() || !strings.HasPrefix(dirCgroup.Name(), "machine-qemu") {
			continue
		}

		// Cut VM-ID from dir
		// format: machine-qemu \x2d 200 \x2d Droplet\x2d8599157.scope
		//                           vm-id    vm-name
		ID, err := strconv.ParseInt(strings.Split(strings.TrimPrefix(dirCgroup.Name(), "machine-qemu\\x2d"), "\\x2d")[0], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unknown dir")
			continue
		}
		id := int(ID)

		// get PID of qemu process
		// Note: /libvirt/ component was added by a libvirt change, should be all focal and cgroupsv2
		pid, err := ReadPIDFile(basedirCgroupVM, dirCgroup.Name(), "/libvirt/cgroup.procs")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading pid for VM: %s\n", dirCgroup.Name())
			return err
		}
		if pid == 0 {
			fmt.Fprintf(os.Stderr, "error: pid is zero for %s\n", dirCgroup.Name())
		}

		// lookup if we know this VM already
		v, ok := pinfo[pid]
		if ok {
			// just mark it
			v.scanned = true
			continue
		} else {
			// store VM data
			var v *process_info
			v = new(process_info)
			v.pid = pid
			v.ID = id
			v.ptype = TypeVM
			v.dir = dirCgroup.Name()
			v.scanned = true

			pinfo[pid] = v
			if optDebug {
				fmt.Fprintf(os.Stderr, "debug: added VM-ID: %d  info @ %p\n", id, v)
			}
		}
	}
	return nil
}

// Get service IDs parsing blkio cgroup
func GetServiceIDs() (error) {
	// mark all existing processes to detect dead ones
	for _, s := range pinfo {
		s.scanned = false
	}

	dirsCgroup, err := ioutil.ReadDir(basedirCgroupHV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blkio cgroup is not configured")
		return err
	}

	// Iterate over the base directory
	for _, dirCgroup := range dirsCgroup {
		// Find only dirs that contain service info
		if !dirCgroup.IsDir() || !strings.HasSuffix(dirCgroup.Name(), ".service") {
			continue
		}

		// get PID of process
		pid, err := ReadPIDFile(basedirCgroupHV, dirCgroup.Name(), "/cgroup.procs")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading pid for service %s\n", dirCgroup.Name())
			return err
		}
		if pid == 0 {
			// seems to happen with various system.slice services
			continue
		}

		// lookup if we know this process already
		s, ok := pinfo[pid]
		if ok {
			// just mark it
			s.scanned = true
			continue
		} else {
			// store service data
			var s *process_info
			s = new(process_info)
			s.pid = pid
			s.ptype = TypeService
			s.dir = dirCgroup.Name()
			s.scanned = true

			pinfo[pid] = s
			if optDebug {
				fmt.Fprintf(os.Stderr, "debug: added service: %d  info @ %p\n", pid, s)
			}
		}
	}

	// find dead services
	/*
	for _, s := range pinfo {
		if s.scanned == false {
			// remove service
			var k hist_key

			k.Pid = uint32(s.pid)
			// Deleting a process directly from the BPF map should be race-safe
			// as the process is gone and no new events will therefore be added from BPF side
			// BUG: SIGSEGV, racy with BPF side?
			if err := hists.Delete(&k); err != nil {
				fmt.Fprintf(os.Stderr, "Can't delete droplet %d map entry:", s.pid, err)
			}
			delete(pinfo, s.pid)
		}
	}
	*/

	return nil
}

func splitFileLine(r rune) bool {
        return r == ' ' || r == ':' || r == '='
}

func splitFileLineRedux(r rune) bool {
        return r == ' '
}

// cgroupsv2: io.stat
// TODO: remove debug code
func ReadIOServiceFilev2(base, prefix string, suffix string) (uint64, uint64, uint64, uint64, error) {
	var rd, wr, rdio, wrio uint64

	path := filepath.Join(base, prefix, suffix)
	if optDebug {
		fmt.Fprintf(os.Stderr, "debug: reading file: %s\n", path)
	}

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error open\n")
		return 0, 0, 0, 0, err
	}
	defer f.Close()

	// That loop looks fishy as it will only return values in the end. It works
	// because there is only one line with the matching major:minor and all other lines
	// are skipped.
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// format: major:minor rbytes=amount wbytes=amount rios=amount wios=amount ...
		fields := strings.FieldsFunc(sc.Text(), splitFileLine)
		if len(fields) < 10 {
			fmt.Fprintf(os.Stderr, "invalid line\n")
			return 0, 0, 0, 0, fmt.Errorf("invalid line found while parsing %s: %s", path, sc.Text())
		}

		major, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parse\n")
			return 0, 0, 0, 0, err
		}
		minor, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parse\n")
			return 0, 0, 0, 0, err
		}

		// only /var/lib/libvirt/images is relevant, as this becomes vda
		if major != def_major || minor != def_minor {
			continue
		}

		if fields[2] != "rbytes" || fields[4] != "wbytes" || fields[6] != "rios" || fields[8] != "wios" {
			fmt.Fprintf(os.Stderr, "error fields\n")
			return 0, 0, 0, 0, fmt.Errorf("invalid values in %s: %s", path, sc.Text())
		}

		// TODO: throw error checking away
		rd, err = strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parse\n")
			return 0, 0, 0, 0, err
		}
		wr, err = strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parse\n")
			return 0, 0, 0, 0, err
		}
		rdio, err = strconv.ParseUint(fields[7], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parse\n")
			return 0, 0, 0, 0, err
		}
		wrio, err = strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parse\n")
			return 0, 0, 0, 0, err
		}
	}
	if optDebug {
		fmt.Fprintf(os.Stderr, "debug: return rd: %d  wr: %d  rios: %d  wios: %d\n", rd, wr, rdio, wrio)
	}
	return rd, wr, rdio, wrio, sc.Err()
}

func ReadIOThrottleFile(base, prefix string, suffix string) (uint64, error) {
	path := filepath.Join(base, prefix, suffix)

	if optDebug {
		fmt.Fprintf(os.Stderr, "debug: reading file: %s\n", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// format: major:minor limit
		fields := strings.FieldsFunc(sc.Text(), splitFileLine)
		if len(fields) < 3 {
			// TODO XXX handle empty files
			continue
		}

		major, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0, err
		}
		minor, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}

		// only limit on /var/lib/libvirt/images
		if int64(major) != def_major || int64(minor) != def_minor {
			fmt.Fprintf(os.Stderr, "error: unknown limit on %d:%d path: %s\n", major, minor, path)
			continue
		}

		limit, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return 0, err
		}

		if (limit != 0) {
			//fmt.Fprintf(os.Stderr, "    %d:%d  %d\n", major, minor, value)
			// bail-out on first line on purpose as we set all devices to the same value
			return limit, err
		}
	}
	return 0, sc.Err()
}

// return true if /proc/pid/stat is kernel thread or false otherwise
func ReadStatFile(base, prefix string, suffix string) (bool, error) {
	path := filepath.Join(base, prefix, suffix)

	if optDebug {
		fmt.Fprintf(os.Stderr, "debug: reading file: %s\n", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.FieldsFunc(sc.Text(), splitFileLineRedux)
		if len(fields) < 9 {
			continue
		}

		flag, err := strconv.ParseInt(fields[8], 10, 64)
		if err != nil {
			return false, err
		}

		ppid, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return false, err
		}

		if (flag & 0x00200000 == 0x00200000) && (ppid == 2) {
			return true, nil
		} else {
			return false, nil
		}
	}
	fmt.Fprintf(os.Stderr, "It's the final ERROR\n")
	return false, sc.Err()
}

func ReadPIDFile(base, prefix string, suffix string) (int, error) {
	path := filepath.Join(base, prefix, suffix)

	if optDebug {
		fmt.Fprintf(os.Stderr, "debug: reading file: %s\n", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// format: first line contains qemu parent PID
		// TODO: maybe need to add children PIDs too
		pid, err := strconv.Atoi(sc.Text())
		if err != nil {
			return 0, err
		}

		// bail out at first found pid
		if pid != 0 {
			return pid, sc.Err()
		}
	}
	return 0, sc.Err()
}

func ReadDiskstatFile(base, prefix string, suffix string) (uint64, uint64, uint64, uint64, error) {
	path := filepath.Join(base, prefix, suffix)

	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)

	var read uint64
	var write uint64
	var read_sectors uint64
	var write_sectors uint64

	for sc.Scan() {
		// format: 15 values, 0=reads, 2=sectors-read 4=writes 6=sectors-written
		fields := strings.FieldsFunc(sc.Text(), splitFileLine)
		if len(fields) < 15 {
			fmt.Fprintf(os.Stderr, "error: Invalid diskstat format\n")
			return 0, 0, 0, 0, nil
		}

		read, err = strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		write, err = strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		read_sectors, err = strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		write_sectors, err = strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return 0, 0, 0, 0, err
		}
	}
	return read_sectors * 512, write_sectors * 512, read, write, sc.Err()
}

func ReadMounts(base, prefix string, suffix string) (string, error) {
	path := filepath.Join(base, prefix, suffix)

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)

	var link string
	for sc.Scan() {
		// format: /dev/mapper/vg0-libvirt_images
		fields := strings.FieldsFunc(sc.Text(), splitFileLine)
		if len(fields) < 2 {
			fmt.Fprintf(os.Stderr, "error: Invalid mount format\n")
			return "", nil
		}
		if fields[1] != "/var/lib/libvirt/images" {
			continue
		} else {
			link = fields[0]
		}
	}
	return link, sc.Err()
}

// TODO: rename formatBandwith or so
func formatDelta(delta uint64) (uint64, string) {
	var format string

	if delta > 1000000 {
		delta /= 1000000
		format = "MB/s"
	} else if delta > 1000 {
		delta /= 1000
		format = "KB/s"
	} else if delta >= 0 {
		format = " B/s"
	}
	return delta, format
}

func formatTime(delta uint64) (uint64, string) {
	var format string

	if delta > 1000000 {
		delta /= 1000000
		format = " s"
	} else if delta > 1000 {
		delta /= 1000
		format = "ms"
	} else if delta >= 0 {
		format = "µs"
	}
	return delta, format
}


var Reset  = "\033[0m"
var Red    = "\033[31m"
var Green  = "\033[32m"
var Yellow = "\033[33m"
var Blue   = "\033[34m"
var Purple = "\033[35m"
var Cyan   = "\033[36m"
var Gray   = "\033[37m"
var White  = "\033[97m"
var bgReset = "\033[49m"
var bgLightGreen = "\033[102m"
var bgLightBlue = "\033[104m"
var bgLightGrey = "\033[47m"
var bgBlue = "\033[44m"

var toggle int

func PrintData(o *output) {
	if !optHeadless {
		if optColor {
			var color string

			if o.ID == -1 {
				fmt.Fprintf(os.Stderr, " %s\t\t", o.name)
			} else {
				fmt.Fprintf(os.Stderr, " #%d (%d)\t\t", o.ID, o.pid)
			}

			rdelta, rformat := formatDelta(o.rd_bytes)
			wdelta, wformat := formatDelta(o.wr_bytes)

			// TODO: reduce spacing for 0 values
			fmt.Fprintf(os.Stderr, "%3d %s / ", rdelta, rformat)
			fmt.Fprintf(os.Stderr, "%3d %s\t\t", wdelta, wformat)

			fmt.Fprintf(os.Stderr, "%5d / %5d\t\t",	o.rd_ops, o.wr_ops)

			rdelta, rformat = formatTime(o.rd_avg)
			wdelta, wformat = formatTime(o.wr_avg)
			fmt.Fprintf(os.Stderr, "%4d %s / %4d %s\t\t", rdelta, rformat, wdelta, wformat)

			rdelta, rformat = formatTime(o.rd_max)
			wdelta, wformat = formatTime(o.wr_max)
			fmt.Fprintf(os.Stderr, "%4d %s / %4d %s", rdelta, rformat, wdelta, wformat)

			fmt.Fprintf(os.Stderr, "\n  percs [%4d/%4d]: ", o.rd_perc, o.wr_perc)
			fmt.Fprintf(os.Stderr, "\t p50: %d/%d \t p90: %d/%d \t p99: %d/%d",
				o.rd_p50, o.wr_p50,
				o.rd_p90, o.wr_p90,
				o.rd_p99, o.wr_p99)

			fmt.Fprintf(os.Stderr, "\t\t%6d", o.bs_avg)

			if toggle == 0 {
				toggle = 1
				color = bgLightBlue
			} else {
				toggle = 0
				color = bgLightGreen
			}
			fmt.Println(string(color))
		} else {
			if o.ID == -1 {
				fmt.Fprintf(os.Stderr, " %-20s", o.name)
				if len(o.name) < 8 {
					fmt.Fprintf(os.Stderr,"\t\t\t")
				} else {
					fmt.Fprintf(os.Stderr,"\t")
				}
			} else {
				fmt.Fprintf(os.Stderr, " #%d (%d)\t\t", o.ID, o.pid)
			}

			rdelta, rformat := formatDelta(o.rd_bytes)
			wdelta, wformat := formatDelta(o.wr_bytes)

			// TODO: reduce spacing for 0 values
			fmt.Fprintf(os.Stderr, "%3d %s / ", rdelta, rformat)
			fmt.Fprintf(os.Stderr, "%3d %s\t\t", wdelta, wformat)

			fmt.Fprintf(os.Stderr, "%5d / %5d\t\t",	o.rd_ops, o.wr_ops)

			rdelta, rformat = formatTime(o.rd_avg)
			wdelta, wformat = formatTime(o.wr_avg)
			fmt.Fprintf(os.Stderr, "%4d %s / %4d %s\t\t", rdelta, rformat, wdelta, wformat)

			rdelta, rformat = formatTime(o.rd_max)
			wdelta, wformat = formatTime(o.wr_max)
			fmt.Fprintf(os.Stderr, "%4d %s / %4d %s", rdelta, rformat, wdelta, wformat)

			/* debug - disable percs for now for readability
			fmt.Fprintf(os.Stderr, "\n  percs [%4d/%4d]: ", o.rd_perc, o.wr_perc)
			fmt.Fprintf(os.Stderr, "\t p50: %d/%d \t p90: %d/%d \t p99: %d/%d",
				o.rd_p50, o.wr_p50,
				o.rd_p90, o.wr_p90,
				o.rd_p99, o.wr_p99)

			fmt.Fprintf(os.Stderr, "\t\t%6d", o.bs_avg)
			*/
			fmt.Fprintf(os.Stderr, "\n")
		}
	}
	if optCSV {
		// TODO: this sucks, making CSV global does fail on writes
		CSV, err := os.OpenFile(CSV_File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			panic("Error open CSV file:" + err.Error())
		}
		defer CSV.Close()

		s := fmt.Sprintf("\n%s,%d,", o.timestamp.Format("2006-01-02 15:04:05"), o.ID)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,", o.rd_bytes, o.wr_bytes)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,", o.rd_ops, o.wr_ops)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,", o.rd_avg, o.wr_avg)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,", o.rd_max, o.wr_max)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,", o.rd_perc, o.wr_perc)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,%d,", o.rd_p50, o.rd_p90, o.rd_p99)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,%d,%d,", o.wr_p50, o.wr_p90, o.wr_p99)
		CSV.WriteString(s)

		s = fmt.Sprintf("%d,", o.bs_avg)
		CSV.WriteString(s)
	}
}

// Total HV consumption including everything
func GetHVData() (error) {
	// cgroup summary is not working so use diskstats for md1 instead
	// TODO: broken on new HVs, check if it works with v2!
	var rd, wr, rdops, wrops uint64
	var err error

	if cgroupVersion == 2 {
		rd, wr, rdops, wrops, err = ReadIOServiceFilev2("/sys/fs/cgroup/", "", blkioServiced)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading total stats for HV\n")
			return nil
		}
	}

	if HV_global.usable == true {
		time_diff := time.Now().Sub(HV_global.timestamp)

		if rd < HV_global.last.read_bytes || rdops < HV_global.last.read_ops ||
		   wr < HV_global.last.write_bytes || wrops < HV_global.last.write_ops {
			   fmt.Fprintf(os.Stderr, "error: implausible blkio value for read or write\n")
		}

		fmt.Fprintf(os.Stderr, "Total\t\t\t")

		rbytes := uint64(float64(rd - HV_global.last.read_bytes) / time_diff.Seconds())
		rdelta, rformat := formatDelta(rbytes)

		wbytes := uint64(float64(wr - HV_global.last.write_bytes) / time_diff.Seconds())
		wdelta, wformat := formatDelta(wbytes)

		fmt.Fprintf(os.Stderr, "%3d %s / %3d %s\t\t", rdelta, rformat, wdelta, wformat)
		fmt.Fprintf(os.Stderr, "%5d / %5d",
			uint64(float64(rdops - HV_global.last.read_ops) / time_diff.Seconds()),
			uint64(float64(wrops - HV_global.last.write_ops) / time_diff.Seconds()))

		ops := total_events
		if ops > 0 {
			fmt.Fprintf(os.Stderr, "\t\t\tLost %d/%d (%d %%)",
						dropped_events, ops, (100 * dropped_events) / ops)
		}
		total_events = 0
		dropped_events = 0
		fmt.Println(string(bgReset))
	}

	HV_global.last.read_bytes = rd
	HV_global.last.write_bytes = wr
	HV_global.last.read_ops = rdops
	HV_global.last.write_ops = wrops
	HV_global.timestamp = time.Now()
	HV_global.usable = true
	return nil
}

// implement sort interfaces for process_info
type ByID []*process_info

func (p ByID) Len() int           { return len(p) }
func (p ByID) Less(i, j int) bool { return p[i].ID < p[j].ID }
func (p ByID) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

type ByPID []*process_info

func (p ByPID) Len() int           { return len(p) }
func (p ByPID) Less(i, j int) bool { return p[i].pid < p[j].pid }
func (p ByPID) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func CalcPercentile(percent int, perc []uint64) uint64 {
	len := len(perc)

	if len < 3 {
		return 0
	}

	return perc[(len * percent) / 100]
}

// used unicodes:
// Δ is \xce\x94
// ⌀ is \xe2\x8c\x80

func ProcessData(d *process_info) () {
	var o output
	// TODO: cleanup
	rd := d.act.read_bytes
	wr := d.act.write_bytes
	rdops := d.act.read_ops
	wrops := d.act.write_ops

	// reset traffic
	d.act.read_bytes = 0
	d.act.write_bytes = 0
	d.act.read_ops = 0
	d.act.write_ops = 0

	if (d.usable == true) {
		time_diff := time.Now().Sub(d.timestamp)

		var lat_rd_avg uint64 = 0
		var lat_wr_avg uint64 = 0

		if d.ptype == TypeVM {
			o.ID = d.ID
		} else {
			o.ID = -1
		}
		o.pid = d.pid
		o.timestamp = d.timestamp
		//o.name = d.dir
		o.name = d.comm

		// read - write bandwith during cycle
		o.rd_bytes = uint64(float64(rd) / time_diff.Seconds())
		o.wr_bytes = uint64(float64(wr) / time_diff.Seconds())

		// read-write IOPS during cycle
		o.rd_ops = uint64(float64(rdops) / time_diff.Seconds())
		o.wr_ops = uint64(float64(wrops) / time_diff.Seconds())

		// read - write average latencies during cycle
		if d.lat.read_nr != 0 {
			lat_rd_avg = d.lat.read_total / d.lat.read_nr
		}
		if d.lat.write_nr != 0 {
			lat_wr_avg = d.lat.write_total / d.lat.write_nr
		}

		o.rd_avg = lat_rd_avg
		o.wr_avg = lat_wr_avg

		o.rd_max = d.lat.read_max
		o.wr_max = d.lat.write_max

		// calculate percentiles
		// sort array by value
		o.rd_perc = len(d.rd_perc)
		o.wr_perc = len(d.wr_perc)
		sort.Slice(d.rd_perc, func(i, j int) bool {
			return d.rd_perc[i] < d.rd_perc[j]
		})
		sort.Slice(d.wr_perc, func(i, j int) bool {
			return d.wr_perc[i] < d.wr_perc[j]
		})

		//for _, v := range d.perc {
		//	fmt.Fprintf(os.Stderr, "%d ", v)
		//}
		//fmt.Fprintf(os.Stderr, "\n")

		// calculate values for p50, p90 and p99
		o.rd_p50 = CalcPercentile(50, d.rd_perc)
		o.wr_p50 = CalcPercentile(50, d.wr_perc)
		o.rd_p90 = CalcPercentile(90, d.rd_perc)
		o.wr_p90 = CalcPercentile(90, d.wr_perc)
		o.rd_p99 = CalcPercentile(99, d.rd_perc)
		o.wr_p99 = CalcPercentile(99, d.wr_perc)

		// delete slice content
		d.rd_perc = d.rd_perc[:0]
		d.wr_perc = d.wr_perc[:0]

		var bs_avg uint64 = 0
		if d.bs_nr != 0 {
			bs_avg = d.bs_total / d.bs_nr
		}
		o.bs_avg = bs_avg

		d.lat_read_avg = lat_rd_avg
		d.lat_write_avg = lat_wr_avg

		// only print data if non-zero
		if o.rd_perc != 0 || o.wr_perc != 0 || o.rd_ops != 0 || o.wr_ops != 0 {
			PrintData(&o)
		}
	}

	d.last.read_bytes = rd
	d.last.write_bytes = wr
	d.last.read_ops = rdops
	d.last.write_ops = wrops

	// TODO: re-factor into struct (same for HV) and reset by fn
	d.lat.read_total = 0
	d.lat.read_nr = 0
	d.lat.read_max = 0

	d.lat.write_total = 0
	d.lat.write_nr = 0
	d.lat.write_max = 0

	d.bs_total = 0
	d.bs_nr = 0

	d.timestamp = time.Now()	// TODO: we miss some ns by taking another ts
	d.usable = true
}

// TODO: output should be a local to parent and passed to print
func GetVMData() error {
	// sort VMs by VM ID to keep output comparable between cycles
	vinfo_sort := make([]*process_info, 0, len(pinfo))
	for _, v := range pinfo {
		if v.ptype == TypeVM {
			vinfo_sort = append(vinfo_sort, v)
		}
	}
	sort.Sort(ByID(vinfo_sort))

	if len(vinfo_sort) > 0 {
		fmt.Fprintf(os.Stderr, "VMs:\n")
	}

	for _, v := range vinfo_sort {
		ProcessData(v)
	}
	return nil
}

func ParseVMs() (error) {
	if noVMs == true {
		return nil
	}

	err := GetVMIDs()
	if err != nil {
		return err
	}

	err = GetVMData()
	if err != nil {
                return err
        }

	return err
}

func ParseKthreads() {
	// sort kthreads to keep output comparable between cycles
	kinfo_sort := make([]*process_info, 0, len(pinfo))
	for _, k := range pinfo {
		if k.ptype == TypeKthread {
			kinfo_sort = append(kinfo_sort, k)
		}
	}
	sort.Sort(ByPID(kinfo_sort))

	if len(kinfo_sort) > 0 {
		fmt.Fprintf(os.Stderr, "Kernel threads: %d\n", len(kinfo_sort))
	}

	for _, k := range kinfo_sort {
		ProcessData(k)
	}
}

func ParseProcesses() {
	// sort processes to keep output comparable between cycles
	pinfo_sort := make([]*process_info, 0, len(pinfo))
	for _, p := range pinfo {
		if p.ptype == TypeProcess {
			pinfo_sort = append(pinfo_sort, p)
		}
	}
	sort.Sort(ByPID(pinfo_sort))

	if len(pinfo_sort) > 0 {
		fmt.Fprintf(os.Stderr, "Processes: %d\n", len(pinfo_sort))
	}

	for _, p := range pinfo_sort {
		ProcessData(p)
	}
}

/*
func ParseServices() (error) {
	err := GetServiceIDs()
	if err != nil {
		return err
	}

	return err
}

func ParseBPF() (error) {
	if !optBPFHist {
		return nil
	}

	var k iodataKey
        var v iodataVal

        keys := make(map[int32]iodataVal)
        iter := iodataMap.Iterate()

        for iter.Next(&k, &v) {
                keys[k.Pid] = v
        }

        for k := range keys {
                if _, ok := dropletPIDs[k]; !ok {
                        err := removeDropletEntry(k)
                        if err != nil {
                                log.KV("pid", k).Warn("unable to remove pid entry from the iodata map")
                        }
                }
        }
        return nil
}
*/

func printHeader() () {
	fmt.Fprintf(os.Stderr, "Process\t\t\t     Δ-BW R/W\t\t\t     Δ-IOPS R/W\t\t     ⌀-lat R/W\t\t\t     max-lat R/W\t\n")
	fmt.Fprintf(os.Stderr, "Perc.# R/W\t\t    p50 R/W\t\t p90 R/W\t\t  p99 R/W\t\t  ⌀-Blocksize\n")
}

//
// Note: all latency values below are in microseconds
//

// latencies measured during probe
var probe_lat_read_avg_min uint64 = math.MaxUint64
var probe_lat_read_avg_max uint64
var probe_lat_write_avg_min uint64 = math.MaxUint64
var probe_lat_write_avg_max uint64

// maximum bandwidth measured during probe in bytes/s
var probe_max_read_bw uint64
var probe_max_write_bw uint64

// targeted (average over interval) latencies for droplets
var target_lat_read_avg uint64
var target_lat_write_avg uint64

var manual_lat_read_avg int
var manual_lat_write_avg int

var def_major int64
var def_minor int64

// print and clear global latency stats
func printLatencyStats() () {
	var lat_read_avg uint64
	var lat_write_avg uint64

	// avoid div-by-zero for empty stats
	if lat.read_nr != 0 {
		lat_read_avg = lat.read_total / lat.read_nr

		if lat_read_avg < probe_lat_read_avg_min {
			probe_lat_read_avg_min = lat_read_avg
		}
		if lat_read_avg > probe_lat_read_avg_max {
			probe_lat_read_avg_max = lat_read_avg
		}
	} else {
		lat_read_avg = 0
	}
	if lat.write_nr != 0 {
		lat_write_avg = lat.write_total / lat.write_nr

		if lat_write_avg < probe_lat_write_avg_min {
			probe_lat_write_avg_min = lat_write_avg
		}
		if lat_write_avg > probe_lat_write_avg_max {
			probe_lat_write_avg_max = lat_write_avg
		}
	} else {
		lat_write_avg = 0
	}
	fmt.Fprintf(os.Stderr, "\t\tread-events:  %-9d\t ⌀-read-lat: %d µs\t\tmax-read-lat: %d µs\n", lat.read_nr, lat_read_avg, lat.read_max)
	fmt.Fprintf(os.Stderr, "\t\twrite-events: %-9d\t ⌀-write-lat: %d µs\t\tmax-write-lat: %d µs\n", lat.write_nr, lat_write_avg, lat.write_max)

	// why can't go have a proper memset?
	lat.read_total = 0
	lat.read_nr = 0
	lat.read_max = 0
	lat.write_total = 0
	lat.write_nr = 0
	lat.write_max = 0
}

func SleepInterruptible() {
	// plain Sleep is not interruptable by SIGINT, so this needs to be more complicated
	tsecs := cycle_secs * 10
	for tsecs > 0 {
		if exiting {
			break
		}
		tsecs--
		time.Sleep(100 * time.Millisecond)
	}
}

// check IOPS for droplets 
func PickVictim() {
	var max_ios uint64
	var pid int

	// find droplet doing the most IO
	for _, d := range pinfo {
		ios := d.last.read_ops + d.last.write_ops
		if ios > max_ios {
			max_ios = ios
			//fmt.Fprintf(os.Stderr, "debug: new-victim: %d old-victim: %d io-s: %d\n", d.pid, pid, ios)
			pid = d.pid
		}
	}
	fmt.Fprintf(os.Stderr, "info: droplet doing most IO is: %d with: %d\n", pinfo[pid].ID, max_ios)
}

// detect latency-violation, call for action
func CheckLatencyTarget() {
	var enforce bool
	var ios uint64	// IOs over all droplets
	for _, d := range pinfo {

		ios += d.last.read_ops + d.last.write_ops
		if d.lat_read_avg > target_lat_read_avg {
			enforce = true
			fmt.Fprintf(os.Stderr, "info: Detected droplet # %d exhausting read latency limit\n", d.ID)
		}
		if d.lat_write_avg > target_lat_write_avg {
			enforce = true
			fmt.Fprintf(os.Stderr, "info: Detected droplet # %d exhausting write latency limit\n", d.ID)
		}
	}

	if enforce == true {
		// check for number of read/write events, if below threshold we can drop out as data is noise
		if ios > 100 {
			PickVictim()
			return
		} else {
			fmt.Fprintf(os.Stderr, "info: droplet-IOPS too low (%d), not throttling\n", ios)
		}
	}
}

func PrintIOLimits() {
	for _, d := range pinfo {
		limit_rd, err := ReadIOThrottleFile(basedirCgroupVM, d.dir, blkioThrottleReads)
		if err != nil {
			continue
		}
		limit_wr, err := ReadIOThrottleFile(basedirCgroupVM, d.dir, blkioThrottleReads)
		if err != nil {
			continue
		}
		if limit_rd != 0 || limit_wr != 0 {
			fmt.Fprintf(os.Stderr, "Limit on droplet #%d  read: %d  write %d\n", d.ID, limit_rd, limit_wr)
		}
	}
}

// TODO: pass device from arg
func DetectDevice() (error) {
	// check device is block device
	//stat := syscall.Stat_t{}
	//_ = syscall.Stat(target, &stat)

	//def_major = int64(stat.Rdev / 256)
	//def_minor = int64(stat.Rdev % 256)

	fmt.Fprintf(os.Stderr, "Target partition default major:minor: %d:%d\n", def_major, def_minor)
	return nil
}

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

func main() {
	fmt.Fprintf(os.Stderr, "Reaper started\n")
	if isRoot() == false {
		panic("Must be run as root.")
	}

	flag.BoolVar(&optMonitor, "monitor-only", true, "Monitor only without bandwidth throttling")
	flag.BoolVar(&optLogEvents, "log-events", false, "Log BPF events to stdout") // TODO: maybe add a log file target
	flag.BoolVar(&optHeadless, "headless", false, "No monitor output")
	flag.BoolVar(&optCSV, "csv", false, "Write output to CSV file")
	flag.BoolVar(&optColor, "color", false, "Colorful terminal output")
	flag.BoolVar(&optDebug, "debug", false, "Verbose debug messages")
	flag.BoolVar(&optTraceReq, "trace-req", false, "Request based tracing (physical disk)")
	flag.BoolVar(&optTraceBio, "trace-bio", false, "Bio based tracing (md device)")
	flag.BoolVar(&optBPFHist, "histogram-mode", false, "Aggregate data in histograms")
	flag.IntVar(&cycle_secs, "secs", 10, "Delay between updates in seconds")
	flag.Int64Var(&def_major, "major", 8, "Target device major")
	flag.Int64Var(&def_minor, "minor", 0, "Target device minor")
	flag.IntVar(&manual_lat_read_avg, "target-read-lat", 100000, "Target average read latency in microseconds")
	flag.IntVar(&manual_lat_write_avg, "target-write-lat", 100000, "Target average write latency in microseconds")
	flag.Parse()

	// configure cgroup based params based on the cgroup version
	err := ConfigureCgroupVars()
	if err != nil {
		panic("Error ConfigureCgroupVars:" + err.Error())
	}

	err = DetectDevice()
	if err != nil {
		panic("Error DetectDevice:" + err.Error())
	}

	// TODO: unconditionally force bio mode as req mode isn't supported for now
	optTraceReq = false
	optTraceBio = true

	if !optTraceReq && !optTraceBio {
		optTraceBio = true
	}

	if optTraceReq {
		fmt.Fprintf(os.Stderr, "Request tracing enabled\n")
	}
	if optTraceBio {
		fmt.Fprintf(os.Stderr, "Bio tracing enabled\n")
	}

	if optCSV {
		// TODO: add date and host
		CSV, err := os.Create(CSV_File)
		if err != nil {
			panic("Error os.Create CSV file:" + err.Error())
		}
		defer CSV.Close()

		header := "Timestamp,VM-ID,read-bytes,write-bytes,rd-iops,wr-iops,avg-read-lat,avg-write-lat,max-read-lat,max-write-lat,read-perc-nr,wr-perc-nr,p50-read-lat,p90-read-lat,p99-read-lat,p50-write-lat,p90-write-lat,p99-write-lat,avg-blocksize\n"
		if _, err := CSV.WriteString(header); err != nil {
			log.Println(err)
		}
		fmt.Fprintf(os.Stderr, "Logging results to %s\n", CSV_File)
	}

	if !optBPFHist {
		bpfprogramFile = "./reaper-log.bpf.o"
		fmt.Fprintf(os.Stderr, "Mode: 1:1 log using %s\n", bpfprogramFile)
		go run_bpf_log()
	} else {
		bpfprogramFile = "./reaper-hist.bpf.o"
		fmt.Fprintf(os.Stderr, "Mode: histogram using %s\n", bpfprogramFile)
		go run_bpf_hist()
	}

	// set fixed latency limits if defined
	// TODO: fix it, message comes always as default is 2000 not 0
	if manual_lat_read_avg != 0 {
		target_lat_read_avg = uint64(manual_lat_read_avg)
	}
	if manual_lat_write_avg != 0 {
		target_lat_write_avg = uint64(manual_lat_write_avg)
	}
	if manual_lat_read_avg != 0 || manual_lat_write_avg != 0 {
		fmt.Fprintf(os.Stderr, "manual latency targets applied: read: %d µs   write: %d µs\n", target_lat_read_avg, target_lat_write_avg)
	}

	HV_global.ptype = TypeHVGlobal

	cycle := 0
	for {
		if optColor {
			fmt.Println(string(bgLightGrey))
			fmt.Fprintf(os.Stderr, "### Cycle %d\n", cycle)
		} else {
			fmt.Fprintf(os.Stderr, "\n### Cycle %d\n", cycle)
		}
		printLatencyStats()
		printHeader()

		if optColor {
			fmt.Println(string(bgLightGreen))
		}

		err := ParseVMs()
		if err != nil {
			panic("Error ParseVMs:" + err.Error())
		}

		if optColor {
			fmt.Println(string(bgLightGrey))
		}

		ParseKthreads()
		ParseProcesses()

		/*
		err = ParseServices()
		if err != nil {
			panic("Error ParseServices:" + err.Error())
		}

		err = ParseBPF()
		if err != nil {
			panic("Error ParseBPF:" + err.Error())
		}
		*/

		err = GetHVData()
		if err != nil {
			panic("Error GetHVData:" + err.Error())
		}

		if !optMonitor {
			CheckLatencyTarget()
			PrintIOLimits()
		}

		if optBPFHist {
			LifeCheck()
		}

		cycle++
		if exiting {
			break
		}
		SleepInterruptible()

	}

	if optColor {
		fmt.Println(string(bgReset) + string(Reset))
	}
}

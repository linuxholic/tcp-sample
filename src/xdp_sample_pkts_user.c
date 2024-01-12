// SPDX-License-Identifier: GPL-2.0
static const char *__doc__ = "XDP sample packet\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <poll.h>
#include <sys/mman.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <time.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>

#include "../common/common_params.h"

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define MAX_CPUS 128

static pcap_t* pd;
static pcap_dumper_t* pdumper;
static unsigned int pcap_pkts;
static struct config cfg = {
	.ifindex   = -1,
};
static struct xdp_program *prog;
struct perf_buffer *pb;
static int flow_map_fd;

static const char *default_filename = "samples.pcap";
#define SAMPLE_SIZE 1024
#define NANOSECS_PER_USEC 1000
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
#define MAX_IDLE_SEC 3600 /* 1h */

struct flow_key {

    union {
        __be32 ip;
        struct in6_addr ip6;
    } src_ip;

    union {
        __be32 ip;
        struct in6_addr ip6;
    } dst_ip;

    __be16 src_port;
    __be16 dst_port;
};

struct flow_info {
    __u64 flow_bytes;
    __u64 flow_pkts;
	__u64 timestamp;
};

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct {
		__u16 cookie;
		__u16 pkt_len;
		__u8  pkt_data[SAMPLE_SIZE];
	} __packed *e = data;
	struct pcap_pkthdr h = {
		.caplen	= e->pkt_len,
		.len	= e->pkt_len,
	};
	struct timespec ts;
	int i, err;

	if (e->cookie != 0xdead)
		printf("BUG cookie %x sized %d\n", e->cookie, size);

	err = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (err < 0)
		printf("Error with clock_gettime! (%i)\n", err);

	h.ts.tv_sec  = ts.tv_sec;
	h.ts.tv_usec = ts.tv_nsec / NANOSECS_PER_USEC;

	if (verbose) {
		printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
		for (i = 0; i < e->pkt_len; i++)
			printf("%02x ", e->pkt_data[i]);
		printf("\n");
	}

	pcap_dump((u_char *) pdumper, &h, e->pkt_data);
	pcap_pkts++;
}

static void sig_handler(int signo)
{
	struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(cfg.ifindex);
	enum xdp_attach_mode m = xdp_multiprog__attach_mode(mp);

	printf("\n Cleaning up...");
	xdp_program__detach(prog, cfg.ifindex, m, 0);
	perf_buffer__free(pb);
	pcap_dump_close(pdumper);
	pcap_close(pd);
	printf("\n%u packet samples stored in %s\n", pcap_pkts, cfg.filename);

	exit(0);
}

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"filename",    required_argument,	NULL,  1  },
	 "Store packet sample into <file>", "<file>"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

void _flow_map_gc(void *key, void *value)
{
    int err;
    struct flow_info *info;
	struct timespec ts;

    while (bpf_map_get_next_key(flow_map_fd, key, key) == 0) {
        if (bpf_map_lookup_elem(flow_map_fd, key, value) == 0) {
            info = value;

            /* get current boot time */
            err = clock_gettime(CLOCK_BOOTTIME, &ts);
            if (err < 0)
                printf("Error with clock_gettime! (%i)\n", err);

            /* calc timeout of flow entry */
            if (ts.tv_sec - info->timestamp / NANOSEC_PER_SEC > MAX_IDLE_SEC)
            {
                bpf_map_delete_elem(flow_map_fd, key);
                if (err) printf("flow map delete entry failed.\n");
                printf("flow map delete entry.\n");
            }
        }
    }
}

void* flow_map_gc(void* arg)
{
    int err;
    struct bpf_map_info map_info;
    __u32 map_info_len = sizeof(map_info);
    void *key, *value;

    err = bpf_obj_get_info_by_fd(flow_map_fd, &map_info, &map_info_len);
    if (err < 0)
    {
        printf("Failed to get BPF map info\n");
        return NULL;
    }

    key = malloc(map_info.key_size);
    value = malloc(map_info.value_size);

    while (true)
    {
        memset(key, 0, map_info.key_size);
        memset(value, 0, map_info.value_size);
        _flow_map_gc(key, value);
        printf("flow map gc done.\n");
        sleep(60);
    }

    return NULL;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int mymap_fd;
    pthread_t thread_id;
	char filename[256];
	int err;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	char progname[] = "xdp_sample_prog";
	char errmsg[1024];

	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));

	/* Cmdline options can change these */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	snprintf(filename, sizeof(filename), "xdp_sample_pkts_kern.o");
	xdp_opts.open_filename = filename;
	xdp_opts.prog_name = progname;
	xdp_opts.opts = &opts;

	prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		return err;
	}
	err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			cfg.ifname, errmsg, err);
		return err;
	}

    mymap_fd = bpf_object__find_map_fd_by_name(
            xdp_program__bpf_obj(prog), "my_map");
    flow_map_fd = bpf_object__find_map_fd_by_name(
            xdp_program__bpf_obj(prog), "flow_map");

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		fprintf(stderr, "signal");
		return 1;
	}

    err = pthread_create(&thread_id, NULL, flow_map_gc, NULL);
    if (err != 0)
    {
		fprintf(stderr, "pthread_create failed.\n");
		return 1;
    }

	pb = perf_buffer__new(mymap_fd, 8, print_bpf_output, NULL, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "perf_buffer setup failed");
		return 1;
	}

	pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (!pd) {
		perf_buffer__free(pb);
		goto out;
	}

	pdumper = pcap_dump_open(pd, cfg.filename);
	if (!pdumper) {
		perf_buffer__free(pb);
	    pcap_close(pd);
		goto out;
	}

	while ((err = perf_buffer__poll(pb, 1000)) >= 0) {
	}

	return 0;
out:
	xdp_program__detach(prog, cfg.ifindex, cfg.attach_mode, 0);
	return -1;
}

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/timekeeping.h> // for ktime_get_real_ts64
#include <linux/time64.h>      // for time64_to_tm
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Cross-Kernel Firewall with Logging");

#define MAX_RULES 128
#define RULE_BUF_LEN 256
#define LOG_PATH "/var/log/blocked_packets.log"

struct rule {
    __be32 ip;
    __be16 port;
};

static struct rule rules[MAX_RULES];
static int rule_count = 0;

static struct nf_hook_ops nfho;
static struct proc_dir_entry *proc_file;

// Convert string IP to __be32
static __be32 str_to_ip(const char *ip_str) {
    unsigned char a, b, c, d;
    if (sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4)
        return htonl((a << 24) | (b << 16) | (c << 8) | d);
    return 0;
}

// /proc write to add rules
ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char *kbuf;
    char ip_str[20];
    int port;

    if (count > RULE_BUF_LEN) return -EINVAL;
    kbuf = kzalloc(count + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, buffer, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    if (sscanf(kbuf, "%19s %d", ip_str, &port) == 2 && rule_count < MAX_RULES) {
        rules[rule_count].ip = str_to_ip(ip_str);
        rules[rule_count].port = htons(port);
        pr_info("Rule added: %s %d\n", ip_str, port);
        rule_count++;
    }

    kfree(kbuf);
    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops proc_fops = {
    .proc_write = proc_write,
};
#else
static const struct file_operations proc_fops = {
    .write = proc_write,
};
#endif

// Log dropped packets to file
static void log_packet(const struct sk_buff *skb, const struct iphdr *ip_header, const struct tcphdr *tcp_header) {
    struct file *file;
    char log_buf[256];
    struct timespec64 ts;
    struct tm tm;
    loff_t pos;

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);

    snprintf(log_buf, sizeof(log_buf),
             "[%04ld-%02d-%02d %02d:%02d:%02d] BLOCKED: %pI4:%d -> %pI4:%d on %s (TCP)\n",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             &ip_header->saddr, ntohs(tcp_header->source),
             &ip_header->daddr, ntohs(tcp_header->dest),
             skb->dev ? skb->dev->name : "unknown");

    file = filp_open(LOG_PATH, O_WRONLY | O_CREAT, 0644);  // Removed O_APPEND
    if (!IS_ERR(file)) {
        file->f_mode |= FMODE_WRITE;  // ✅ Ensure write mode
        pos = i_size_read(file_inode(file));  // ✅ Always write to file end

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        kernel_write(file, log_buf, strlen(log_buf), &pos);
#else
        vfs_write(file, log_buf, strlen(log_buf), &pos);
#endif
        filp_close(file, NULL);
    }
}

// Hook function
static unsigned int hook_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int i;

    if (!skb) return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (ip_header->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcp_header = (void *)ip_header + ip_header->ihl * 4;

    for (i = 0; i < rule_count; i++) {
        if (ip_header->saddr == rules[i].ip && tcp_header->source == rules[i].port) {
            log_packet(skb, ip_header, tcp_header);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static int __init firewall_init(void) {
    proc_file = proc_create("firewall_rules", 0666, NULL, &proc_fops);
    if (!proc_file) return -ENOMEM;

    nfho.hook = hook_fn;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    pr_info("Firewall Logger Module Loaded.\n");
    return 0;
}

static void __exit firewall_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    proc_remove(proc_file);
    pr_info("Firewall Logger Module Unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);


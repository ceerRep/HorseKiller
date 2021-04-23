extern "C"
{
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <net/if.h>

#include <80211Wrapper.h>
}

#include <tuple>
#include <string>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / (sizeof(decltype(*x))))
#endif

struct chandef
{
    enum nl80211_chan_width width;

    unsigned int control_freq;
    unsigned int center_freq1;
    unsigned int center_freq2;
};

static const std::tuple<std::string, nl80211_chan_width, int, nl80211_channel_type> chanmode[] = {
    {"HT20",
     NL80211_CHAN_WIDTH_20,
     0,
     NL80211_CHAN_HT20},
    {"HT40+",
     NL80211_CHAN_WIDTH_40,
     10,
     NL80211_CHAN_HT40PLUS},
    {"HT40-",
     NL80211_CHAN_WIDTH_40,
     -10,
     NL80211_CHAN_HT40MINUS},
    {"NOHT",
     NL80211_CHAN_WIDTH_20_NOHT,
     0,
     NL80211_CHAN_NO_HT},
    {"5MHz",
     NL80211_CHAN_WIDTH_5,
     0,
     (nl80211_channel_type)-1},
    {"10MHz",
     NL80211_CHAN_WIDTH_10,
     0,
     (nl80211_channel_type)-1},
    {"80MHz",
     NL80211_CHAN_WIDTH_80,
     0,
     (nl80211_channel_type)-1},
};

int get_cf1(nl80211_chan_width width, int diff, unsigned long freq)
{
    unsigned int cf1 = freq, j;
    unsigned int vht80[] = {5180, 5260, 5500, 5580, 5660, 5745, 5825};

    switch (width)
    {
    case NL80211_CHAN_WIDTH_80:
        /* setup center_freq1 */
        for (j = 0; j < ARRAY_SIZE(vht80); j++)
        {
            if (freq >= vht80[j] && freq < vht80[j] + 80)
                break;
        }

        if (j == ARRAY_SIZE(vht80))
            break;

        cf1 = vht80[j] + 30;
        break;
    default:
        cf1 = freq + diff;
        break;
    }

    return cf1;
}

chandef getChandef(int channel, std::string channel_width)
{
    chandef def;
    memset(&def, 0, sizeof def);

    int freq = ieee80211_channel_to_frequency(channel, channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);
    def.control_freq = def.center_freq1 = freq;

    if (channel_width.length())
    {
        for (const auto &[name, width, diff, type] : chanmode)
        {
            if (channel_width == name)
            {
                def.width = width;
                def.center_freq1 = get_cf1(width, diff, freq);
                def.width = width;
            }
        }
    }

    return def;
}

int setChannel(nl_msg *msg, int channel, std::string channel_width)
{
    auto def = getChandef(channel, channel_width);
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, def.control_freq);
    NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, def.width);

    switch (def.width)
    {
    case NL80211_CHAN_WIDTH_20_NOHT:
        NLA_PUT_U32(msg,
                    NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                    NL80211_CHAN_NO_HT);
        break;
    case NL80211_CHAN_WIDTH_20:
        NLA_PUT_U32(msg,
                    NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                    NL80211_CHAN_HT20);
        break;
    case NL80211_CHAN_WIDTH_40:
        if (def.control_freq > def.center_freq1)
            NLA_PUT_U32(msg,
                        NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                        NL80211_CHAN_HT40MINUS);
        else
            NLA_PUT_U32(msg,
                        NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                        NL80211_CHAN_HT40PLUS);
        break;
    default:
        break;
    }

    if (def.center_freq1)
        NLA_PUT_U32(msg,
                    NL80211_ATTR_CENTER_FREQ1,
                    def.center_freq1);

    if (def.center_freq2)
        NLA_PUT_U32(msg,
                    NL80211_ATTR_CENTER_FREQ2,
                    def.center_freq2);

    return 0;

nla_put_failure:
    return -ENOBUFS;
}

namespace
{
    int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                      void *arg)
    {
        struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
        int len = nlh->nlmsg_len;
        struct nlattr *attrs;
        struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
        int *ret = (int *)arg;
        int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

        *ret = 0;

        if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
            return NL_STOP;

        if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
            ack_len += err->msg.nlmsg_len - sizeof(*nlh);

        if (len <= ack_len)
            return NL_STOP;

        attrs = (nlattr *)((unsigned char *)nlh + ack_len);
        len -= ack_len;

        nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
        if (tb[NLMSGERR_ATTR_MSG])
        {
            len = strnlen((char *)nla_data(tb[NLMSGERR_ATTR_MSG]),
                          nla_len(tb[NLMSGERR_ATTR_MSG]));
            fprintf(stderr, "kernel reports: %*s\n", len,
                    (char *)nla_data(tb[NLMSGERR_ATTR_MSG]));
        }

        return NL_STOP;
    }

    static int finish_handler(struct nl_msg *msg, void *arg)
    {
        int *ret = (int *)arg;
        *ret = 0;
        return NL_SKIP;
    }

    static int ack_handler(struct nl_msg *msg, void *arg)
    {
        int *ret = (int *)arg;
        *ret = 0;
        return NL_STOP;
    }

    static int (*registered_handler)(struct nl_msg *, void *);
    static void *registered_handler_data;

    void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
    {
        registered_handler = handler;
        registered_handler_data = data;
    }

    int valid_handler(struct nl_msg *msg, void *arg)
    {
        if (registered_handler)
            return registered_handler(msg, registered_handler_data);

        return NL_OK;
    }
}

extern "C"
{
    int setChannel(const char *nif, int channel, const char *width)
    {
        struct nl_msg *msg;
        int ret, err;

        // Open socket to kernel.
        struct nl_sock *socket = nl_socket_alloc();           // Allocate new netlink socket in memory.
        genl_connect(socket);                                 // Create file descriptor and bind socket.
        int driver_id = genl_ctrl_resolve(socket, "nl80211"); // Find the nl80211 driver ID.

        // First we'll get info for wlan0.
        msg = nlmsg_alloc(); // Allocate a message.

        // auto cb = nl_cb_alloc(false ? NL_CB_DEBUG : NL_CB_DEFAULT);
        // auto s_cb = nl_cb_alloc(false ? NL_CB_DEBUG : NL_CB_DEFAULT);

        int if_index = if_nametoindex(nif);
        genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_SET_WIPHY, 0); // Setup the message.
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);                  // Add message attributes.

        setChannel(msg, channel, width);

        // nl_socket_set_cb(socket, s_cb);
        ret = nl_send_auto_complete(socket, msg);

        err = 1;

        // nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
        // nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
        // nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
        // nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

        // while (err > 0)
        // 	nl_recvmsgs(socket, cb);

        nl_recvmsgs_default(socket);

    // Goto statement required by NLA_PUT_U32().
    nla_put_failure:
        nl_close(socket);
        nlmsg_free(msg);
	nl_socket_free(socket);
        return 1;
    }

    int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
    {
        /* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
        if (chan <= 0)
            return 0; /* not supported */
        switch (band)
        {
        case NL80211_BAND_2GHZ:
            if (chan == 14)
                return 2484;
            else if (chan < 14)
                return 2407 + chan * 5;
            break;
        case NL80211_BAND_5GHZ:
            if (chan >= 182 && chan <= 196)
                return 4000 + chan * 5;
            else
                return 5000 + chan * 5;
            break;
        default:;
        }
        return 0; /* not supported */
    }

    int ieee80211_frequency_to_channel(int freq)
    {
        /* see 802.11 17.3.8.3.2 and Annex J */
        if (freq == 2484)
            return 14;
        else if (freq < 2484)
            return (freq - 2407) / 5;
        else if (freq >= 4910 && freq <= 4980)
            return (freq - 4000) / 5;
        else
            return (freq - 5000) / 5;
    }
}

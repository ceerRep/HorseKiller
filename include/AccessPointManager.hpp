#ifndef _ACCESS_POINT_MANAGER

#define _ACCESS_POINT_MANAGER

#include <map>
#include <deque>
#include <mutex>
#include <memory>
#include <tins/tins.h>
#include <Configuration.hpp>

using namespace Tins;

struct AccessPoint
{
    HWAddress<6> bssid;
    std::string essid;
    int channel;

    std::shared_ptr<Dot11ProbeResponse> resp;
    std::shared_ptr<Dot11Beacon> beacon;

    std::deque<double> signals;

    AccessPoint() : bssid(Tins::Dot11::BROADCAST), essid(), channel(1), signals(), resp(nullptr) {}

    bool operator<(const AccessPoint &r) const
    {
        return bssid < r.bssid;
    }
};

class AccessPointManager
{
    std::mutex lock;
    const Configuration &config;
    std::map<HWAddress<6>, AccessPoint> aps;
    std::map<std::string, AccessPoint*> ssid2ap_2, ssid2ap_5;

public:
    AccessPointManager(const Configuration &config) : config(config) {}

    void update(HWAddress<6> bssid, std::string essid, int channel, double signal)
    {
        std::lock_guard lg{lock};

        if (signal > 100 || signal < -100)
            return;

        if (aps.count(bssid) == 0)
        {
            std::cout << "AP detected: [" << channel << "] " << bssid.to_string() << ' ' << essid << ' ' << signal << std::endl;
        }

        auto &ap = aps[bssid];
        ap.bssid = bssid;
        ap.essid = essid;
        ap.channel = channel;
        ap.signals.push_back(signal);

        while (ap.signals.size() > config.channel_stat_num)
            ap.signals.pop_front();
        
        if (channel <= 14)
            ssid2ap_2[essid] = &ap;
        else
            ssid2ap_5[essid] = &ap;
    }

    void addResponse(Dot11ProbeResponse *resp)
    {
        std::lock_guard lg{lock};

        if (aps.count(resp->addr2()))
        {
            auto &ap = aps[resp->addr2()];
            ap.resp = std::shared_ptr<Dot11ProbeResponse>(resp->clone());
        }
    }

    void addBeacon(Dot11Beacon *beacon)
    {
        std::lock_guard lg{lock};

        if (aps.count(beacon->addr2()))
        {
            auto &ap = aps[beacon->addr2()];
            ap.beacon = std::shared_ptr<Dot11Beacon>(beacon->clone());
        }
    }

    AccessPoint getApByESSID(std::string essid, int band)
    {
        std::lock_guard lg{lock};

        if (band || band == 2)
        {
            if (ssid2ap_2.count(essid))
                return *ssid2ap_2[essid];
        }

        if (band || band == 5)
        {
            if (ssid2ap_5.count(essid))
                return *ssid2ap_5[essid];
        }

        return AccessPoint();
    }

    std::map<int, std::vector<AccessPoint>> getAPs()
    {
        std::lock_guard lg{lock};

        std::map<int, std::vector<AccessPoint>> ret;

        std::vector<std::tuple<AccessPoint, double>> view;

        for (const auto &[_, ap] : aps)
        {
            double sum = 0.0;

            for (auto x : ap.signals)
                sum += x;

            sum /= ap.signals.size();

            view.push_back({ap, sum});

            if (sum > config.channel_minimum_dbm)
            {
                ret[ap.channel].push_back(ap);
            }
        }

        std::sort(view.begin(), view.end(), [](const auto &l, const auto &r) -> bool {
            auto &[_1, s1] = l;
            auto &[_2, s2] = r;

            return s1 > s2;
        });

        for (auto &[ap, sum] : view)
        {
            std::cout << ap.channel << ' '
                      << ap.bssid << ' '
                      << ap.essid << ' '
                      << sum << ' '
                      << ((bool)ap.resp) << std::endl;
        }

        return ret;
    }
};

#endif // _ACCESS_POINT_MANAGER

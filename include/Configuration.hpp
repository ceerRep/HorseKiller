#ifndef _CONFIGURATION_HPP
#define _CONFIGURATION_HPP

#include <yaml-cpp/yaml.h>
#include <vector>

struct Configuration
{
    int channel_minimum_dbm;
    int channel_stat_num;

    int scan_stage_channel_time;
    int attack_stage_channel_time;

    std::string device;
    bool drop_fcs;

    int scan_round;

    std::vector<int> channels;

    std::string target_mac;
};

namespace YAML
{
    template <>
    struct convert<Configuration>
    {
        static Node encode(const Configuration &rhs)
        {
            Node node;

            node["channel_minimum_dbm"] = rhs.channel_minimum_dbm;
            node["channel_stat_num"] = rhs.channel_stat_num;
            node["scan_stage_channel_time"] = rhs.scan_stage_channel_time;
            node["attack_stage_channel_time"] = rhs.attack_stage_channel_time;
            node["scan_round"] = rhs.scan_round;

            node["device"] = rhs.device;
            node["drop_fcs"] = rhs.drop_fcs;
            
            node["channels"] = rhs.channels;
            node["target_mac"] = rhs.target_mac;

            return node;
        }

        static bool decode(const Node &node, Configuration &rhs)
        {
            rhs.channel_minimum_dbm = node["channel_minimum_dbm"].as<int>();
            rhs.channel_stat_num = node["channel_stat_num"].as<int>();
            rhs.scan_stage_channel_time = node["scan_stage_channel_time"].as<int>();
            rhs.attack_stage_channel_time = node["attack_stage_channel_time"].as<int>();
            rhs.scan_round = node["scan_round"].as<int>();

            rhs.device = node["device"].as<std::string>();
            rhs.drop_fcs = node["drop_fcs"].as<bool>();
            
            rhs.channels = node["channels"].as<std::vector<int>>();
            rhs.target_mac = node["target_mac"].as<std::string>();
            return true;
        }
    };
}

#endif // _CONFIGURATION_HPP
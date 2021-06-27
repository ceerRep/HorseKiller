#ifndef _REGION_CONFIGURATION_HPP

#define _REGION_CONFIGURATION_HPP

#include "Configuration.hpp"

struct RegionConfiguration : public Configuration
{
    std::vector<std::string> target_ssids;
};

namespace YAML
{
    template <>
    struct convert<RegionConfiguration>
    {
        static Node encode(const RegionConfiguration &rhs)
        {
            Node node = convert<Configuration>::encode(rhs);
            node["target_ssids"] = rhs.target_ssids;

            return node;
        }

        static bool decode(const Node &node, RegionConfiguration &rhs)
        {
            bool ret = convert<Configuration>::decode(node, rhs);
            rhs.target_ssids = node["target_ssids"].as<std::vector<std::string>>();
            
            return ret;
        }
    };
}

#endif

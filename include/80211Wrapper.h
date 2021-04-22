#ifndef _80211_WRAPPER
#define _80211_WRAPPER

#include <linux/nl80211.h>

int setChannel(const char* nif, int channel, const char* width);
int ieee80211_channel_to_frequency(int chan, enum nl80211_band band);
int ieee80211_frequency_to_channel(int freq);

#endif // _80211_WRAPPER
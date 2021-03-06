//
// Why this file?
//
// We all need to add our personal SSID/password to each ESP project but we
// do not want that information pushed to Github. This file solves that
// problem.
//
// First tell git to ignore changes to this file:
//
// git update-index --assume-unchanged include/ssid_config.h 
//
// Then, enter your SSID and passphrase below and it will never be committed
// to Github.
//
// Change password on project basis? Copy the default version this file to your
// project directory, redo the instructions and you have separate wifi settings
// for that project.
// 
// For reference, see
//   https://www.kernel.org/pub/software/scm/git/docs/git-update-index.html
//


#ifndef __SSID_CONFIG_H__
#define __SSID_CONFIG_H__
#if 1
#define WIFI_SSID "NETGEAR29"
#define WIFI_PASS "0935489948"
#else
#define WIFI_SSID "DEMO"
#define WIFI_PASS "zaq12345"
#endif
#endif // __SSID_CONFIG_H__

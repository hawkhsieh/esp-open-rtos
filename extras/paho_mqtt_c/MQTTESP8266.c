/**
  ******************************************************************************
  * @file    MQTTESP8266.c
  * @author  Baoshi <mail(at)ba0sh1(dot)com>
  * @version 0.1
  * @date    Sep 9, 2015
  * @brief   Eclipse Paho ported to ESP8266 RTOS
  *
  ******************************************************************************
  * @copyright
  *
  * Copyright (c) 2015, Baoshi Zhu. All rights reserved.
  * Use of this source code is governed by a BSD-style license that can be
  * found in the LICENSE.txt file.
  *
  * THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS OR IMPLIED
  * WARRANTY.  IN NO EVENT WILL THE AUTHOR(S) BE HELD LIABLE FOR ANY DAMAGES
  * ARISING FROM THE USE OF THIS SOFTWARE.
  *
  */


#include <espressif/esp_common.h>
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/sys.h>
#include "lwip/api.h"

#include <string.h>

#include "MQTTESP8266.h"

#include "mbedtls/config.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "asdLog.h"

#define TLS

#if 0
const char *server_root_cert = "-----BEGIN CERTIFICATE-----"\
"MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU"\
"MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs"\
"IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290"\
"MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux"\
"FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h"\
"bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v"\
"dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt"\
"H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9"\
"uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX"\
"mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX"\
"a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN"\
"E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0"\
"WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD"\
"VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0"\
"Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU"\
"cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx"\
"IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN"\
"AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH"\
"YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5"\
"6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC"\
"Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX"\
"c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a"\
"mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ="\
"-----END CERTIFICATE-----";
#endif


char  expired(Timer* timer)
{
    portTickType now = xTaskGetTickCount();
    int32_t left = timer->end_time - now;
    return (left < 0);
}


void  countdown_ms(Timer* timer, unsigned int timeout)
{
    portTickType now = xTaskGetTickCount();
    timer->end_time = now + timeout / portTICK_RATE_MS;
}


void  countdown(Timer* timer, unsigned int timeout)
{
    countdown_ms(timer, timeout * 1000);
}


int  left_ms(Timer* timer)
{
    portTickType now = xTaskGetTickCount();
    int32_t left = timer->end_time - now;
    return (left < 0) ? 0 : left / portTICK_RATE_MS;
}


void  InitTimer(Timer* timer)
{
    timer->end_time = 0;
}

#ifdef TLS

void hexDump (char *desc, char *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        infof ("%s:\n", desc);

    if (len == 0) {
        infof("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        infof("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                infof ("  %s\n", buff);

            // Output the offset.
            infof ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        infof (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        infof ("   ");
        i++;
    }

    // And print the final ASCII bit.
    infof ("  %s\n", buff);
}


int  mqtt_esp_read(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
    int rcvd = 0;
    int ret=0;

    ret = mbedtls_ssl_read(&n->tls.ssl, buffer, len);

    if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        infof("closed by peer\n");
    }

    if ( ret == -76 ){
        errf("ret=-76\n");
        int rc = 0;
        struct timeval tv;
        fd_set fdset;

        FD_ZERO(&fdset);
        FD_SET(n->tls.ctx.fd, &fdset);
        //It seems tv_sec actually means FreeRTOS tick
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = timeout_ms % 1000;
        rc = select(n->tls.ctx.fd + 1, &fdset, 0, 0, &tv);
        if ((rc > 0) && (FD_ISSET(n->tls.ctx.fd, &fdset)))
        {
        }
        else
        {
            return -1;
        }

    }else if(ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ){

        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        errf("mbedtls_ssl_read: %d - %s\n", ret, error_buf);

        ret = -1;
    }else{
      //  hexDump("read",(char*)buffer, ret);
    }

    rcvd = ret ;
    return rcvd;
}

int  ConnectNetwork(Network* n, const char* host, char *port)
{
    int ret;
    if ( (ret = TLSConnect_Init( &n->tls )) != 0 ){
        errf("ret=%d\n",ret);
        return -1;
    }
    if ( (ret = TLSConnect_OpenFD( &n->tls , (char*)host , port )) != 0 ) {
        TLSConnect_Destroy(&n->tls);
        errf("ret=%d\n",ret);
        return -1;
    }

    mbedtls_net_set_nonblock(&n->tls.ctx);
    return 0;
}

int  DisconnectNetwork(Network* n)
{
    TLSConnect_DisConnect(&n->tls);
    TLSConnect_Destroy(&n->tls);
    return 0;
}

int  mqtt_esp_write(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
	struct timeval tv;
	fd_set fdset;
    int rc = 0;
	FD_ZERO(&fdset);
    FD_SET(n->tls.ctx.fd, &fdset);
	// It seems tv_sec actually means FreeRTOS tick
    tv.tv_sec = timeout_ms / portTICK_RATE_MS;
    tv.tv_usec = 0;
    rc = select(n->tls.ctx.fd + 1, 0, &fdset, 0, &tv);
    if ((rc > 0) && (FD_ISSET(n->tls.ctx.fd, &fdset)))
	{
        while((rc = mbedtls_ssl_write(&n->tls.ssl, buffer , len)) <= 0)
        {
            if(rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                errf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", rc);
                goto exit;
            }
        }

        len = rc;
	}
	else
	{
        errf("errno=%d\n",errno);
	    // select fail
	    return -1;
	}
exit:
	return rc;
}

void  NewNetwork(Network* n)
{
    n->tls.ctx.fd = -1;
    n->mqttread = mqtt_esp_read;
	n->mqttwrite = mqtt_esp_write;
}


#if 0
int TLSConnectNetwork(Network *n, char* addr, int port, SlSockSecureFiles_t* certificates, unsigned char sec_method, unsigned int cipher, char server_verify) {
	SlSockAddrIn_t sAddr;
	int addrSize;
	int retVal;
	unsigned long ipAddress;

	retVal = sl_NetAppDnsGetHostByName(addr, strlen(addr), &ipAddress, AF_INET);
	if (retVal < 0) {
		return -1;
	}

	sAddr.sin_family = AF_INET;
	sAddr.sin_port = sl_Htons((unsigned short)port);
	sAddr.sin_addr.s_addr = sl_Htonl(ipAddress);

	addrSize = sizeof(SlSockAddrIn_t);

    n->server_fd.fd = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, SL_SEC_SOCKET);
    if (n->server_fd.fd < 0) {
		return -1;
	}

	SlSockSecureMethod method;
	method.secureMethod = sec_method;
    retVal = sl_SetSockOpt(n->server_fd.fd, SL_SOL_SOCKET, SL_SO_SECMETHOD, &method, sizeof(method));
	if (retVal < 0) {
		return retVal;
	}

	SlSockSecureMask mask;
	mask.secureMask = cipher;
    retVal = sl_SetSockOpt(n->server_fd.fd, SL_SOL_SOCKET, SL_SO_SECURE_MASK, &mask, sizeof(mask));
	if (retVal < 0) {
		return retVal;
	}

	if (certificates != NULL) {
        retVal = sl_SetSockOpt(n->server_fd.fd, SL_SOL_SOCKET, SL_SO_SECURE_FILES, certificates->secureFiles, sizeof(SlSockSecureFiles_t));
		if(retVal < 0)
		{
			return retVal;
		}
	}

    retVal = sl_Connect(n->server_fd.fd, ( SlSockAddr_t *)&sAddr, addrSize);
	if( retVal < 0 ) {
		if (server_verify || retVal != -453) {
            sl_Close(n->server_fd.fd);
			return retVal;
		}
	}

	SysTickIntRegister(SysTickIntHandler);
	SysTickPeriodSet(80000);
	SysTickEnable();

	return retVal;
}




static int  host2addr(const char *hostname , struct in_addr *in)
{
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(hostname, 0 , &hints , &servinfo);
    if (rv != 0)
    {
        return rv;
    }

    // loop through all the results and get the first resolve
    for (p = servinfo; p != 0; p = p->ai_next)
    {
        h = (struct sockaddr_in *)p->ai_addr;
        in->s_addr = h->sin_addr.s_addr;
    }
    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}

#endif
#endif

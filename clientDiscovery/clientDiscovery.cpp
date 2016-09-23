#undef SOAP_WSA_2005
#include <string>
#include <memory>

#include <iostream>

#include "soapStub.h"
#include "wsdd.nsmap"
#include "soapH.h"

using namespace::std; 

static shared_ptr<soap> ONVIF_Initsoap( const string& was_To, const string& was_Action, int timeout)
{
    auto soapClient = shared_ptr<soap>(new soap); 
    
    if(soapClient)
    {
        std::cout << "create Soap object Failed" << std::endl;
        return shared_ptr<soap>(nullptr); 
    }

    soap_set_namespaces(soapClient.get(), namespaces); 
    if(timeout <= 0)
        timeout = 10; 
    soapClient->recv_timeout = timeout; 
    soapClient->send_timeout = timeout; 
    soapClient->connect_timeout = timeout; 

    auto header = new SOAP_ENV__Header; 
    soapClient->header = header; 
    soap_default_SOAP_ENV__Header(soapClient.get(), header); 
    
    srand(time(0)); 
    auto Flagrand = rand()%9000 + 1000; 
    std::array<unsigned char, 6> macaddr{{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}};
    char _HwId[1024]; 
    sprintf(_HwId, "urn:uuid:%ud68a-1dd2-11b2-a105-%02X%02X%02X%02X%02X%02X", 
                        Flagrand,  macaddr[0],  macaddr[1],  macaddr[2],  macaddr[3],  macaddr[4],  macaddr[5]); 

    header->wsa__MessageID = new char[100]; 
    memset(header->wsa__MessageID, 0, 100); 
    strncpy(header->wsa__MessageID, _HwId, strlen(_HwId)); 

    if(!was_Action.empty())
    {
        header->wsa__Action = new char[1024]; 
        memset(header->wsa__Action, '\0', 1024); 
        strncpy(header->wsa__Action, was_Action.c_str(), 1024); 
    }

    if(!was_To.empty())
    {
        header->wsa__To = new char[was_To.length() + 1]; 
        strncpy(header->wsa__To, was_To.c_str(), was_To.length()); 
        header->wsa__To[was_To.length()] = '\0'; 
    }
    soapClient->header = header; 
    return soapClient; 
}

int ONVIF_ClientDiscovery()
{
    const string& was_To        ="urn:schemas-xmlsoap-org:ws:2005:04:discovery";  
    const string& was_Action    = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"; 
    const string& soap_endpoint = "soap.udp://239.255.255.250:3702/"; 

    auto soapClient = ONVIF_Initsoap(was_To, was_Action, 5); 

    wsdd__ScopesType sScope; 
    soap_default_wsdd__ScopesType(soapClient.get(), &sScope); 
    sScope.__item = nullptr; 

    wsdd__ProbeType req; 
    soap_default_wsdd__ProbeType(soapClient.get(), &req); 
    req.Scopes = &sScope; 
    req.Types = nullptr; 

    auto retval = soap_send___wsdd__Probe(soapClient.get(), soap_endpoint.c_str(), nullptr, &req); 

    struct __wsdd__ProbeMatches resp; 
    unsigned hasDev = 0; 
    while(retval == SOAP_OK)
    {
        retval  = soap_recv___wsdd__ProbeMatches(soapClient.get(), &resp); 
        if(retval == SOAP_OK)
        {
            if(soapClient->error){
                cout << "[" << __LINE__ << "] recv error:" << soapClient->error << ", " << *soap_faultcode(soapClient.get()) << ", " <<   *soap_faultstring(soapClient.get()) << endl;  
                retval = soapClient->error; 
            }
            else
            {
                hasDev ++ ;  
                if(resp.wsdd__ProbeMatches->ProbeMatch != nullptr  && resp.wsdd__ProbeMatches->ProbeMatch->XAddrs != nullptr)
                {
                    printf(" ################  recv  %d devices info #### \n",  hasDev ); 
                    printf("Target Service Address  : %s\r\n",  resp.wsdd__ProbeMatches->ProbeMatch->XAddrs); 
                    printf("Target EP Address       : %s\r\n",  resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address); 
                    printf("Target Type             : %s\r\n",  resp.wsdd__ProbeMatches->ProbeMatch->Types); 
                    printf("Target Metadata Version : %d\r\n",  resp.wsdd__ProbeMatches->ProbeMatch->MetadataVersion); 
                    sleep(1); 
                }
            }
        }
        else if(soapClient->error)
        {
            if(hasDev == 0)
            {
                printf("[%s][%d] Thers Device discovery or soap error: %d,  %s,  %s \n",  __func__,  __LINE__,  soapClient->error,  *soap_faultcode(soapClient.get()),  *soap_faultstring(soapClient.get())); 
                retval  =  soapClient->error; 
            }
            else
            {
                 printf(" [%s]-[%d] Search end! It has Searched %d devices! \n",  __func__,  __LINE__,  hasDev); 
                 retval  =  0; 
            }
        }
    }
    soap_destroy(soapClient.get()); 
    soap_end(soapClient.get()); 
    soap_free(soapClient.get()); 
}

int main(void)
{
    if(ONVIF_ClientDiscovery() != 0)
    {
        cout << "Discovery Failed!" << endl; 
        return -1; 
    }
    return 0;
}

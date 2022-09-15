using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    enum ProcessStep
    {
        AREG_REQ,        //App Regist Request
        AREG_PLY,        //App Regist Reply
        UUID_RPT,        // UUID Report 
        UUID_ACK,        // UUID Report ACK
        CRED_REQ,        //credential Request
        CRED_PLY,        //credential Reply
        AREG_CMP,        //App Regist Complete
        AREG_FIN,        //App Regist Finished

        VCON_REQ,        //Verify connect Request
        VCON_PLY,        //Verify connect Reply
        AVRY_REQ,        // App Vryope Request
        AVRY_PLY,        // App Vryope Reply
        AVRY_CMP,        // App Vryope Complete
        AVRY_FIN,        // App Vryope Finished

        WCON_REQ,       // WebSocket Connect Request
        WCON_PLY,       // WebSocket Connect Reply
        WUID_ANN,       // WebSocket UUID Announce

        STEP_ERR
    }


    enum DeviceType
    {
        CONSOLE,
        MOBILE


    }

  

}

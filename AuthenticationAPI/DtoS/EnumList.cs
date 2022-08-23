using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    enum ProcessStep
    {
        AREG_REQ,        //App Regist Request
        AERG_PLY,        //App Regist Reply
        CRED_REQ,        //credential Request
        CRED_PLY,        //credential Reply
        UUID_RPT,        // UUID Report 
        UUID_ACK,        // UUID Report ACK
        UUID_ANN,        // UUID Announce
        AREG_CMP,        //App Regist Complete
        AREG_FIN,        //App Regist Finished
        HSPW_ANN,        //HASH Password Announce
        VRYP_CMP,         //App Verify Complete
        WSKT_CON,       // WebSocket Connect
        STEP_ERR
    }


    enum DeviceType
    {
        CONSOLE,
        MOBILE


    }

  

}

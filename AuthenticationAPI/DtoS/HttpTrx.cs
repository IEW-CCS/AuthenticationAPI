using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class HTTPTrx
    {
        public string UserName { get; set; }
        public string DeviceType { get; set; }
        public string ProcStep { get; set; }
        public int ReturnCode { get; set; }
        public string ReturnMsg { get; set; }
        public string DataContent { get; set; }
        public string ECS { get; set; }            // Encrype with Public Key 
        public string ECSSign { get; set; }

        public HTTPTrx()
        {
            UserName = string.Empty;
            DeviceType = string.Empty;
            ProcStep = string.Empty;
            ReturnCode = 0;
            ReturnMsg = string.Empty;
            DataContent = string.Empty;
            ECS = string.Empty;
            ECSSign = string.Empty;
        }

    }
}



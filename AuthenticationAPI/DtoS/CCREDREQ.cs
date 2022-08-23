using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CCREDREQ
    {
        public string ServerName { get; set; }
        public string UserName { get; set; }
        public string MobileRSAPublicKey { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CCREDPLY
    {
        public string ServerName { get; set; }
        public string Credential { get; set; }
        public string ServerRSAPublicKey { get; set; }
        public DateTime TimeStamp { get; set; }
    }
}

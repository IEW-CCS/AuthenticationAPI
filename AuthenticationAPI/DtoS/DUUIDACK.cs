using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DUUIDACK
    {
        public string ServerName { get; set; }
        public string ServicePublicKey { get; set; }
        public DateTime TimeStamp { get; set; }

        public DUUIDACK()
        {
            ServerName = string.Empty;
            ServicePublicKey = string.Empty;
            TimeStamp = DateTime.Now;
        }
    }
}

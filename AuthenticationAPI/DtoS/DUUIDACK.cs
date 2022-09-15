using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DUUIDACK
    {
        public string ServerName { get; set; }
        public string ServerPublicKey { get; set; }

        public DUUIDACK()
        {
            ServerName = "";
            ServerPublicKey = "";
        }
    }
}

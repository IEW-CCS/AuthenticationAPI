using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CRUIDPLY
    {
        public string ServerName { get; set; }
        public string ServerPublicKey { get; set; }

        public CRUIDPLY()
        {
            ServerName = "";
            ServerPublicKey = "";
        }
    }
}

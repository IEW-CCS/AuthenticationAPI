using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CRCRLPLY
    {
        public string CredentialSign { get; set; }

        public CRCRLPLY()
        {
            CredentialSign = "";
        }
    }
}

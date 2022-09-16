using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APREGFIN
    {
        public string AuthenticationToken { get; set; }
        public string AuthenticationURL { get; set; }
        public APREGFIN()
        {
            AuthenticationToken = string.Empty;
            AuthenticationURL = string.Empty;
        }
    }
}

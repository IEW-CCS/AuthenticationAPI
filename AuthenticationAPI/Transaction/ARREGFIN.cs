using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class ARREGFIN
    {
        public string AuthenticationToken { get; set; }
        public string AuthenticationURL { get; set; }
        public ARREGFIN()
        {
            AuthenticationToken = string.Empty;
            AuthenticationURL = string.Empty;
        }
    }
}

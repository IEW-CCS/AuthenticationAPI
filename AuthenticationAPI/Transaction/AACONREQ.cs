using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AACONREQ
    {
        public string DeviceCode { get; set; }
       
        public AACONREQ()
        {
            DeviceCode = string.Empty;
        }
    }
}

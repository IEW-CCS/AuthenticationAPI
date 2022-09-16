using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AVCONREQ
    {
        public string DeviceCode { get; set; }
       
        public AVCONREQ()
        {
            DeviceCode = string.Empty;
        }
    }
}

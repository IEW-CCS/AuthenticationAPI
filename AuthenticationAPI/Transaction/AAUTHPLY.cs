using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AAUTHPLY
    {
        public string SerialNumber { get; set; }
     
        public AAUTHPLY()
        {
            SerialNumber = string.Empty;
        }
    }
}

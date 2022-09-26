using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AACONPLY
    {
        public string PassCode { get; set; }
    
        public AACONPLY()
        {
            PassCode = string.Empty; 
        }
    }
}

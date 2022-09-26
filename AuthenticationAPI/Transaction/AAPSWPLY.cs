using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AAPSWPLY
    {
        public string PassWordData { get; set; }
     
        public AAPSWPLY()
        {
            PassWordData = string.Empty;
        }
    }
}

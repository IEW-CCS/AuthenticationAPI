using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AAUTHREQ
    {
     
        public string PassWord { get; set; }
        public string PassCode { get; set; }


        public AAUTHREQ()
        {
            PassWord = string.Empty;
            PassCode = string.Empty;
        }
    }
}

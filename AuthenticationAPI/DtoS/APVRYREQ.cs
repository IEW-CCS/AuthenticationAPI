using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APVRYREQ
    {
     
        public string PassWord { get; set; }
        public string PassCode { get; set; }


        public APVRYREQ()
        {
            PassWord = string.Empty;
            PassCode = string.Empty;
        }
    }
}

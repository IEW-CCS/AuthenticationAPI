using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CCREDREQ
    {
        public string UserName { get; set; }
        public DateTime TimeStamp { get; set; }

        public CCREDREQ()
        {
            UserName = string.Empty;
            TimeStamp = DateTime.Now;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CCREDPLY
    {
        public string ServerName { get; set; }
        public string Credential { get; set; }
        public DateTime TimeStamp { get; set; }

        public CCREDPLY()
        {
            ServerName = string.Empty;
            Credential = string.Empty;
            TimeStamp = DateTime.Now;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class GENQRINFO
    {
        public string ServerName { get; set; }
        public string UserName { get; set; }
        public string HttpURL { get; set; }
        public string HttpToken { get; set; }
        public string ProcStep { get; set; }
    }
}

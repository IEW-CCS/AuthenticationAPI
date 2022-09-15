using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class HttpTrx
    {
        public string username { get; set; }
        public string devicetype { get; set; }
        public string procstep { get; set; }
        public int returncode { get; set; }
        public string returnmsg { get; set; }
        public string datacontent { get; set; }
        public string ecs { get; set; }            // Encrype with Public Key 
        public string ecssign { get; set; }

        public HttpTrx()
        {
            username = "";
            devicetype = "";
            procstep = "";
            returncode = 0;
            returnmsg = "";
            datacontent = "";
            ecs = "";
            ecssign = "";
        }

    }
}



using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DBContext
{
    public class AUTH_SECURITY
    {
        public int id { get; set; }
        public string username { get; set; }
        public string device_type { get; set; }
        public string client_publickey { get; set; }
        public string server_publickey { get; set; }
        public string server_privatekey { get; set; }
    }
}

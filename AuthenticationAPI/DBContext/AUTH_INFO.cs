using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DBContext
{
    public class AUTH_INFO
    {
        public int id { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string sign { get; set; }
    }
}

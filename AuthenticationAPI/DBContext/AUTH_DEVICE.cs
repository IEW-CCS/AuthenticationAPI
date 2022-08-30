using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DBContext
{
    public class AUTH_DEVICE
    {
        public int id { get; set; }
        public string username { get; set; }
        public string deviceuuid { get; set; }
        public string credential { get; set; }
    }
}

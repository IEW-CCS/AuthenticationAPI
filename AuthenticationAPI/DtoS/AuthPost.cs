using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AuthPost
    {
        public string UserID { get; set; }
        public string VryopeData { get; set; }
        public DateTime TimeStamp { get; set; }
    }
}

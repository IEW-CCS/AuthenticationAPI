using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APVRYPLY
    {
        public string HashPassword { get; set; }
        public string Result { get; set; }
        public DateTime TimeStamp { get; set; }

        public APVRYPLY()
        {
            HashPassword = string.Empty;
            Result = string.Empty;
            TimeStamp = DateTime.Now;
        }
    }
}

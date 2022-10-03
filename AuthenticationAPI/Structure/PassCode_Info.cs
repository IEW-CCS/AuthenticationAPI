using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Structure
{
    public class PassCode_Info
    {
        public string PassCode { get; set; }
        public DateTime CreateDateTime { get; set; }

        public PassCode_Info()
        {
            PassCode = string.Empty;
            CreateDateTime = DateTime.Now;
        }
    }
}

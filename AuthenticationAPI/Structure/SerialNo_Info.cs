using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Structure
{
    public class SerialNo_Info
    {
        public string SerialNo { get; set; }
        public DateTime CreateDateTime { get; set; }

        public SerialNo_Info()
        {
            SerialNo = string.Empty;
            CreateDateTime = DateTime.Now;
        }
    }
}

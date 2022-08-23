using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class HttpECS
    {
        public string Algo { get; set; }
        public string Key { get; set; }
        public string IV { get; set; }

    }
}

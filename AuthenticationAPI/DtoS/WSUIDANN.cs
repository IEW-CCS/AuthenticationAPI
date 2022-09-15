﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class WSUIDANN
    {
       
        public string Credential { get; set; }
        public string SignedPublicKey { get; set; }


        public WSUIDANN()
        {

            Credential = string.Empty;
            SignedPublicKey = string.Empty;
           
        }
    }
}
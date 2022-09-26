using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class AAPSWREQ
    {
        public string BiometricsResult { get; set; }
        public string SerialNo { get; set; }
        public string CredentialSign { get; set; }


        public AAPSWREQ()
        {
            BiometricsResult = string.Empty;
            SerialNo = string.Empty;
            CredentialSign = string.Empty;
        }
    }
}

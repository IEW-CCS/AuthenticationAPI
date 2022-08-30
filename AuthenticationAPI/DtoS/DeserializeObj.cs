using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DeserializeObj
    {
        public static HttpTrx _HttpTrx(string DataContent)
        {
            HttpTrx obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<HttpTrx>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;

        }
        public static ECS _ECS(string DataContent)
        {
            ECS obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<ECS>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APREGREQ _APREGREQ(string DataContent)
        {
            APREGREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APREGREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APREGPLY _APREGPLY(string DataContent)
        {
            APREGPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APREGPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APREGCMP _APREGCMP(string DataContent)
        {
            APREGCMP obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APREGCMP>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static CCREDREQ _CCREDREQ(string DataContent)
        {
            CCREDREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<CCREDREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static CCREDPLY _CCREDPLY(string DataContent)
        {
            CCREDPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<CCREDPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static DUUIDRPT _DUUIDRPT(string DataContent)
        {
            DUUIDRPT obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<DUUIDRPT>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static DUUIDACK _DUUIDACK(string DataContent)
        {
            DUUIDACK obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<DUUIDACK>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static DUUIDANN _DUUIDANN(string DataContent)
        {
            DUUIDANN obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<DUUIDANN>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APVRYCMP _APVRYCMP(string DataContent)
        {
            APVRYCMP obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APVRYCMP>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APVRYREQ _APVRYREQ(string DataContent)
        {
            APVRYREQ obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APVRYREQ>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
        public static APVRYPLY _APVRYPLY(string DataContent)
        {
            APVRYPLY obj = null;
            try
            {
                obj = JsonSerializer.Deserialize<APVRYPLY>(DataContent);
            }
            catch
            {
                obj = null;
            }
            return obj;
        }
    }
}

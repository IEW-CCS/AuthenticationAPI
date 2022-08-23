using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class MessageMap
    {
        public string Msg_id { get;  }
        public string Obj_id { get;  }
        public string Method { get;  }


        // Service ObjectID  MethodID.
        public MessageMap (string ServiceID, string objectID, string methodName)
        {
            Msg_id = ServiceID;
            Obj_id = objectID;
            Method = methodName;
        }

    }
}

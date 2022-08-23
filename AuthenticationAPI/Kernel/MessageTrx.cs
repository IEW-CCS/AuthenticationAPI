using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class MessageTrx
    {
        private string _clientID;
        private string _function;
        private string _data;
        private DateTime _timeStamp;
       
        public string ClientID
        {
            get
            {
                return this._clientID;
            }
            set
            {
                this._clientID = value;
            }
        }

        public string Function
        {
            get
            {
                return this._function;
            }
            set
            {
                this._function = value;
            }
        }

        public string Data
        {
            get
            {
                return this._data;
            }
            set
            {
                this._data = value;
            }
        }

        public DateTime TimeStamp
        {
            get
            {
                return this._timeStamp;
            }
            set
            {
                this._timeStamp = value;
            }
        }


        public MessageTrx()
        {
            this.ClientID = string.Empty;
            this.Data = string.Empty;
            this.Function = string.Empty;
            this.TimeStamp = DateTime.Now;
        }
    }
}

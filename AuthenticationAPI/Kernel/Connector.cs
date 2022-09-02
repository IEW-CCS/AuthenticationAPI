using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class Connector
    {

        private string _methodName;

        private string _objectId;

        private bool _isInitRun;

        private MethodInfo _methodInfo;

        private IHttpTrxService _service;

        private object _syncObject = new object();

        private const long _limit_RunTime = (long)200;

        private bool _enabled;

        private bool IsEnabled
        {
            get
            {
                return this._enabled;
            }
        }

        private bool IsInitRun
        {
            get
            {
                return this._isInitRun;
            }
        }

        public string ObjectId
        {
            get
            {
                return this._objectId;
            }
            set
            {
                this._objectId = value;
            }
        }

        public string MethodName
        {
            get
            {
                return this._methodName;
            }
            set
            {
                this._methodName = value;
            }
        }

        public IHttpTrxService Service
        {
            get
            {
                return this._service;
            }
            set
            {
                this._service = value;
            }
        }



        public void Init(string objectId, string m)
        {

            this._objectId = objectId;
            this._methodName = m;
            this._isInitRun = true;
            this._methodInfo = null;
            this._enabled = true;

        }

        private void Disable()
        {
            this._enabled = false;
        }

        private void Enable()
        {
            this._enabled = true;
        }

        private void Exe_Reflection(object o)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            string method = string.Empty;
            int param_count = 0;
            try
            {
                try
                {
                    object[] objects = o as object[];
                    object[] param = objects[1] as object[];
                    MethodInfo mi = objects[0] as MethodInfo;
                    method = mi.Name;
                    param_count = (param != null ? (int)param.Length : 0);  //  Record Log for debug used.
                    mi.Invoke(this._service, param);
                }
                catch (Exception exception)
                {
                    Exception ex = exception;

                }
            }
            finally
            {
                stopwatch.Stop();
            }
        }

        //非同步處理Invoke
        public bool BeginInvoke(object[] param)
        {
            bool flag;
            if (!this._enabled)
            {
                return false;
            }
            if (this._service == null)
            {
                throw new Exception("Handler  is not create.");
            }
            lock (this._syncObject)
            {
                if (this._isInitRun)
                {
                    MethodInfo mi = this._service.GetType().GetMethod(this._methodName);
                    this._isInitRun = false;
                    if (mi == null)
                    {
                        throw new Exception(string.Format("Methed {0} is not exist in class {1}.", this._methodName, this._service.GetType().ToString()));
                    }
                    this._methodInfo = mi;
                }
                if (this._methodInfo == null)
                {
                    throw new Exception(string.Format("Methed {0} is not exist in class {1}.", this._methodName, this._service.GetType().ToString()));
                }
                WaitCallback waitCallback = new WaitCallback(this.Exe_Reflection);
                object[] objArray = new object[] { this._methodInfo, param };
                flag = ThreadPool.QueueUserWorkItem(waitCallback, objArray);
            }
            return flag;
        }
    }
}

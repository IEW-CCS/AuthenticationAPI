using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationAPI.Kernel
{
    public class MessageManager : IMessageManager
    {
        private readonly IServiceProvider _serviceProvider;

        private object _syncObject = new object();
        public bool _stopFlag = false;
        private double _concurrentWorkCount;
        private Dictionary<string, Connector> _messageMapping;
        private List<MessageMap> _messageMapList ;

        private readonly ILogger _logger;

        public MessageManager(ILoggerFactory loggerFactory, IServiceProvider service)
        {
            _logger = loggerFactory.CreateLogger<MessageManager>();
            _serviceProvider = service;

            Init();
        }

        public void Init()
        {
            CreateMessageMap();
            MessageMap_Registered();
        }
        
        private void CreateMessageMap()
        {
            _messageMapList = new List<MessageMap>();
            _messageMapList.Add(new MessageMap("WS_LOGIN", "HelloService", "Hello"));
            _messageMapList.Add(new MessageMap("WS_LOGIN2", "HelloService", "Hello2"));

        }
        private void MessageMap_Registered()
        {
            _messageMapping = new Dictionary<string, Connector>();
            foreach (MessageMap objMsg in _messageMapList)
            {
                Connector item = new Connector();
                item.Init(objMsg.Obj_id, objMsg.Method);
                var ServiceCollection = _serviceProvider.GetServices<IService>();
                var obj = ServiceCollection.Where(o => o.ServiceName.Equals(item.ObjectId)).FirstOrDefault();
                if (obj != null)
                {
                    item.Service = (obj) as IService;
                    try
                    {
                        _messageMapping.Add(objMsg.Msg_id, item);
                    }
                    catch (Exception)
                    {
                        throw new Exception(string.Format("message=[{0}] is Add Error .", objMsg.Method));
                    }
                }
                else
                {
                    _logger.LogError("Object ID : " + item.ObjectId + " Not Exist in Register Table");
                }
            }
        }

        public void MessageDispatch(string name, object[] parameters)
        {
            lock (this._syncObject)
            {
                this._concurrentWorkCount += 1.0;
                if (this._concurrentWorkCount > double.MaxValue)
                {
                    this._concurrentWorkCount = 1.0;
                }
            }
            if (!this._stopFlag)
            {
                if (this._messageMapping.ContainsKey(name))
                {
                   Connector item = _messageMapping[name];
                   if (!item.BeginInvoke(parameters))
                   {
                     throw new Exception(string.Format("Message {0},objectID {1},Method {2}, Queue User Work Item Error.", name, item.ObjectId, item.MethodName));
                   }
                }
                else
                {
                    throw new Exception("Message Dispatch Not Exist Key = " + name);
                }
                return;
            }
            throw new Exception("Message Dispatch is Stop!");
        }
    }
}

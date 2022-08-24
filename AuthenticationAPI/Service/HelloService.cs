using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.DtoS;

namespace AuthenticationAPI.Service
{
    public class HelloService : IService
    {

        private string _SeviceName = "HelloService";
        private readonly IQueueManager _QueueManager;
        private readonly IObjectManager _ObjectManager;


        private  ObjectManager ConstObject;

        public HelloService (IQueueManager QueueManager, IObjectManager ObjectManager)
        {
            _QueueManager = QueueManager;
            _ObjectManager = ObjectManager;
 
            Init();

        }
        public string ServiceName
        {
            get
            {
                return this._SeviceName;
            }
        }

        public void Init()
        {
            ConstObject = (ObjectManager)_ObjectManager.GetInstance;
        }

        public void Hello(MessageTrx input)
        {
            MessageTrx SendOutMsg = new MessageTrx();
            SendOutMsg.ClientID = input.ClientID;
            SendOutMsg.Function = input.Function;
           
            SendOutMsg.Data = "This is Wenjou WebSocker and DB Test Test";
            _QueueManager.PutMessage(SendOutMsg);






            /*  第二種寫法 兩種都可以
            using (var db = new DBContext.DBContext(ConstObject.DB_Type, ConstObject.DB_ConnectString))
            {
                DBContext.HelloWould hellotesting = new DBContext.HelloWould();
                hellotesting.hello = "This is Wenjou WebSocker and DB Test Test";
                db.Add(hellotesting);
                db.SaveChanges();
            }*/
        }
    }
}

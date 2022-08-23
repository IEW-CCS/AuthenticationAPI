using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class QueueManager : IQueueManager
    {
        private ConcurrentQueue<MessageTrx> _MsgQueueList;
     
        public QueueManager()
        {
            this._MsgQueueList = new ConcurrentQueue<MessageTrx>();
        }

        public void PutMessage(MessageTrx msg)
        {
            this._MsgQueueList.Enqueue(msg);
        }

        public MessageTrx GetMessage()
        {
            MessageTrx result = null;
            if (this._MsgQueueList.Count > 0)
            {
                this._MsgQueueList.TryDequeue(out result);
            }
            return result;
        }

        public int GetCount()
        {
            return this._MsgQueueList.Count;
        }

        public void ClearQueue()
        {
            lock (this._MsgQueueList)
            {
                this._MsgQueueList.Clear();
            }
        }
    }
}

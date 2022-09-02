using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class QueueManager : IQueueManager
    {
        private ConcurrentQueue<MessageTrx> _msgQueueList;
     
        public QueueManager()
        {
            this._msgQueueList = new ConcurrentQueue<MessageTrx>();
        }

        public void PutMessage(MessageTrx msg)
        {
            this._msgQueueList.Enqueue(msg);
        }

        public MessageTrx GetMessage()
        {
            MessageTrx result = null;
            if (this._msgQueueList.Count > 0)
            {
                this._msgQueueList.TryDequeue(out result);
            }
            return result;
        }

        public int GetCount()
        {
            return this._msgQueueList.Count;
        }

        public void ClearQueue()
        {
            lock (this._msgQueueList)
            {
                this._msgQueueList.Clear();
            }
        }
    }
}

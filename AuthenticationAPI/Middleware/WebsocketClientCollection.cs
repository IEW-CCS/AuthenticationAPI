using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Middleware
{
    public class WebsocketClientCollection
    {
        private static List<WebsocketClient> _clients = new List<WebsocketClient>();
        public static void Add(WebsocketClient client)
        {
            _clients.Add(client);
        }

        public static void Remove(WebsocketClient client)
        {
            _clients.Remove(client);
        }

        public static WebsocketClient Get(string clientId)
        {
            var client = _clients.FirstOrDefault(c => c.Id == clientId);
            return client;
        }

        public static WebsocketClient Get(string Fnuction, string clientId)
        {
            var client = _clients.FirstOrDefault(c => c.Id == clientId && c.Function == Fnuction);
            return client;
        }
        public static List<WebsocketClient> GetAll()
        {
            return _clients.ToList();
        }
    }
}

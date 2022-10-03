using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.WebSockets;
using System.Threading.Tasks;
using System.Text;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;
using AuthenticationAPI.Kernel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using AuthenticationAPI.DtoS;
using Microsoft.Extensions.Configuration;

namespace AuthenticationAPI.Middleware
{
    public class WebsocketHandlerMiddleware : IDisposable
    {
        private readonly RequestDelegate next;
        private readonly ILogger Logger;
        private readonly IQueueManager QueueManager;
        private readonly IMessageManager MessageManager;
        private readonly IConfiguration Configuration;
        private int _TaskSleepPeriodMs = 100;
        private Thread _route = null;
        private bool _keepRunning = true;
        public WebsocketHandlerMiddleware(RequestDelegate _next,ILoggerFactory loggerFactory, IMessageManager messagemanage, IQueueManager queuemanager, IConfiguration configuration )
        {
            this.next = _next;
            QueueManager = queuemanager;
            MessageManager = messagemanage;
            Configuration = configuration;
            Logger = loggerFactory.CreateLogger<WebsocketHandlerMiddleware>();
            _route = new Thread(new ThreadStart(scanSendQueueTask));
            _route.IsBackground = true;
            _route.Start();
            
        }
        private void scanSendQueueTask()
        {
            int count = 0;
            while (_keepRunning)
            {
                try
                {
                    count++;
                    DoSendProc();
                    int queue_deap = QueueManager.GetCount();
                    if (queue_deap <= 0)
                    {
                        Thread.Sleep(this._TaskSleepPeriodMs);
                        continue;
                    }
                    if (count > int.MaxValue)
                    {
                        count = 0;
                        Thread.Sleep(this._TaskSleepPeriodMs);
                    }
                }
                catch { }
            }
        }
        private void DoSendProc()
        {
            // 送出 WebSocket to Client
            AuthenticationAPI.Kernel.MessageTrx msg = QueueManager.GetMessage();
            if (msg != null)
            {
                string ClientID = msg.ClientID;
                string Function = msg.Function;
                string MessageBody = msg.Data;

                if(ClientID == string.Empty)
                {
                    return;
                }
                try
                {
                    var client = WebsocketClientCollection.Get(ClientID);

                    if (client != null)
                    {
                        client.SendMessageAsync(MessageBody);
                    }
                    else
                    {
                        Logger.LogError(string.Format("Client ID Not Exist ."));
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError(string.Format("Exception Error msg = {0}.", ex.Message));
                }
            }
        }
        public async Task Invoke(HttpContext context)
        {
            // 透過Web 收HTTP  / WS transaction 進來.
            if (context.WebSockets.IsWebSocketRequest)
            {
                // WEB SOCKET type : 
                // 進入點一
                System.Net.WebSockets.WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync();
                //string clientId = Guid.NewGuid().ToString();
                String path = context.Request.Path.Value.Substring(1);
                var wsClient = new WebsocketClient
                {
                    Id = string.Empty,
                    Function = path,
                    WebSocket = webSocket
                };

                string RequestStartPath = string.Concat("/", Configuration["Server:WSServiceName"]);
                //----- 檢查 Exist Token Info --------
                if (context.Request.Path.Value.StartsWith(RequestStartPath))
                {
                   
                    var bearerToken = context.Request.Query["access_token"].ToString().Trim();
                    if (!String.IsNullOrEmpty(bearerToken))
                    {
                        context.Request.Headers.Add("Authorization", "Bearer " + bearerToken);
                    }
                }

                if (await this.AuthorizeUserFromHttpContextAsync(context))
                {
                    try
                    {
                        string ClientID = await this.GetUserNameFromHttpContextAsync(context);
                        wsClient.Id = ClientID;

                        if (ClientID != String.Empty)
                        {
                            WSTrx Ws = this.WSTrxConnectReplyOK();
                            string WsJsonStr = System.Text.Json.JsonSerializer.Serialize(Ws);
                            await wsClient.SendMessageAsync(WsJsonStr);  
                            await Handle(wsClient);
                        }
                        else
                        {
                            int RTCode = (int)WSAuthErrorCode.TokenInfoError;
                            WSTrx Ws = this.WSTrxConnectReplyNG(RTCode);
                            string WsJsonStr = System.Text.Json.JsonSerializer.Serialize(Ws);
                            await wsClient.SendMessageAsync(WsJsonStr);  
                            wsClient.WebSocket.Abort();
                            await context.Response.WriteAsync("closed");
                            return;
                        }    
                    }
                    catch (Exception ex)
                    {
                        int RTCode = (int)WSAuthErrorCode.ConnectError;
                        WSTrx Ws = this.WSTrxConnectReplyNG(RTCode);
                        Ws.ReturnMsg += ", ErrMsg = " + ex.Message;
                        string WsJsonStr = System.Text.Json.JsonSerializer.Serialize(Ws);
                        await wsClient.SendMessageAsync(WsJsonStr);
                        wsClient.WebSocket.Abort();
                        await context.Response.WriteAsync("closed");
                        return;
                    }
                }
                else
                {
                    int RTCode = (int)WSAuthErrorCode.AuthorizedError;
                    WSTrx Ws = this.WSTrxConnectReplyNG(RTCode);
                    string WsJsonStr = System.Text.Json.JsonSerializer.Serialize(Ws);
                    await wsClient.SendMessageAsync(WsJsonStr);
                    wsClient.WebSocket.Abort();
                    return;
                }
            }
            else
            {
                // context.Response.StatusCode = 404 ;
                await next(context);  // 這一行可以判斷是否為WebSocket 連線 如果不是可以轉給Http對應 ->  對應至Controllers 內, 依層次來search .(原件 valueController)     
            }
        }

        private async Task Handle(WebsocketClient webSocket)
        {
            WebsocketClientCollection.Add(webSocket);
            Logger.LogInformation($"Websocket client added Client ID = " + webSocket.Id);
            WebSocketReceiveResult result = null;
            do
            {
                try
                {
                    var buffer = new byte[1024 * 1];
                    result = await webSocket.WebSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                    if (result.MessageType == WebSocketMessageType.Text && !result.CloseStatus.HasValue)
                    {
                        var msgString = Encoding.UTF8.GetString(buffer);
                        Logger.LogInformation($"Websocket client ReceiveAsync message {msgString}.");
                        //------以後這邊考慮組判斷上來的資訊直接對應到反序列化結果------
                        try
                        {
                            MessageTrx Message = new MessageTrx();
                            Message.ClientID = webSocket.Id;
                            Message.Data = msgString;
                            Message.Function = webSocket.Function;
                            Message.TimeStamp = DateTime.Now;

                            // 進入點一. Message Dispatch (Invoke to Service function)
                            MessageManager.MessageDispatch(Message.Function, new object[] { Message });

                        }
                        catch (Exception ex)
                        {
                            Logger.LogError(string.Format("MessageDispatch Error , Msg = {0}.", ex.Message));
                        }

                    }
                }
                catch(Exception ex)
                {
                    string errresult = ex.Message.ToString() ;
                }

                if(result == null)
                {
                    break;
                }
            }
            while (!result.CloseStatus.HasValue);
            WebsocketClientCollection.Remove(webSocket);
            Logger.LogInformation($"Websocket client closed.");
        }
        public void Dispose()
        {
            _keepRunning = false;
            Thread.Sleep(1000);
        }
        protected string ObtainAppTokenFromHeader(string authHeader)
        {
            if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.Contains(" "))
            {
                return null;
            }
            else
            {
                string[] authSchemeAndJwt = authHeader.Split(' ');
                string authScheme = authSchemeAndJwt[0];
                if (authScheme != "Bearer")
                    return null;
                string jwt = authSchemeAndJwt[1];
                return jwt;
            }
        }
        protected async Task<bool> AuthorizeUserFromHttpContextAsync(HttpContext context)
        {
            var jwtBearerOptions = context.RequestServices.GetRequiredService<JwtBearerOptions>() as JwtBearerOptions;
            string jwt = this.ObtainAppTokenFromHeader(context.Request.Headers["Authorization"]);
            if (jwt == null)
            {
                return false;
            }
            var jwtBacker = new JwtBearerBacker(jwtBearerOptions);
            return jwtBacker.IsJwtValid(jwt);
        }
        protected async Task<string> GetUserNameFromHttpContextAsync(HttpContext context)
        {
            var jwtBearerOptions = context.RequestServices.GetRequiredService<JwtBearerOptions>() as JwtBearerOptions;
            string jwtHeader = this.ObtainAppTokenFromHeader(context.Request.Headers["Authorization"]);
            if (jwtHeader == null)
            {
                return string.Empty;
            }
            var jwtBacker = new JwtBearerBacker(jwtBearerOptions);
            return jwtBacker.JetUserName(jwtHeader);
        }
        private WSTrx WSTrxConnectReplyNG(int retuenCode)
        {
            WSTrx WSReply = new WSTrx();
            WSReply.ProcStep = ProcessStep.ARWSCPLY.ToString();
            WSReply.ReturnCode = retuenCode;
            WSReply.ReturnMsg = WSAuthError.ErrorMsg(retuenCode);
            WSReply.DataContent = string.Empty;
            return WSReply;
        }
        private WSTrx WSTrxConnectReplyOK()
        {
            WSTrx WSReply = new WSTrx();
            WSReply.ProcStep = ProcessStep.ARWSCPLY.ToString();
            WSReply.ReturnCode = 0;
            WSReply.ReturnMsg = "Login Success";
            WSReply.DataContent = string.Empty;
            return WSReply;
        }
    }
}

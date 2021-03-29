public async Task<Response> GetAccountValidationGiact(Request req)
        {

        
            //logging to splunk
            _logger.LogInformation($"Function GetAccountValidationGiact.");
            _logger.LogInformation($"Calling function to get Token from EUA");

            var mp_bearertoken = await GetToken();
            bool validateMoneyProc = await ValidateMoneyProcessing(req.RoutingNumber.Trim(), mp_bearertoken); // makes sure routing number is valid in right format
            ResponseGiactProxy responseGiact = new ResponseGiactProxy(); 
            Response resp = new Response();

            if (validateMoneyProc)
            {
                //call giact
                var giact_bearer_token = await GetToken();
                var client = new RestClient(giact_proxy.ToString());
                var request = new RestRequest();
                request.Method = Method.POST;

                request.AddParameter("Authorization", string.Format("Bearer {0}", giact_bearer_token.ToString()), ParameterType.HttpHeader);
                request.AddParameter("Accept-Encoding", "gzip, deflate, br", ParameterType.HttpHeader);
                request.AddHeader("Accept", "application/json");
                request.AddParameter("Connection", "keep-alive", ParameterType.HttpHeader);
                request.AddParameter("client_id", client_id.ToString(), ParameterType.HttpHeader);
                request.AddParameter("X-Message-ID", "1234", ParameterType.HttpHeader);

                RequestGiact reqq = new RequestGiact { AccountNumber = req.AccountNumber.Trim(), RoutingNumber = req.RoutingNumber.Trim(), AccountType = "" };
                request.AddParameter("application/json; charset=utf-8", JsonConvert.SerializeObject(reqq), ParameterType.RequestBody);

                IRestResponse response = await client.ExecuteAsync(request);

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    responseGiact = JsonConvert.DeserializeObject<ResponseGiactProxy>(response.Content.ToString());
                    resp = GetResponseCodes(responseGiact.Verification.code.Trim().ToString());
                    resp.Explanation = responseGiact.Verification.Description;
                    resp.recommend = responseGiact.Verification.recommendation;
                    resp.response = responseGiact.Details.AccountResponseCode;
                }
                else if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new ArgumentException();
                }
                else if ( response.StatusCode == HttpStatusCode.BadRequest )
                {
                    dynamic resGiactErrorResponse = JsonConvert.DeserializeObject<MoneyProcErrorResponse>(response.Content.ToString());
                    if (resGiactErrorResponse != null)
                    {
                        throw new ArgumentException("Giact Validation error => " + resGiactErrorResponse.developermessage.ToString());
                    }
                    else
                    {
                        throw new ArgumentException("Giact server error!");
                    }
                }
            }
            else
            {
                resp = GetResponseCodes(_money_proc_failed);
            }
             
            return resp;   
        }

        public Response GetResponseCodes(string AccountResponseCode)
        {
            if (AccountResponseCode is null) throw new ArgumentException("Wrong Account Response Code");
            if (AccountResponseCode == string.Empty) throw new ArgumentException("Wrong Account Response Code or Code is empty");
            VPIResponseCodes vpi_response = new VPIResponseCodes();
            Response finalResponse = new Response();

            string connStr = _dbSettings.Value.RenvpiConnectionString;
            try
            {
                using (OracleConnection objConn = new OracleConnection(connStr))
                {
                    #region Configure Oracle Command
                    objConn.Open();
                    OracleCommand cmd = new OracleCommand();
                    cmd.Connection = objConn;
                    cmd.CommandText = "pkg.get_nacha_response";
                    cmd.CommandType = CommandType.StoredProcedure;

                    cmd.Parameters.Add(new OracleParameter("igverify", OracleDbType.Varchar2)).Value = AccountResponseCode;

                    var out_VPI_Response = cmd.Parameters.Add(new OracleParameter("iorecordset", OracleDbType.RefCursor, ParameterDirection.Output));
                    out_VPI_Response.Size = 255;
                    
                    var out_SuccessFailure = cmd.Parameters.Add(new OracleParameter("oerror_code", OracleDbType.Varchar2, ParameterDirection.Output));
                    out_SuccessFailure.Size = 255;

                    var out_ErrorMessage = cmd.Parameters.Add(new OracleParameter("oerror_message", OracleDbType.Varchar2, ParameterDirection.Output));
                    out_ErrorMessage.Size = 255;

                    #endregion
                    cmd.ExecuteNonQuery();
                    var rdVPI_Response = ((OracleRefCursor)cmd.Parameters["iorecordset"].Value).GetDataReader();
                    var errorCode = Convert.ToInt32(((IDbDataParameter)(cmd.Parameters["oerror_code"])).Value.ToString());
                    var errorMessage = ((IDbDataParameter)(cmd.Parameters["oerror_message"])).Value.ToString();

                    if (errorCode != 0)
                    {
                        return  null;
                    }
                    else
                    {
                        while (rdVPI_Response.Read())
                        {
                            vpi_response.AccountReponseCode = rdVPI_Response.GetOracleValue(0).ToString();
                            vpi_response.ResponseExplanation = rdVPI_Response.GetOracleValue(2).ToString();
                            vpi_response.AdditionalComments = rdVPI_Response.GetOracleValue(3).ToString();
                            vpi_response.ResponseMessage = rdVPI_Response.GetOracleValue(4).ToString();
                            vpi_response.Action = rdVPI_Response.GetOracleValue(5).ToString();

                            finalResponse = _mapper.Map<Response>(vpi_response); //use automapper
                        }
                        rdVPI_Response.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Database Error: " + ex.Message.ToString());
            }
            return finalResponse;
        }

        public async Task<string> GetToken()
        {

        
            var certificate_credentials = _configuration.GetSection("certificate_credentials").Value;
            var certificate_password = _configuration.GetSection("certificate_password").Value;
            var base64Token = $"Basic {Base64Encode($"{client_id}:{secret}")}";

            var client = new RestClient(eua_proxy.Trim().ToString());
            var projectFolder = System.IO.Directory.GetCurrentDirectory();
            var certs_folder = Path.Combine(projectFolder, "Certificates");
            string certFile = Path.Combine(certs_folder, certificate_credentials.ToString());
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.DefaultConnectionLimit = 9999;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            X509Certificate2 certificate = new X509Certificate2(certFile, certificate_password.ToString(), X509KeyStorageFlags.MachineKeySet);
            client.ClientCertificates = new X509CertificateCollection() { certificate };
            client.Proxy = new WebProxy();
            var restrequest = new RestRequest(Method.POST);
            string encodedBody = string.Format("grant_type=client_credentials&scope=openid&realm=system&auth_method=mutual-tls&message_id=8f18e2e2-8cd5-4b53-a911-e146cf87f7dd");
            restrequest.AddParameter("application/x-www-form-urlencoded", encodedBody, ParameterType.RequestBody);
            restrequest.AddParameter("Content-Type", "application/x-www-form-urlencoded", ParameterType.HttpHeader);
        
            restrequest.AddParameter("Authorization", base64Token.ToString(), ParameterType.HttpHeader);
            restrequest.AddParameter("Connection", "keep-alive", ParameterType.HttpHeader);
            restrequest.AddParameter("Accept-Encoding", "gzip, deflate, br", ParameterType.HttpHeader);
            restrequest.AddParameter("Accept", "*/*", ParameterType.HttpHeader);
            IRestResponse response = await client.ExecuteAsync(restrequest);
            if ( response.StatusCode == HttpStatusCode.BadRequest)
            {
                EUAStdMessage errorMessage = JsonConvert.DeserializeObject<EUAStdMessage>(response.Content.ToString());
                if (errorMessage != null)
                    throw new ArgumentException("EUA endpoint error " + errorMessage.developermessage.ToString());
                else
                    throw new ArgumentException("EUA server error");
                       
            }
            Token tokenbearer = JsonConvert.DeserializeObject<Token>(response.Content.ToString());
            string bearerToken = tokenbearer.access_token.ToString().Trim();
            return bearerToken;
        }

        public async Task<bool> ValidateMoneyProcessing(string routingNumber , string bearerToken)
        {
         
         
            var client = new RestClient(money_proc_proxy.ToString());
            var restrequest = new RestRequest(Method.GET);

            restrequest.AddParameter("routing", routingNumber, ParameterType.UrlSegment);
            restrequest.AddParameter("Authorization", string.Format("Bearer {0}", bearerToken), ParameterType.HttpHeader);
            restrequest.AddParameter("Accept-Encoding", "gzip, deflate, br", ParameterType.HttpHeader);
            restrequest.AddParameter("Accept", "*/*", ParameterType.HttpHeader);
            restrequest.AddParameter("Connection", "keep-alive", ParameterType.HttpHeader;
            restrequest.AddParameter("client_id", client_id.ToString(), ParameterType.HttpHeader);
            restrequest.AddParameter("X-MessageID", "1234", ParameterType.HttpHeader);

            IRestResponse response = await client.ExecuteAsync(restrequest);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                return true;
            }
        
            else
            {
                return false;
            }
        }
        private static string Base64Encode(string plainText)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }
    }

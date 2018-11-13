using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace lambda_authorizer_dotnet_core
{
    public class Function
    {
        private readonly string Key;
        private readonly TokenValidationParameters ValidationParameters;

        public Function()
        {
            Key = Environment.GetEnvironmentVariable("Key");
            ValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key)),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };
        }

        public APIGatewayCustomAuthorizerResponse FunctionHandler(APIGatewayCustomAuthorizerRequest authEvent, ILambdaContext context)
        {
            var token = authEvent.AuthorizationToken;
            var authorized = ValidateToken(token);
            var resource = authEvent.MethodArn;

            return authorized ? SetResponse("Allow", resource) : SetResponse("Deny", resource);
        }

        public bool ValidateToken(string token)
        {
            try 
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(token, ValidationParameters, out var validatedToken);
                return true;
            }
            catch 
            {
                return false;
            }
        }

        private APIGatewayCustomAuthorizerResponse SetResponse(string effect, string resource)
        {
            var response = new APIGatewayCustomAuthorizerResponse();
            
            response.PrincipalID = "user";

            var policyDocument = new APIGatewayCustomAuthorizerPolicy();
            var statement = new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement();
            statement.Action = new HashSet<string> { "execute-api:Invoke" };
            statement.Resource = new HashSet<string> { resource };
            statement.Effect = effect;
            policyDocument.Statement.Add(statement);
            
            response.PolicyDocument = policyDocument;
            
            return response;
        }
    }
}
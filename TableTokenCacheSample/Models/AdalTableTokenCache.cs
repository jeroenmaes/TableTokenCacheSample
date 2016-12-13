using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.IdentityModel.Protocols;
using System.Configuration;

namespace TableTokenCacheSample.Models
{
    public class TokenEntity : TableEntity
    {
        public string UserTokenCacheId { get; set; }
        public byte[] CacheBits { get; set; }
        public DateTime LastWrite { get; set; }

        public TokenEntity(string webUniqueUserId, byte[] token, DateTime lastWriteTime)
        {
            UserTokenCacheId = webUniqueUserId;
            CacheBits = token;
            LastWrite = lastWriteTime;

            RowKey = webUniqueUserId;
            PartitionKey = "usertoken";
        }

        public TokenEntity() { }
    }

    public class TokenEntityRepository
    {
        private readonly CloudTable _cloudTable;
        public TokenEntityRepository(string connectionString)
        {
            var cloudAccount = CloudStorageAccount.Parse(connectionString);
            _cloudTable = cloudAccount.CreateCloudTableClient().GetTableReference("usertokencaches");
            _cloudTable.CreateIfNotExists();
        }

        public IEnumerable<TokenEntity> GetAllTokensForUser(string userId)
        {
            TableQuery<TokenEntity> query = new TableQuery<TokenEntity>()
                .Where(TableQuery.CombineFilters(
                    TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, "usertoken"),
                    TableOperators.And,
                    TableQuery.GenerateFilterCondition("RowKey", QueryComparisons.Equal, userId)));

            return _cloudTable.ExecuteQuery(query).ToList();
        }

        public void Delete(TokenEntity tokenEntity)
        {
            var tableOp = TableOperation.Delete(tokenEntity);
            _cloudTable.Execute(tableOp);
        }

        public void InsertOrReplace(TokenEntity tokenEntity)
        {
            var tableOp = TableOperation.InsertOrReplace(tokenEntity);
            _cloudTable.Execute(tableOp);
        }
    }

    public class TableTokenCache : TokenCache
    {
        private readonly string userId;
        private readonly TokenEntityRepository _repository;
        private TokenEntity Cache;
        private string _connectionString = ConfigurationManager.AppSettings["sta:endpoint"];

        public TableTokenCache(string signedInUserIdId)
        {
            this.userId = signedInUserIdId;
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;

            this._repository = new TokenEntityRepository(_connectionString);

        }
        
        public override void Clear()
        {
            base.Clear();
            foreach (var item in _repository.GetAllTokensForUser(userId))
            {
                _repository.Delete(item);
            }
        }

        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            var latestToken = _repository.GetAllTokensForUser(userId)
                    .OrderByDescending(a => a.LastWrite)
                    .FirstOrDefault();

            if (Cache == null || (latestToken != null && Cache.LastWrite < latestToken.LastWrite))
                Cache = latestToken;

            this.Deserialize((Cache == null) ? null : MachineKey.Unprotect(Cache.CacheBits, "ADALTableCache"));
        }

        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if (this.HasStateChanged)
            {
                var cacheBits = MachineKey.Protect(this.Serialize(), "ADALTableCache");

                Cache = new TokenEntity(userId, cacheBits, DateTime.UtcNow);
                _repository.InsertOrReplace(Cache);

                this.HasStateChanged = false;
            }
        }
    }
}
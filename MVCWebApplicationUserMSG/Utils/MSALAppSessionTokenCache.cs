using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Identity.Client;
using System.Threading;

namespace MVCWebApplicationUserMSG.Utils
{
    /// <summary>
    /// An implementation of token cache for Confidential clients backed by Http session.
    /// </summary>
    /// <seealso cref="https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/token-cache-serialization"/>
    public class MSALAppSessionTokenCache
    {
        /// <summary>
        /// The application cache key
        /// </summary>
        internal readonly string AppCacheId;

        /// <summary>
        /// The HTTP context being used by this app
        /// </summary>
        internal HttpContextBase HttpContextInstance = null;

        private static ReaderWriterLockSlim SessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        /// <summary>
        /// Initializes a new instance of the <see cref="MSALAppSessionTokenCache"/> class.
        /// </summary>
        /// <param name="tokenCache">The client's instance of the token cache.</param>
        /// <param name="clientId">The application's id (Client ID).</param>
        public MSALAppSessionTokenCache(ITokenCache tokenCache, string clientId, HttpContextBase httpcontext)
        {
            this.HttpContextInstance = httpcontext;
            this.AppCacheId = clientId + "_AppTokenCache";

            tokenCache.SetBeforeAccess(AppTokenCacheBeforeAccessNotification);
            tokenCache.SetAfterAccess(AppTokenCacheAfterAccessNotification);
            tokenCache.SetBeforeWrite(AppTokenCacheBeforeWriteNotification);
        }

        /// <summary>
        /// if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void AppTokenCacheBeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // Since we are using a SessionCache ,whose methods are threads safe, we need not to do anything in this handler.
        }

        /// <summary>
        /// Loads the application's tokens from session cache.
        /// </summary>
        private void LoadAppTokenCacheFromSession(TokenCacheNotificationArgs args)
        {
            SessionLock.EnterReadLock();

            args.TokenCache.DeserializeMsalV3((byte[])HttpContextInstance.Session[this.AppCacheId]);

            SessionLock.ExitReadLock();
        }

        /// <summary>
        /// Persists the application token's to session cache.
        /// </summary>
        private void PersistAppTokenCache(TokenCacheNotificationArgs args)
        {
            SessionLock.EnterWriteLock();

            // Reflect changes in the persistence store
            HttpContextInstance.Session[this.AppCacheId] = args.TokenCache.SerializeMsalV3();

            SessionLock.ExitWriteLock();
        }

        /// <summary>
        /// Clears the TokenCache's copy of this user's cache.
        /// </summary>
        public void Clear()
        {
            SessionLock.EnterWriteLock();

            HttpContextInstance.Session[this.AppCacheId] = null;

            SessionLock.ExitWriteLock();
        }

        /// <summary>
        /// Triggered right before MSAL needs to access the cache. Reload the cache from the persistence store in case it changed since the last access.
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void AppTokenCacheBeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            this.LoadAppTokenCacheFromSession(args);
        }

        /// <summary>
        /// Triggered right after MSAL accessed the cache.
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void AppTokenCacheAfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (args.HasStateChanged)
            {
                this.PersistAppTokenCache(args);
            }
        }
    }
}
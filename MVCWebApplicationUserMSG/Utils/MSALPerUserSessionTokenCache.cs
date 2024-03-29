﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Identity.Client;
using System.Security.Claims;
using System.Threading;
using MVCWebApplicationUserMSG.Utils;

namespace MVCWebApplicationUserMSG.Utils
{
    /// <summary>
    /// This is a MSAL's TokenCache implementation for one user. It uses Sql server as a backend store and uses the Entity Framework to read and write to that database.
    /// </summary>
    /// <seealso cref="https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/token-cache-serialization"/>
    public class MSALPerUserSessionTokenCache
    {
        private static ReaderWriterLockSlim SessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        /// <summary>
        /// Once the user signes in, this will not be null and can be ontained via a call to ClaimsPrincipal.Current
        /// </summary>
        internal ClaimsPrincipal SignedInUser;

        /// <summary>
        /// The HTTP context being used by this app
        /// </summary>
        private HttpContextBase HttpContext = null;

        /// <summary>Initializes a new instance of the <see cref="MSALPerUserSessionTokenCache"/> class.</summary>
        /// <param name="tokenCache">The token cache.</param>
        /// <param name="httpcontext">The current HttpContext.</param>
        public MSALPerUserSessionTokenCache(ITokenCache tokenCache, HttpContextBase httpcontext)
        {
            this.Initialize(tokenCache, httpcontext, ClaimsPrincipal.Current);
        }

        public MSALPerUserSessionTokenCache(ITokenCache tokenCache, HttpContextBase httpcontext, ClaimsPrincipal user)
        {
            this.Initialize(tokenCache, httpcontext, user);
        }

        /// <summary>Initializes the cache instance</summary>
        /// <param name="tokenCache">The ITokenCache passed through the constructor</param>
        /// <param name="httpcontext">The current HttpContext</param>
        /// <param name="user">The signed in user's ClaimPrincipal, could be null.
        /// If the calling app has it available, then it should pass it themselves.</param>
        private void Initialize(ITokenCache tokenCache, HttpContextBase httpcontext, ClaimsPrincipal user)
        {
            this.HttpContext = httpcontext;

            tokenCache.SetBeforeAccess(UserTokenCacheBeforeAccessNotification);
            tokenCache.SetAfterAccess(UserTokenCacheAfterAccessNotification);
            tokenCache.SetBeforeWrite(UserTokenCacheBeforeWriteNotification);

            if (user == null)
            {
                // No users signed in yet, so we return
                return;
            }

            this.SignedInUser = user;
        }

        /// <summary>
        /// Loads the user token cache from http session.
        /// </summary>
        public void LoadUserTokenCacheFromSession(TokenCacheNotificationArgs args)
        {
            string cacheKey = this.GetSignedInUsersUniqueId();

            if (string.IsNullOrWhiteSpace(cacheKey))
                return;

            SessionLock.EnterReadLock();
            try
            {
                args.TokenCache.DeserializeMsalV3((byte[])this.HttpContext.Session[cacheKey]);
            }
            finally
            {
                SessionLock.ExitReadLock();
            }
        }

        /// <summary>
        /// Persists the user token blob to the Http session.
        /// </summary>
        public void PersistUserTokenCache(TokenCacheNotificationArgs args)
        {
            string cacheKey = this.GetSignedInUsersUniqueId();

            if (string.IsNullOrWhiteSpace(cacheKey))
                return;

            SessionLock.EnterWriteLock();

            try
            {
                // Reflect changes in the persistence store
                this.HttpContext.Session[cacheKey] = args.TokenCache.SerializeMsalV3();
            }
            finally
            {
                SessionLock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Clears the TokenCache's copy of this user's cache.
        /// </summary>
        public void Clear()
        {
            string cacheKey = this.GetSignedInUsersUniqueId();

            if (string.IsNullOrWhiteSpace(cacheKey))
                return;

            // httpContext.Session[this.GetSignedInUsersCacheKey()] = null;

            SessionLock.EnterWriteLock();

            try
            {
                // Reflect changes in the persistent store
                this.HttpContext.Session.Remove(cacheKey);
            }
            finally
            {
                SessionLock.ExitWriteLock();
            }
        }

        /// <summary>
        /// if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>

        private void UserTokenCacheBeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // Since we obtain and release lock right before and after we read the Http session, we need not do anything here.
        }

        /// <summary>
        /// Triggered right after MSAL accessed the cache.
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void UserTokenCacheAfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (args.HasStateChanged)
            {
                this.PersistUserTokenCache(args);
            }
        }

        /// <summary>
        /// Triggered right before MSAL needs to access the cache. Reload the cache from the persistence store in case it changed since the last access.
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void UserTokenCacheBeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            this.LoadUserTokenCacheFromSession(args);
        }

        /// <summary>
        /// Explores the Claims of a signed-in user (if available) to populate the unique Id of this cache's instance.
        /// </summary>
        /// <returns>The signed in user's object.tenant Id , if available in the ClaimsPrincipal.Current instance</returns>
        internal string GetSignedInUsersUniqueId()
        {
            if (this.SignedInUser != null)
            {
                return this.SignedInUser.GetMsalAccountId();
            }
            return null;
        }
    }
}